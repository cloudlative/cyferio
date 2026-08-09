import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from .. import mailer
from ..audit import log_action
from ..auth import require_admin, require_user
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import User

router = APIRouter(prefix="/api/clients", tags=["clients"])


def _friendly_ovpn_error(name: str, e: ScriptError) -> str:
    """Translates the raw stderr from `--show-ovpn` into a message safe/
    useful to show a non-technical user. The script's own "no .ovpn file
    found at <path>" case (file genuinely missing/moved -- see
    openvpn-install.sh's do_show_ovpn) is common enough to deserve a
    specific, actionable message instead of leaking a server filesystem
    path into the UI."""
    if "no .ovpn file found" in e.message.lower():
        return (
            f"'{name}'s .ovpn profile file is missing on the server (it may "
            "have been moved, deleted, or never delivered to the location "
            "this app can read). Use Restore to issue a brand-new "
            "certificate and profile for this client."
        )
    return e.message


# Client names: the script itself sanitizes to this character set (replacing
# anything else with "_"), and that sanitization already happened silently
# before. Validating up front here gives a clear 400 error in the UI
# instead of the client being silently created under a mangled name.
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class AddClientRequest(BaseModel):
    name: str
    mac: str

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not NAME_RE.match(v):
            raise ValueError(
                "Name must be 1-64 characters: letters, numbers, underscore, or hyphen only."
            )
        return v

    @field_validator("mac")
    @classmethod
    def _nonempty_mac(cls, v: str) -> str:
        # Deliberately not re-validating the MAC format here -- the script
        # normalizes/validates it robustly already (any separator style,
        # any case) and is the single source of truth for that logic.
        if not v.strip():
            raise ValueError("MAC address is required.")
        return v.strip()


@router.get("")
def get_clients(_: User = Depends(require_user)):
    try:
        return cli.list_clients()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/revoked")
def get_revoked_clients(_: User = Depends(require_user)):
    try:
        return cli.list_revoked()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/{name}/macs")
def get_client_macs(name: str, _: User = Depends(require_user)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        return cli.list_macs(name)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


class MacRequest(BaseModel):
    mac: str

    @field_validator("mac")
    @classmethod
    def _nonempty_mac(cls, v: str) -> str:
        # Not re-validating the format here either -- see AddClientRequest
        # above, same reasoning: the script normalizes/validates.
        if not v.strip():
            raise ValueError("MAC address is required.")
        return v.strip()


@router.post("/{name}/macs", status_code=201)
def add_client_mac(name: str, body: MacRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        result = cli.add_mac(name, body.mac)
    except ScriptError as e:
        log_action(db, user, "add_mac", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "add_mac", target=name, detail=result, success=True)
    return {"message": result}


@router.delete("/{name}/macs/{mac}")
def remove_client_mac(name: str, mac: str, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        result = cli.remove_mac(name, mac)
    except ScriptError as e:
        log_action(db, user, "remove_mac", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "remove_mac", target=name, detail=result, success=True)
    return {"message": result}


@router.post("", status_code=201)
def add_client(body: AddClientRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        result = cli.add_client(body.name, body.mac)
    except ScriptError as e:
        log_action(db, user, "add_client", target=body.name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    # The audit log keeps the script's full raw stdout (useful for support/
    # debugging); the user-facing response is a short, clean sentence --
    # see revoke_client below for why the raw CLI text is deliberately not
    # surfaced directly to a non-technical toast.
    log_action(db, user, "add_client", target=body.name, detail=result, success=True)
    return {"message": f"Client '{body.name}' added successfully."}


@router.delete("/{name}")
def revoke_client(name: str, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        result = cli.revoke_client(name)
    except ScriptError as e:
        log_action(db, user, "revoke_client", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    # easy-rsa's own stdout here is several lines of raw, technical CLI
    # output (vars-file warnings, "This process is destructive!", etc.) --
    # fine to keep in full in the audit log, but confusing shown directly to
    # a non-technical user in a toast, so the API response is a short, clean
    # sentence instead.
    log_action(db, user, "revoke_client", target=name, detail=result, success=True)
    return {"message": f"Client '{name}' revoked successfully."}


@router.get("/{name}/ovpn")
def get_client_ovpn(name: str, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Returns an existing client's .ovpn config content on demand.
    Admin-only (unlike most GETs in this router) since this is genuinely
    sensitive key material -- deliberately never bulk-returned as part of
    the main client list, only fetched lazily per-client here."""
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        content = cli.show_ovpn(name)
    except ScriptError as e:
        raise HTTPException(status_code=400, detail=_friendly_ovpn_error(name, e))
    return {"name": name, "ovpn": content}


class EmailOvpnRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        v = v.strip()
        if not mailer.is_valid_email(v):
            raise ValueError("Please enter a valid email address.")
        return v


@router.post("/{name}/email-ovpn")
def email_client_ovpn(name: str, body: EmailOvpnRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    if not mailer.is_configured():
        raise HTTPException(status_code=400, detail="SMTP is not configured.")
    try:
        content = cli.show_ovpn(name)
    except ScriptError as e:
        friendly = _friendly_ovpn_error(name, e)
        log_action(db, user, "email_ovpn", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=friendly)
    try:
        mailer.send_ovpn_profile(to_address=body.email, client_name=name, ovpn_content=content)
    except Exception as e:
        log_action(db, user, "email_ovpn", target=name, detail=f"send to {body.email} failed: {e}", success=False)
        raise HTTPException(status_code=502, detail="Failed to send email. Check SMTP settings and try again.")
    log_action(db, user, "email_ovpn", target=name, detail=f"sent to {body.email}", success=True)
    return {"message": f"Profile for '{name}' emailed to {body.email}."}


class PurgeRevokedRequest(BaseModel):
    names: list[str]


@router.post("/revoked/purge")
def purge_revoked_clients(body: PurgeRevokedRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Bulk permanent-delete of one or more revoked clients' leftover PKI/
    .ovpn files -- mirrors the MAC bulk-remove UI pattern (select several,
    one confirm, per-item results)."""
    results = []
    for name in body.names:
        if not NAME_RE.match(name):
            results.append({"name": name, "ok": False, "message": "Invalid client name."})
            continue
        try:
            result = cli.purge_revoked(name)
        except ScriptError as e:
            log_action(db, user, "purge_revoked", target=name, detail=e.message, success=False)
            results.append({"name": name, "ok": False, "message": e.message})
            continue
        log_action(db, user, "purge_revoked", target=name, detail=result, success=True)
        results.append({"name": name, "ok": True, "message": f"'{name}' purged."})
    return {"results": results}


class RestoreClientRequest(BaseModel):
    mac: str

    @field_validator("mac")
    @classmethod
    def _nonempty_mac(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("MAC address is required.")
        return v.strip()


@router.post("/revoked/{name}/restore")
def restore_revoked_client(name: str, body: RestoreClientRequest, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Reissues a brand-new certificate under a revoked client's name -- see
    cli_wrapper.restore_client / openvpn-install.sh's do_restore_client for
    why this is NOT the same as un-revoking the old certificate."""
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    try:
        result = cli.restore_client(name, body.mac)
    except ScriptError as e:
        log_action(db, user, "restore_client", target=name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "restore_client", target=name, detail=result, success=True)
    return {"message": f"Client '{name}' restored (reissued with a new certificate)."}
