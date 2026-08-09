import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from .. import mailer
from .. import policy_store
from ..audit import log_action
from ..auth import require_admin, require_client_manager, require_user
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import User
from ..policy_store import PolicyValidationError

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
    # Served from the same background-refreshed snapshot that powers
    # /api/dashboard (see cli_wrapper.get_clients_snapshot) -- near-instant
    # on a warm snapshot, falls back to a direct call otherwise.
    try:
        return cli.get_clients_snapshot()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/revoked")
def get_revoked_clients(_: User = Depends(require_user)):
    try:
        return cli.get_revoked_snapshot()
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
def add_client_mac(name: str, body: MacRequest, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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
def remove_client_mac(name: str, mac: str, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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
def add_client(body: AddClientRequest, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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
def revoke_client(name: str, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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
def get_client_ovpn(name: str, _: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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
def email_client_ovpn(name: str, body: EmailOvpnRequest, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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
def purge_revoked_clients(body: PurgeRevokedRequest, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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


class CleanStaleDbRequest(BaseModel):
    names: list[str]


@router.post("/revoked/clean-stale-db")
def clean_stale_db_entries(body: CleanStaleDbRequest, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
    """Bulk removal of revoked clients' leftover openvpn_db.txt entries --
    mirrors /revoked/purge's per-item bulk-result pattern. Distinct from
    purge: this only touches the MAC-binding db entry, not PKI/.ovpn files
    (a client can be stale_db_entry:true while files_present is already
    false, i.e. already purged -- that's exactly the case purge's UI button
    can't reach, since it's only shown when files_present is true)."""
    results = []
    for name in body.names:
        if not NAME_RE.match(name):
            results.append({"name": name, "ok": False, "message": "Invalid client name."})
            continue
        try:
            result = cli.clean_stale_db_entry(name)
        except ScriptError as e:
            log_action(db, user, "clean_stale_db_entry", target=name, detail=e.message, success=False)
            results.append({"name": name, "ok": False, "message": e.message})
            continue
        log_action(db, user, "clean_stale_db_entry", target=name, detail=result, success=True)
        results.append({"name": name, "ok": True, "message": f"'{name}'s stale MAC-db entry removed."})
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
def restore_revoked_client(name: str, body: RestoreClientRequest, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
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


# --- Per-client restrictions (country / OS / bandwidth quota) ---------------
# Enforced entirely by the client-connect/client-disconnect scripts on the
# OpenVPN host (host-scripts/ in this repo, not part of this Docker image)
# -- these endpoints only read/write client_policy.json via policy_store,
# they never invoke cli_wrapper/openvpn-install.sh for this feature.

class PolicyRequest(BaseModel):
    """Same partial-update-by-field-presence convention as Settings'
    UpdateSettingsRequest: a field omitted from the request body is left
    untouched; an explicit null clears it. The "Manage Restrictions"
    dialog always sends all three fields together (it always shows/edits
    the full current state at once), but the API itself stays field-level
    partial for consistency with the rest of this app.

    `country` is a per-client ISO 3166-1 alpha-2 code chosen independently
    from a full country dropdown (see templates/clients.html) -- there is
    no deployment-wide "the one restricted country" concept; every client
    can be restricted to a different country, or none at all."""
    country: str | None = None
    allowed_os: list[str] | None = None
    bandwidth_weekly_gb: float | None = None


@router.get("/policies")
def get_all_client_policies(_: User = Depends(require_client_manager)):
    """Bulk name -> policy dict for every client with a restriction set
    (clients with none simply don't appear in the result). Admin-only, same
    as the per-client GET below -- exists purely so the All Clients table
    can render restriction-summary badges per row without an N+1 fetch."""
    return {"policies": policy_store.get_all_policies()}


@router.get("/{name}/policy")
def get_client_policy(name: str, _: User = Depends(require_client_manager)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")
    return {
        "policy": policy_store.get_policy(name),
        "usage": policy_store.get_usage(name),
    }


@router.put("/{name}/policy")
def update_client_policy(name: str, body: PolicyRequest, user: User = Depends(require_client_manager), db: Session = Depends(get_db)):
    if not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Invalid client name.")

    fields_set = body.model_fields_set

    try:
        result = policy_store.set_policy(
            name,
            country=body.country if "country" in fields_set else ...,
            allowed_os=body.allowed_os if "allowed_os" in fields_set else ...,
            bandwidth_weekly_gb=body.bandwidth_weekly_gb if "bandwidth_weekly_gb" in fields_set else ...,
        )
    except PolicyValidationError as e:
        log_action(db, user, "update_client_policy", target=name, detail=str(e), success=False)
        raise HTTPException(status_code=400, detail=str(e))

    detail_bits = []
    if "country" in fields_set:
        detail_bits.append(f"country={body.country or 'ANY'}")
    if "allowed_os" in fields_set:
        detail_bits.append(f"allowed_os={','.join(body.allowed_os) if body.allowed_os else 'ANY'}")
    if "bandwidth_weekly_gb" in fields_set:
        detail_bits.append(f"bandwidth_weekly_gb={body.bandwidth_weekly_gb or 'ANY'}")
    log_action(db, user, "update_client_policy", target=name, detail="; ".join(detail_bits) or "no changes", success=True)
    return {"policy": result}
