"""Web-triggered OpenVPN install/uninstall -- the one host-namespace action
routed over SSH via services/system/host_executor.py instead of running
in-process, per the Phase 1 migration plan's §2a. Every other VPN/client
operation stays on cli_wrapper.py exactly as today; this route is
deliberately narrow.

Given the blast radius (stands up or tears down the entire OpenVPN server on
the host -- real systemd service, real firewall rules, real PKI wipe on
uninstall), this whole router is locked down two ways beyond the normal
`openvpn_install`/`execute` RBAC check:
  1. Bootstrap-admin only (User.is_bootstrap_admin) -- no role/permission
     grant can open this up to any other account, see _require_install below.
  2. A short-lived step-up re-auth ("elevated" session flag, see
     verify_access()/_require_elevated below) -- being logged in as the
     bootstrap admin isn't enough on its own; a fresh password confirmation
     is required every ELEVATED_TTL_MINUTES, same sliding-window shape as
     auth.py's own session-timeout check but deliberately much shorter.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from services.openvpn.exceptions import OpenVPNError
from services.openvpn.exceptions import ValidationError as MacFormatError
from services.openvpn.validator import normalize_mac
from services.system.host_executor import HostExecutorConfig, run_host_command

from .. import vpn_identity_sync
from ..audit import log_action
from ..auth import verify_password
from ..config import settings
from ..db import get_db
from ..models import User
from ..permissions import require_permission

router = APIRouter(prefix="/api/openvpn", tags=["openvpn-install"])

ELEVATED_TTL_MINUTES = 15
_SESSION_ELEVATED_KEY = "openvpn_install_verified_at"

_require_install_permission = require_permission("openvpn_install", "execute")


def _require_install(user: User = Depends(_require_install_permission)) -> User:
    """Layers the bootstrap-admin-only restriction on top of the ordinary
    RBAC check above -- see this module's docstring for why. Any other
    account, even one an admin explicitly granted openvpn_install/execute
    to, is refused here."""
    if not user.is_bootstrap_admin:
        raise HTTPException(status_code=403, detail="Only the bootstrap admin account can access OpenVPN install/uninstall.")
    return user


def is_elevated(request: Request) -> bool:
    """Whether this session has confirmed the bootstrap admin's password
    within the last ELEVATED_TTL_MINUTES -- used by both this router (to
    gate the actual install/uninstall calls) and routes/pages.py (to gate
    the page itself). Deliberately its own narrow flag, not reusing the
    general session-timeout's `last_activity` -- that one slides on every
    request and would never actually expire during normal use of the page."""
    verified_at_iso = request.session.get(_SESSION_ELEVATED_KEY)
    if not verified_at_iso:
        return False
    try:
        verified_at = datetime.fromisoformat(verified_at_iso)
    except ValueError:
        return False
    elapsed_minutes = (datetime.now(timezone.utc) - verified_at).total_seconds() / 60
    return elapsed_minutes <= ELEVATED_TTL_MINUTES


def _require_elevated(request: Request, user: User = Depends(_require_install)) -> User:
    if not is_elevated(request):
        raise HTTPException(
            status_code=403,
            detail="Re-enter your password on the OpenVPN Install page to continue.",
        )
    return user


class VerifyAccessRequest(BaseModel):
    password: str


@router.post("/verify-access")
def verify_access(body: VerifyAccessRequest, request: Request, user: User = Depends(_require_install)):
    """Step-up re-auth for this router -- see module docstring. Depends on
    _require_install (not _require_elevated -- this is the endpoint that
    *grants* elevation) so only the bootstrap admin can even attempt it."""
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password.")
    request.session[_SESSION_ELEVATED_KEY] = datetime.now(timezone.utc).isoformat()
    return {"elevated": True, "ttl_minutes": ELEVATED_TTL_MINUTES}


def _host_executor_config() -> HostExecutorConfig:
    if not settings.HOST_SSH_TARGET or not settings.HOST_SSH_KEY_PATH:
        raise HTTPException(
            status_code=400,
            detail="Host executor is not configured -- set HOST_SSH_TARGET and "
            "HOST_SSH_KEY_PATH (see .env.example) before install/uninstall can run.",
        )
    return HostExecutorConfig(
        ssh_key_path=settings.HOST_SSH_KEY_PATH,
        ssh_target=settings.HOST_SSH_TARGET,
        remote_script_path=settings.HOST_SSH_REMOTE_SCRIPT_PATH,
        use_sudo=settings.HOST_SSH_USE_SUDO,
        timeout_seconds=settings.HOST_SSH_TIMEOUT_SECONDS,
        ssh_port=settings.HOST_SSH_PORT,
    )


@router.get("/status")
def get_install_status(user: User = Depends(_require_elevated)):
    """Whether the host executor is configured, and (if so) whether OpenVPN
    is currently installed/running there -- backs the minimal Install/
    Uninstall admin page's initial state. Requires elevation like
    install/uninstall (not just _require_install) since even this read
    leaks host state to whoever calls it -- the page itself only fetches it
    once the "confirm your password" gate has been passed."""
    if not settings.HOST_SSH_TARGET or not settings.HOST_SSH_KEY_PATH:
        return {"configured": False}
    config = _host_executor_config()
    try:
        data = run_host_command(config, "status")
    except OpenVPNError as e:
        raise HTTPException(status_code=502, detail=e.detail)
    return {"configured": True, **data}


@router.post("/install")
def post_install(
    mac: str | None = None,
    port: int = 1194,
    protocol: str = "udp",
    dns: int = 1,
    client_name: str | None = None,
    public_ip: str | None = None,
    user: User = Depends(_require_elevated),
    db: Session = Depends(get_db),
):
    # First client is optional (task feedback: "OpenVPN installation can
    # proceed without creating an initial client") -- leave both client_name
    # and mac unset/blank to install with none at all; a client can always
    # be added afterward through the ordinary Add User / Clients-page flow,
    # identical to any other client. If a client_name IS given, mac is still
    # mandatory for it (same reasoning as before: the first client goes
    # through the same workflow routes/clients.py::add_client does, and
    # openvpn_admin.py's install action registers this MAC in DB_FILE right
    # after cert creation, closing installer.py's own documented gap -- the
    # bash-script-parity behavior of an unregistered first client that
    # can't pass the MAC check).
    client_name = (client_name or "").strip() or None
    mac_provided = bool(mac and mac.strip())
    if client_name and not mac_provided:
        raise HTTPException(status_code=400, detail="MAC address is required when creating a first client.")
    if mac_provided and not client_name:
        raise HTTPException(status_code=400, detail="Client name is required when a MAC address is given.")
    normalized_mac = None
    if client_name:
        try:
            normalized_mac = normalize_mac(mac)
        except MacFormatError as e:
            raise HTTPException(status_code=400, detail=e.detail)
    config = _host_executor_config()
    args = [f"--port={port}", f"--protocol={protocol}", f"--dns={dns}"]
    if client_name:
        args += [f"--client-name={client_name}", f"--client-mac={normalized_mac}"]
    if public_ip:
        args.append(f"--public-ip={public_ip}")
    try:
        data = run_host_command(config, "install", *args)
    except OpenVPNError as e:
        log_action(db, user, "openvpn_install", detail=e.detail, success=False)
        raise HTTPException(status_code=502, detail=e.detail)
    log_action(db, user, "openvpn_install", target=str(data.get("client_name") or "(no first client)"), success=True)
    # Identity lifecycle sync (see vpn_identity_sync.py), same call
    # routes/clients.py::add_client makes -- links this first client to a
    # portal account, creating a "User"-role one if none exists. Never
    # allowed to fail post_install itself; the server/cert already exist.
    # Skipped entirely when there's no first client to link.
    if data.get("client_name"):
        new_account = vpn_identity_sync.auto_link_new_client(db, str(data["client_name"]))
        if new_account is not None:
            data["portal_account_created"] = new_account  # {"username","temp_password"} -- shown once
    return data


@router.post("/uninstall")
def post_uninstall(user: User = Depends(_require_elevated), db: Session = Depends(get_db)):
    config = _host_executor_config()
    try:
        data = run_host_command(config, "uninstall")
    except OpenVPNError as e:
        log_action(db, user, "openvpn_uninstall", detail=e.detail, success=False)
        raise HTTPException(status_code=502, detail=e.detail)
    log_action(db, user, "openvpn_uninstall", success=True)
    return data
