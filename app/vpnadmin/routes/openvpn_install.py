"""Web-triggered OpenVPN install/uninstall -- the one host-namespace action
routed over SSH via services/system/host_executor.py instead of running
in-process, per the Phase 1 migration plan's §2a. Every other VPN/client
operation stays on cli_wrapper.py exactly as today; this route is
deliberately narrow.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from services.openvpn.exceptions import OpenVPNError
from services.system.host_executor import HostExecutorConfig, run_host_command

from ..audit import log_action
from ..config import settings
from ..db import get_db
from ..models import User
from ..permissions import require_permission

router = APIRouter(prefix="/api/openvpn", tags=["openvpn-install"])

_require_install = require_permission("openvpn_install", "execute")


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
def get_install_status(user: User = Depends(_require_install)):
    """Whether the host executor is configured, and (if so) whether OpenVPN
    is currently installed/running there -- backs the minimal Install/
    Uninstall admin page's initial state."""
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
    port: int = 1194,
    protocol: str = "udp",
    dns: int = 1,
    client_name: str = "client",
    public_ip: str | None = None,
    user: User = Depends(_require_install),
    db: Session = Depends(get_db),
):
    config = _host_executor_config()
    args = [f"--port={port}", f"--protocol={protocol}", f"--dns={dns}", f"--client-name={client_name}"]
    if public_ip:
        args.append(f"--public-ip={public_ip}")
    try:
        data = run_host_command(config, "install", *args)
    except OpenVPNError as e:
        log_action(db, user, "openvpn_install", detail=e.detail, success=False)
        raise HTTPException(status_code=502, detail=e.detail)
    log_action(db, user, "openvpn_install", target=str(data.get("client_name")), success=True)
    return data


@router.post("/uninstall")
def post_uninstall(user: User = Depends(_require_install), db: Session = Depends(get_db)):
    config = _host_executor_config()
    try:
        data = run_host_command(config, "uninstall")
    except OpenVPNError as e:
        log_action(db, user, "openvpn_uninstall", detail=e.detail, success=False)
        raise HTTPException(status_code=502, detail=e.detail)
    log_action(db, user, "openvpn_uninstall", success=True)
    return data
