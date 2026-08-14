"""systemd unit management -- Python port of the systemctl calls scattered
throughout openvpn-install.sh (enable/start the OpenVPN server unit at
:1404, disable on uninstall at :1575, the container-only LimitNPROC
drop-in at :1182-1186 and its removal at :1576, the iptables persistence
unit's enable/disable at :1370/:1569-1570).
"""

from __future__ import annotations

import os

from ..system.process_manager import CommandError, run, run_checked
from .exceptions import ServiceManagementError

LIMITNPROC_DROPIN_DIR = "/etc/systemd/system/openvpn-server@server.service.d"
LIMITNPROC_DROPIN_FILE = f"{LIMITNPROC_DROPIN_DIR}/disable-limitnproc.conf"


def is_container() -> bool:
    """Mirrors `systemd-detect-virt -cq` (:1182)."""
    result = run(["systemd-detect-virt", "-cq"], timeout=5)
    return result.ok


def write_limitnproc_dropin() -> None:
    """Mirrors :1182-1186 -- only called when is_container() is true."""
    os.makedirs(LIMITNPROC_DROPIN_DIR, exist_ok=True)
    with open(LIMITNPROC_DROPIN_FILE, "w", encoding="utf-8") as f:
        f.write("[Service]\nLimitNPROC=infinity\n")


def remove_limitnproc_dropin() -> None:
    """Mirrors :1576."""
    if os.path.exists(LIMITNPROC_DROPIN_FILE):
        os.remove(LIMITNPROC_DROPIN_FILE)


def daemon_reload() -> None:
    _run_systemctl("daemon-reload")


def enable_and_start(unit: str) -> None:
    """Mirrors `systemctl enable --now $unit` (:1404, :1370)."""
    _run_systemctl("enable", "--now", unit)


def restart(unit: str) -> None:
    """No bash-script equivalent -- OpenVPN only rereads server.conf
    (including a newly-added/changed client-connect/client-disconnect
    directive) on a full restart, not a reload. Used by
    host_scripts_manager.install_host_scripts() when wiring the per-client
    restriction hooks onto an ALREADY-installed, already-running server
    (a fresh install's own enable_and_start() above already starts it with
    the hooks in place, so no restart is needed there). Genuinely
    disruptive -- drops every currently-connected client -- so callers
    must opt in explicitly (see openvpn_admin.py's --restart flag), never
    triggered as a side effect."""
    _run_systemctl("restart", unit)


def disable_and_stop(unit: str) -> None:
    """Mirrors `systemctl disable --now $unit` (:1575, :1569)."""
    _run_systemctl("disable", "--now", unit)


def status(unit: str) -> tuple[bool, str]:
    """Returns (is_active, raw `systemctl is-active` output) -- used by the
    installer's post-install verification and the Phase 1 plan's §5a
    "active (running)" check."""
    result = run(["systemctl", "is-active", unit], timeout=10)
    return result.ok, result.stdout.strip()


def is_active(unit: str) -> bool:
    result = run(["systemctl", "is-active", "--quiet", unit], timeout=10)
    return result.ok


def _run_systemctl(*args: str) -> None:
    try:
        run_checked(["systemctl", *args], timeout=30, error_prefix=f"systemctl {' '.join(args)} failed")
    except CommandError as e:
        raise ServiceManagementError(e.message, args=args) from e
