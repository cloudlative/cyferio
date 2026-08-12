"""Installs the client-connect/client-disconnect enforcement layer
(host-scripts/ in this repo: policy_lib.py, openvpn-mac-addr-check.py,
openvpn-client-disconnect.py) -- the MAC-binding check, and every
per-client Device & Access Policy / Location & Network Restriction on top
of it, were previously a MANUAL, README-documented deployment step,
entirely separate from the Python installer. This module folds that step
into install() itself (see installer.py) so a fresh install is
fully-enforcing from the first boot, and exposes install_host_scripts()
standalone (via the `install-host-scripts` CLI action) for an
ALREADY-installed server that predates this change, or was installed
before host-scripts/ existed as a concept.

Idempotent throughout, by design: every step here is safe to re-run
(copying over an identical file, chmod/chown-ing something already
correct, skipping a server.conf line that's already present) -- matching
this repo's established "self-healing on every call" pattern (see
policy_lib.py's _locked()/atomic_write_json() docstrings for the same
idea applied to the JSON policy files themselves).

Deliberately does NOT touch config_manager.render_server_conf() -- that
function's output is diffed against the real bash script's output by the
Phase 1 parity check (see test_install_parity.py), so its return value
must stay byte-for-byte what openvpn-install.sh itself would produce. The
extra directives this module adds live in a clearly-delimited block
APPENDED after render_server_conf()'s content by installer.py's own write
step, not inside render_server_conf() itself.
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

from ..system import package_manager
from ..system.process_manager import CommandError, run
from .exceptions import InstallError
from .paths import OpenVPNPaths

logger = logging.getLogger(__name__)

# host-scripts/ lives at the repo root, three directories up from this
# file (app/services/openvpn/host_scripts_manager.py -> app/services ->
# app -> repo root) -- resolved relative to this file rather than assumed
# from cwd, since this runs as a SSH-invoked script (host_executor.py) with
# no guarantee of what directory it was launched from.
_REPO_ROOT = Path(__file__).resolve().parents[3]
HOST_SCRIPTS_SOURCE_DIR = _REPO_ROOT / "host-scripts"

# Delimiters bracketing the block installer.py appends to server.conf --
# lets install_host_scripts() (and a re-run of install() itself) detect
# "already wired" and skip re-appending a duplicate block, and lets an
# admin see at a glance in server.conf which lines this tool owns vs. the
# original bash-parity content above them.
SERVER_CONF_MARKER_BEGIN = "# --- BEGIN openvpn-toolkit per-client restriction hooks (managed) ---"
SERVER_CONF_MARKER_END = "# --- END openvpn-toolkit per-client restriction hooks ---"


def render_server_conf_additions(paths: OpenVPNPaths) -> str:
    """The extra server.conf lines needed to activate MAC-binding + every
    per-client restriction check -- `script-security 2` (required for
    OpenVPN to run any client-connect/disconnect script at all) plus the
    two hook directives themselves. Returned as a standalone, marker-
    delimited block; callers decide whether/how to append it (see
    installer.py's install() and install_host_scripts() below)."""
    lines = [
        SERVER_CONF_MARKER_BEGIN,
        "script-security 2",
        f"client-connect {paths.mac_check_script}",
        f"client-disconnect {paths.disconnect_script}",
        SERVER_CONF_MARKER_END,
    ]
    return "\n".join(lines) + "\n"


def _chown_nobody(path: str, group_name: str) -> None:
    try:
        import grp
        import pwd
        os.chown(path, pwd.getpwnam("nobody").pw_uid, grp.getgrnam(group_name).gr_gid)
    except (OSError, KeyError):
        # Best-effort, same fail-soft stance as policy_lib.py's own
        # _ensure_dir_writable_by_nobody -- a dev/test environment without
        # a real `nobody` user, or insufficient privilege to chown,
        # shouldn't hard-fail the whole install.
        pass


def _copy_script(src: Path, dest: str, group_name: str, *, executable: bool) -> None:
    if not src.exists():
        raise InstallError(f"host-scripts source file not found: {src} -- is this running from a full repo checkout?")
    shutil.copyfile(src, dest)
    os.chmod(dest, 0o750 if executable else 0o640)
    _chown_nobody(dest, group_name)


def _ensure_file(path: str, initial_content: str, group_name: str, mode: int) -> None:
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(initial_content)
    # Ownership/mode fixed on every call, not just at creation -- same
    # self-healing rationale as the rest of this module (a file that
    # exists but somehow ended up root-owned, e.g. from a manual `touch`
    # before this tool existed, is repaired rather than left broken).
    os.chmod(path, mode)
    _chown_nobody(path, group_name)


# Same path policy_lib.py's own CONFIG_FILE constant and
# OpenVPNPaths.from_conf's default point at -- optional (sourced only if
# present), root-created by an admin following README.md's setup steps,
# so this module never creates it itself, only repairs its permissions
# when it happens to exist.
VPN_TOOLS_CONF_PATH = "/etc/openvpn/vpn-tools.conf"


def _fix_vpn_tools_conf_permissions(group_name: str) -> bool:
    """Found live (2026-08-12, see policy_lib.py's load_config()
    docstring): vpn-tools.conf commonly ends up root:root 0640 (a human
    created/edited it as root, default umask) -- unreadable by `nobody`,
    the user every client-connect/disconnect script invocation actually
    runs as. Before load_config() was hardened to fail open on this, that
    silently broke EVERY connection attempt, not just GeoIP-dependent
    ones. Re-chgrp/chmod on every call (self-healing, same as this
    module's other _ensure_file-backed files) rather than only at
    creation -- this module never creates the file itself (see
    VPN_TOOLS_CONF_PATH's own comment), only repairs it if an admin's
    already put one there. Returns True if anything was actually
    changed."""
    if not os.path.exists(VPN_TOOLS_CONF_PATH):
        return False
    st = os.stat(VPN_TOOLS_CONF_PATH)
    changed = False
    if (st.st_mode & 0o777) != 0o640:
        os.chmod(VPN_TOOLS_CONF_PATH, 0o640)
        changed = True
    try:
        import grp
        gid = grp.getgrnam(group_name).gr_gid
        if st.st_gid != gid:
            os.chown(VPN_TOOLS_CONF_PATH, st.st_uid, gid)
            changed = True
    except (OSError, KeyError):
        pass
    return changed


def _geoip2_importable() -> bool:
    result = run(["python3", "-c", "import geoip2"], timeout=15)
    return result.ok


def ensure_geoip2_package(os_info: package_manager.OSInfo | None = None) -> str | None:
    """Installs the `geoip2` Python package system-wide on the OpenVPN
    host if it isn't already importable -- required for the country/city/
    ASN restriction checks (host-scripts/policy_lib.py's
    geoip_lookup_country/_city/_asn) to do anything beyond fail closed the
    moment an admin configures one of those restrictions; IP address
    restriction and everything else (MAC binding, OS, bandwidth) need it
    for nothing. A no-op, fast, if it's already present -- checked via a
    real `import geoip2` subprocess rather than trying to introspect
    installed packages, so this is accurate regardless of how it got
    there (this function, a manual `pip install`, an OS package, a venv
    on PATH, ...).

    Returns a short human-readable description of what happened, or None
    if nothing needed to change. Best-effort: any failure here is logged
    and swallowed, never raised -- GeoIP-based restrictions are an
    opt-in feature layered on top of MAC-binding/OS/bandwidth
    enforcement (which this function's caller, install_host_scripts,
    already made fully functional regardless of this), so a pip/network
    hiccup installing this one optional dependency must not fail the
    whole install."""
    if _geoip2_importable():
        return None
    try:
        os_info = os_info or package_manager.detect_os()
        # `python3 -m pip` may not exist at all yet (observed live: a
        # fresh Ubuntu image has no `pip` module until python3-pip is
        # installed) -- ensure it via the normal OS package step first,
        # same mechanism installer.py already uses for openvpn/openssl/
        # ca-certificates, rather than a separate get-pip.py bootstrap.
        package_manager.install_packages(os_info, ["python3-pip"])
        # --break-system-packages is required on pip>=23.1 (PEP 668,
        # "externally managed environment") on Debian/Ubuntu 24.04+ and
        # similarly recent distros -- but is an UNRECOGNIZED flag on
        # older pip (e.g. CentOS 7's default), which would otherwise
        # error out immediately. Try with it first (the common case on
        # any currently-supported distro), fall back to a plain install
        # if that specific invocation fails, rather than trying to
        # detect the pip version up front.
        try:
            run(["python3", "-m", "pip", "install", "--break-system-packages", "geoip2"], timeout=120)
        except CommandError:
            pass
        if not _geoip2_importable():
            run(["python3", "-m", "pip", "install", "geoip2"], timeout=120)
        if _geoip2_importable():
            return "installed the geoip2 Python package (needed for country/city/ASN restriction checks)"
        logger.warning("geoip2 still not importable after install attempts -- country/city/ASN "
                        "restrictions will fail closed until this is resolved manually")
        return "attempted to install geoip2, but it's still not importable -- see logs"
    except Exception:
        logger.exception("failed to install geoip2 -- country/city/ASN restrictions will fail closed "
                          "until this is resolved manually (MAC binding/OS/bandwidth are unaffected)")
        return "failed to install geoip2 -- see logs (MAC binding/OS/bandwidth restrictions are unaffected)"


def install_host_scripts(paths: OpenVPNPaths, *, os_info: package_manager.OSInfo | None = None) -> list[str]:
    """Deploys policy_lib.py/openvpn-mac-addr-check.py/
    openvpn-client-disconnect.py to OPENVPN_DIR, creates the policy/
    subdirectory and its JSON files (+ .lock files) with nobody-writable
    permissions, ensures openvpn_db.txt/openvpn.log exist, ensures the
    geoip2 Python package is installed and vpn-tools.conf (if present) is
    nobody-group-readable, and appends the script-security/client-connect/
    client-disconnect block to server.conf if it isn't already there.
    Returns a list of short human-readable change descriptions (for
    CLI/log output) -- entries are only added for things that actually
    changed, so a fully-idempotent repeat call can return an empty list.

    Everything here is meant to be run completely unattended (no manual
    "now go apt-get/pip install X" or "now go chmod Y" follow-up step,
    the exact gap found live on 2026-08-12: this function used to leave
    both the geoip2 package and vpn-tools.conf's permissions for an admin
    to sort out by hand afterward) -- a fresh install (installer.py) or a
    standalone `install-host-scripts` CLI run both get a fully working,
    fully enforcing setup from this one call.

    Does NOT restart/reload the OpenVPN service -- a server.conf change
    only takes effect on the NEXT start. Call this before
    service_manager.enable_and_start() during a fresh install (see
    installer.py) so the very first start already has it; call
    service_manager.restart() explicitly afterward for an
    already-running server (see the `install-host-scripts` CLI action's
    --restart flag) -- deliberately never triggered automatically here,
    since restarting drops every connected client.

    `os_info` lets a caller that already ran package_manager.detect_os()
    (installer.py's install(), during a fresh install) pass it straight
    through instead of this function detecting it again."""
    changes: list[str] = []
    group_name = paths.group_name

    os.makedirs(paths.openvpn_dir, exist_ok=True)
    _copy_script(HOST_SCRIPTS_SOURCE_DIR / "policy_lib.py", paths.policy_lib_script, group_name, executable=False)
    _copy_script(HOST_SCRIPTS_SOURCE_DIR / "openvpn-mac-addr-check.py", paths.mac_check_script, group_name, executable=True)
    _copy_script(HOST_SCRIPTS_SOURCE_DIR / "openvpn-client-disconnect.py", paths.disconnect_script, group_name, executable=True)
    changes.append("installed policy_lib.py / openvpn-mac-addr-check.py / openvpn-client-disconnect.py")

    _ensure_file(paths.db_file, "", group_name, 0o640)
    _ensure_file(paths.conn_log, "", group_name, 0o640)

    os.makedirs(paths.policy_dir, exist_ok=True)
    os.chmod(paths.policy_dir, 0o770)
    _chown_nobody(paths.policy_dir, group_name)
    for policy_path in (paths.client_policy_file, paths.client_usage_file):
        _ensure_file(policy_path, "{}\n", group_name, 0o664)
        # The flock lock file each of policy_lib.py's _locked() calls
        # takes alongside its data file -- pre-created here (same reasoning
        # as client_policy.json/client_usage.json themselves) so the very
        # first connect/disconnect script invocation doesn't have to
        # create it under `nobody` against a root-owned policy/ directory.
        _ensure_file(f"{policy_path}.lock", "", group_name, 0o666)
    changes.append("ensured openvpn_db.txt / openvpn.log / policy/ (client_policy.json, client_usage.json, .lock files) exist with correct ownership")

    if _fix_vpn_tools_conf_permissions(group_name):
        changes.append(f"fixed {VPN_TOOLS_CONF_PATH} permissions so the nobody-run connect/disconnect scripts can read it")

    geoip2_change = ensure_geoip2_package(os_info)
    if geoip2_change:
        changes.append(geoip2_change)

    with open(paths.server_conf, encoding="utf-8") as f:
        server_conf = f.read()
    if SERVER_CONF_MARKER_BEGIN not in server_conf:
        with open(paths.server_conf, "a", encoding="utf-8") as f:
            if not server_conf.endswith("\n"):
                f.write("\n")
            f.write(render_server_conf_additions(paths))
        changes.append(f"appended client-connect/client-disconnect block to {paths.server_conf} -- "
                        f"NOT yet active until the OpenVPN service is restarted")

    return changes
