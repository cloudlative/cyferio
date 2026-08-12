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

import os
import shutil
from pathlib import Path

from .exceptions import InstallError
from .paths import OpenVPNPaths

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


def install_host_scripts(paths: OpenVPNPaths) -> list[str]:
    """Deploys policy_lib.py/openvpn-mac-addr-check.py/
    openvpn-client-disconnect.py to OPENVPN_DIR, creates the policy/
    subdirectory and its JSON files (+ .lock files) with nobody-writable
    permissions, ensures openvpn_db.txt/openvpn.log exist, and appends the
    script-security/client-connect/client-disconnect block to server.conf
    if it isn't already there. Returns a list of short human-readable
    change descriptions (for CLI/log output) -- empty if server.conf
    already had the block (everything else still runs and self-heals, but
    server.conf itself is untouched on a repeat call).

    Does NOT restart/reload the OpenVPN service -- a server.conf change
    only takes effect on the NEXT start. Call this before
    service_manager.enable_and_start() during a fresh install (see
    installer.py) so the very first start already has it; call
    service_manager.restart() explicitly afterward for an
    already-running server (see the `install-host-scripts` CLI action's
    --restart flag) -- deliberately never triggered automatically here,
    since restarting drops every connected client."""
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
