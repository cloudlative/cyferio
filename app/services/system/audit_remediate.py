"""System Audit automated remediation.

PHASE 3 (2026-08-22): remediate_chmod() -- can ONLY chmod a file to one
hardcoded, canonical mode, for one hardcoded allowlist of paths. It cannot
take an arbitrary path or an arbitrary mode from the caller -- see its own
docstring for exactly why that split matters. A single chmod is atomic and
trivially reversible (the previous mode is just a number), which is what
made it safe enough to automate first.

PHASE 4 (2026-08-22): remediate_ssh_directive() and remediate_firewall()
extend automation to SSH config directives and a small set of firewall
enable/allow actions -- exactly the two categories Phase 3's docstring
said needed heavier safeguards before they could be automated. Both get
that treatment here:
  - SSH: back up sshd_config (or whichever file already sets the
    directive) before touching it, apply the ONE hardcoded safe value for
    that directive (never a caller-supplied value), validate the result
    with `sshd -t` BEFORE reloading, and automatically restore the backup
    if validation fails -- sshd is never reloaded with a config that
    doesn't even parse. What this does NOT protect against: a config that
    IS valid but still removes the only account you can log in as (e.g.
    disabling password auth when no admin has a key installed yet) --
    ssh_checks.py's own remediation_risk text on each finding says so
    explicitly, and the frontend surfaces it before the confirm click.
  - Firewall: each action is a small, specific, pre-checked sequence (e.g.
    "add an SSH allow rule, THEN enable ufw" -- never enable-then-check),
    chosen specifically to avoid the classic self-lockout failure mode.
    There is deliberately NO general "run this firewall command" action,
    and no remediation at all for iptables default-policy/rule changes --
    those need a full picture of every port in use to do safely, which
    this module doesn't have.

Every action here is still: caller picks WHICH allowlisted thing to fix,
this module alone decides WHAT change to make. Dispatched via app/cli/
openvpn_admin.py's `remediate-*` actions -- the same one whitelisted
script the host-executor SSH channel already runs for the read-only audit
probes (services/system/audit_probe.py) and the live-session actions
(routes/clients.py)."""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from datetime import datetime, timezone

from ..openvpn.exceptions import FirewallConfigError, ServiceManagementError, ValidationError

# The canonical safe mode for each path is fixed here, not supplied by
# the caller -- vpnadmin/system_audit/system_checks.py's own
# _check_permissions() computes the SAME targets (see that function's
# `checks` list), so this isn't duplicated logic drifting independently;
# it's this module deliberately not trusting the caller with a mode
# value at all. A caller can only pick WHICH allowlisted path to fix,
# never WHAT to set it to.
_CHMOD_TARGETS: dict[str, int] = {
    "/etc/shadow": 0o640,
    "/etc/passwd": 0o644,
    "/etc/ssh/sshd_config": 0o644,
    "/etc/sudoers": 0o440,
}
# SSH host private keys -- ssh_host_<algo>_key, e.g. ssh_host_ed25519_key
# (explicitly NOT the matching .pub file, which is meant to be world-
# readable and isn't a security issue at any mode).
_HOST_KEY_RE = re.compile(r"^/etc/ssh/ssh_host_[a-z0-9]+_key$")
_HOST_KEY_TARGET_MODE = 0o600


def _target_mode_for(path: str) -> int:
    if path in _CHMOD_TARGETS:
        return _CHMOD_TARGETS[path]
    if _HOST_KEY_RE.match(path):
        return _HOST_KEY_TARGET_MODE
    raise ValidationError(f"'{path}' is not an allowed automated-remediation target.")


def remediate_chmod(path: str) -> dict:
    """Fixes ONE file's permissions to its canonical safe mode --
    system_audit's ONLY automated remediation action in this phase.
    Raises ValidationError (never proceeds) for anything outside the
    fixed allowlist above, a path that doesn't resolve to a plain file,
    or a path containing traversal segments (`os.path.normpath` first --
    defense in depth on top of the allowlist itself, which already
    couldn't match a traversal-containing path anyway since it's an exact
    dict lookup / anchored regex, not a prefix check).

    "Backup" for this operation is simply recording the previous mode --
    a chmod has no content to back up, and reverting it is just another
    chmod back to the recorded value (see the API route's own Undo
    affordance). "Validate the resulting configuration" (spec section 7)
    means re-stat-ing the file after the change and confirming the new
    mode actually matches what was requested -- `verified: False` in the
    return value if not (chmod itself would have raised on most real
    failures, but a network filesystem or an unusual mount option could
    theoretically accept the syscall without applying it; this closes
    that gap rather than assuming success)."""
    path = os.path.normpath(path)
    target_mode = _target_mode_for(path)

    if not os.path.isfile(path) or os.path.islink(path):
        raise ValidationError(f"'{path}' does not exist or is not a plain file.")

    previous_mode = stat.S_IMODE(os.stat(path).st_mode)
    if previous_mode == target_mode:
        return {
            "path": path, "previous_mode": oct(previous_mode), "new_mode": oct(previous_mode),
            "target_mode": oct(target_mode), "verified": True, "changed": False,
        }

    # os.chmod, not process_manager.run(["chmod", ...]) -- a single libc
    # syscall has no argument-injection surface at all (no shell, no argv
    # parsing of a path that could start with a dash), where even a
    # safely-argv-listed subprocess call is one more moving part (a
    # missing binary, a PATH surprise) for something this simple.
    os.chmod(path, target_mode)
    new_mode = stat.S_IMODE(os.stat(path).st_mode)
    return {
        "path": path,
        "previous_mode": oct(previous_mode),
        "new_mode": oct(new_mode),
        "target_mode": oct(target_mode),
        "verified": new_mode == target_mode,
        "changed": True,
    }


# --- SSH directive remediation (Phase 4) -----------------------------------

# The ONE safe value each directive is set to -- mirrors ssh_checks.py's own
# _DIRECTIVE_CHECKS `expected` values exactly (kept as a separate literal
# dict, not imported, so this module has no dependency on vpnadmin at all --
# it runs on the HOST via the CLI entrypoint, not inside the app container).
# A caller can only pick WHICH of these directives to fix, never what value
# it gets set to.
_SSH_DIRECTIVE_TARGETS: dict[str, str] = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "no",
    "permitemptypasswords": "no",
    "permituserenvironment": "no",
    "x11forwarding": "no",
    "allowagentforwarding": "no",
    "allowtcpforwarding": "no",
}
_SSHD_CONFIG_MAIN = "/etc/ssh/sshd_config"
_SSHD_CONFIG_DROPIN_DIR = "/etc/ssh/sshd_config.d"


def _sshd_config_paths() -> list[str]:
    paths = [_SSHD_CONFIG_MAIN]
    if os.path.isdir(_SSHD_CONFIG_DROPIN_DIR):
        try:
            paths += sorted(
                os.path.join(_SSHD_CONFIG_DROPIN_DIR, f)
                for f in os.listdir(_SSHD_CONFIG_DROPIN_DIR) if f.endswith(".conf")
            )
        except OSError:
            pass
    return paths


def _find_directive_occurrence(directive: str) -> tuple[str, int, str] | None:
    """Returns (file_path, line_index, original_line) for the LAST
    occurrence of `directive` across sshd_config + sshd_config.d/*.conf --
    same file set and same "last occurrence wins" convention
    ssh_checks.py's own _parse_sshd_config() uses (see that function's
    docstring for why: a best-effort static read, not sshd's actual
    first-match-wins merge logic). Editing whatever occurrence the AUDIT
    ITSELF treated as authoritative keeps the check and the fix for it
    consistent with each other, even where both share the same known
    limitation. Returns None if the directive isn't set anywhere yet."""
    found: tuple[str, int, str] | None = None
    for path in _sshd_config_paths():
        try:
            with open(path, "r") as f:
                lines = f.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == directive:
                found = (path, i, line)
    return found


def _reload_sshd() -> bool:
    """Tries both common service names (Debian/Ubuntu use "ssh", RHEL-
    family uses "sshd") -- a reload (SIGHUP), not a restart, so existing
    connected sessions are not dropped; only new connections see the
    updated config."""
    for service_name in ("ssh", "sshd"):
        result = subprocess.run(
            ["systemctl", "reload", service_name], capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return True
    return False


def remediate_ssh_directive(directive: str) -> dict:
    """Sets one sshd_config directive to its one hardcoded safe value.
    Raises ValidationError for any directive outside _SSH_DIRECTIVE_TARGETS.

    Safety sequence, in order:
      1. Locate the directive's current authoritative occurrence (or plan
         to append it to the main config file if it's not set anywhere).
      2. Back up that file (a plain timestamped copy -- reverting is just
         copying the backup back over the live file).
      3. Write the new value in place (or append it).
      4. Validate with `sshd -t`. If that fails, restore the backup
         immediately and return WITHOUT reloading sshd -- the previous,
         known-working config stays live the whole time; a bad edit never
         reaches a running sshd.
      5. Only once (4) passes: reload sshd so the new value takes effect.

    Returns a dict describing exactly what happened (including whether it
    was rolled back) -- callers must check `applied` rather than assume
    success just because no exception was raised."""
    directive = directive.lower()
    if directive not in _SSH_DIRECTIVE_TARGETS:
        raise ValidationError(f"'{directive}' is not an allowed automated SSH remediation target.")
    target_value = _SSH_DIRECTIVE_TARGETS[directive]

    occurrence = _find_directive_occurrence(directive)
    if occurrence is not None:
        path, line_idx, original_line = occurrence
    else:
        path, line_idx, original_line = _SSHD_CONFIG_MAIN, None, ""

    if not os.path.isfile(path):
        raise ValidationError(f"'{path}' does not exist.")

    with open(path, "r") as f:
        lines = f.readlines()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = f"{path}.audit-backup-{timestamp}"
    shutil.copy2(path, backup_path)

    new_line = f"{directive} {target_value}\n"
    if line_idx is not None:
        lines[line_idx] = new_line
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"\n# Added by System Audit automated remediation, {timestamp}\n")
        lines.append(new_line)

    with open(path, "w") as f:
        f.writelines(lines)

    validation = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=15)
    if validation.returncode != 0:
        shutil.copy2(backup_path, path)
        return {
            "directive": directive, "path": path,
            "previous_line": original_line.strip() or None,
            "attempted_value": target_value,
            "applied": False, "rolled_back": True,
            "validation_error": (validation.stderr or validation.stdout).strip()[:2000],
            "backup_path": backup_path,
        }

    reloaded = _reload_sshd()
    if not reloaded:
        # Config validated fine but neither service name reloaded -- roll
        # back rather than leave a validated-but-not-yet-applied change
        # that a caller's "applied": True would misrepresent.
        shutil.copy2(backup_path, path)
        raise ServiceManagementError(
            "sshd_config was updated and validated, but reloading the sshd/ssh service failed -- "
            "the change was rolled back.", path=path, directive=directive,
        )

    return {
        "directive": directive, "path": path,
        "previous_line": original_line.strip() or None,
        "new_value": target_value,
        "applied": True, "rolled_back": False,
        "backup_path": backup_path,
    }


# --- Firewall remediation (Phase 4) -----------------------------------------

_FIREWALL_ACTIONS = frozenset({
    "ufw_allow_ssh_and_enable", "firewalld_allow_ssh_and_enable", "enable_openvpn_iptables_unit",
})


def _current_ssh_port() -> int:
    """Best-effort read of the currently-configured SSH port, defaulting
    to 22 -- used only to decide what port to explicitly allow BEFORE
    enabling a firewall, so remediation never enables a firewall that
    would immediately cut off the very connection running it."""
    try:
        with open(_SSHD_CONFIG_MAIN, "r") as f:
            text = f.read()
    except OSError:
        return 22
    m = re.search(r"^\s*Port\s+(\d+)", text, re.MULTILINE | re.IGNORECASE)
    return int(m.group(1)) if m else 22


def _run(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _remediate_ufw_allow_ssh_and_enable() -> dict:
    port = _current_ssh_port()
    allow = _run(["ufw", "allow", f"{port}/tcp"])
    if allow.returncode != 0:
        raise FirewallConfigError(
            f"'ufw allow {port}/tcp' failed -- ufw was NOT enabled.",
            output=(allow.stderr or allow.stdout).strip()[:2000],
        )
    enable = _run(["ufw", "--force", "enable"])
    if enable.returncode != 0:
        raise FirewallConfigError(
            f"SSH allow rule for port {port} was added, but 'ufw enable' failed.",
            output=(enable.stderr or enable.stdout).strip()[:2000],
        )
    status = _run(["ufw", "status"])
    return {
        "action": "ufw_allow_ssh_and_enable", "ssh_port_allowed": port,
        "applied": True, "status_output": status.stdout.strip()[:2000],
    }


def _remediate_firewalld_allow_ssh_and_enable() -> dict:
    add = _run(["firewall-cmd", "--permanent", "--add-service=ssh"])
    if add.returncode != 0:
        raise FirewallConfigError(
            "'firewall-cmd --add-service=ssh' failed -- firewalld was NOT started.",
            output=(add.stderr or add.stdout).strip()[:2000],
        )
    enable_start = _run(["systemctl", "enable", "--now", "firewalld"])
    if enable_start.returncode != 0:
        raise FirewallConfigError(
            "SSH was permanently added to firewalld's default zone, but starting firewalld failed.",
            output=(enable_start.stderr or enable_start.stdout).strip()[:2000],
        )
    # --permanent changes need a reload to take effect on the now-running
    # daemon (a fresh `enable --now` start already picks up permanent
    # config, but this is idempotent/harmless if it's a no-op).
    _run(["firewall-cmd", "--reload"])
    return {"action": "firewalld_allow_ssh_and_enable", "applied": True}


def _remediate_enable_openvpn_iptables_unit() -> dict:
    result = _run(["systemctl", "enable", "--now", "openvpn-iptables.service"])
    if result.returncode != 0:
        raise ServiceManagementError(
            "systemctl enable --now openvpn-iptables.service failed.",
            output=(result.stderr or result.stdout).strip()[:2000],
        )
    return {"action": "enable_openvpn_iptables_unit", "applied": True}


def remediate_firewall(action: str) -> dict:
    """Dispatches one allowlisted firewall action. Raises ValidationError
    for anything not in _FIREWALL_ACTIONS -- there is no generic "run this
    firewall command" path; each action here is its own fixed, pre-checked
    sequence (see this module's docstring for why, e.g. always allow SSH
    BEFORE enabling ufw, never after)."""
    if action == "ufw_allow_ssh_and_enable":
        return _remediate_ufw_allow_ssh_and_enable()
    if action == "firewalld_allow_ssh_and_enable":
        return _remediate_firewalld_allow_ssh_and_enable()
    if action == "enable_openvpn_iptables_unit":
        return _remediate_enable_openvpn_iptables_unit()
    raise ValidationError(f"'{action}' is not an allowed automated firewall remediation action.")
