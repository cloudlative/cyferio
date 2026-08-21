"""System Audit Phase 3: automated remediation -- deliberately narrow in
scope. This module can ONLY chmod a file to one hardcoded, canonical mode,
for one hardcoded allowlist of paths. It cannot take an arbitrary path or
an arbitrary mode from the caller -- see remediate_chmod()'s own
docstring for exactly why that split matters.

SCOPE, explicit: file/directory permission fixes only. SSH config
(PermitRootLogin, PasswordAuthentication, ...) and firewall rule changes
are NOT remediated here, and won't be until they get the heavier
safeguards this repo's own task spec calls for (config backup, apply,
validate the RESULT actually works, automatic rollback on failure,
explicit "you may lose remote access" warning) -- a single chmod is
atomic and trivially reversible (the previous mode is just a number),
which is exactly what makes it safe enough to automate FIRST. An SSH or
firewall change is neither.

Dispatched via app/cli/openvpn_admin.py's `remediate-chmod-permissions`
action -- the same one whitelisted script the host-executor SSH channel
already runs for the read-only audit probes (services/system/
audit_probe.py) and the live-session actions (routes/clients.py). This
is the first WRITE capability added to that channel for System Audit --
worth being explicit about, since every other System Audit host-executor
action so far has been read-only."""
from __future__ import annotations

import os
import re
import stat

from ..openvpn.exceptions import ValidationError

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
