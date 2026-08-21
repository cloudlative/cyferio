"""Read-only host-state probes for the System Audit module's live firewall
checks (vpnadmin/system_audit/firewall_checks.py) -- the Phase 2 extension
to that module's Phase 1 file-based-only checks (see that module's own
docstring for the full "why file reads vs. live commands" story).

This is the ONLY new capability the host-executor SSH channel gains for
System Audit: every function here is read-only (no command here can
change firewall/service/system state), matching the module's own
docstring on why that boundary matters (an incorrect firewall change over
this channel could disconnect the administrator from the server -- see
this repo's task spec, "High-Risk Changes"). Dispatched via
app/cli/openvpn_admin.py's `audit-firewall` action -- the same one
whitelisted script host_executor.py is already restricted to running, so
no sudoers/authorized_keys change is needed to add this.

Every probe is individually best-effort: a missing binary (ufw not
installed, nft not installed) is reported as `"installed": false`, never
raised as an error -- one missing tool must not fail the whole probe."""
from __future__ import annotations

from .process_manager import CommandError, run


def _try_run(args: list[str], timeout: int = 10) -> tuple[bool, str, str]:
    """Returns (installed_and_ran, stdout, stderr). "installed_and_ran" is
    False only when the binary itself couldn't be found/run (CommandError)
    -- a non-zero exit with real output (e.g. `ufw status` when ufw is
    installed but inactive still exits 0; `firewall-cmd --state` exits 252
    when firewalld is installed but not running) still counts as "ran",
    the caller inspects stdout/returncode itself for that distinction."""
    try:
        result = run(args, timeout=timeout)
    except CommandError:
        return False, "", ""
    return True, result.stdout, result.stderr


def _try_run_checked(args: list[str], timeout: int = 10) -> tuple[bool, str]:
    """Like _try_run, but for callers that need to tell "ran and
    succeeded, here's real data" apart from "ran but failed" (e.g.
    permission denied without root -- this whole probe assumes it's
    invoked as root via host_executor.py's `sudo -n`, but if that's ever
    misconfigured, a bare non-zero-exit-means-empty-data reading would
    silently look identical to "confirmed zero rules", which is a much
    more dangerous thing to get wrong than just surfacing the error).
    Returns (ok, stdout_or_error_note)."""
    try:
        result = run(args, timeout=timeout)
    except CommandError as e:
        return False, str(e)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout).strip()[:300] or f"exit {result.returncode}"
    return True, result.stdout


def probe_ufw() -> dict:
    installed, stdout, _ = _try_run(["ufw", "status", "verbose"])
    if not installed:
        return {"installed": False}
    active = stdout.strip().lower().startswith("status: active")
    return {"installed": True, "active": active, "status_output": stdout.strip()}


def probe_iptables() -> dict:
    """`-S` (list rules in iptables-restore-loadable format), not `-L`
    -- much easier to reliably parse for "does this rule have a source
    restriction" than `-L`'s columnar human-readable table, and it's what
    iptables-save itself produces. Checked for both the default `filter`
    table (INPUT/FORWARD/OUTPUT policies + rules) and confirms whether
    ip6tables (IPv6) has any rules loaded at all."""
    ok, stdout = _try_run_checked(["iptables", "-S"])
    if not ok:
        # Binary exists (or genuinely doesn't -- can't tell apart here,
        # but either way there's no rule data to report) but the read
        # itself failed -- most commonly a permission error if this ever
        # runs without root. Explicit "error" key, never silently
        # reported as "installed with zero rules": an empty rule set and
        # "couldn't read the rule set" are very different security
        # postures to conflate.
        return {"installed": None, "error": stdout}
    ok6, stdout6 = _try_run_checked(["ip6tables", "-S"])
    policies = {}
    for line in stdout.splitlines():
        if line.startswith("-P "):
            parts = line.split()
            if len(parts) >= 3:
                policies[parts[1]] = parts[2]
    open_rules = [
        line for line in stdout.splitlines()
        if line.startswith("-A INPUT") and "-j ACCEPT" in line and " -s " not in line and "--dport" in line
    ]
    return {
        "installed": True,
        "rules_v4": stdout.strip(),
        "rules_v6": stdout6.strip() if ok6 else None,
        "policies": policies,
        "unrestricted_accept_rules": open_rules,
        "rule_count_v4": len([line for line in stdout.splitlines() if line.startswith("-A")]),
    }


def probe_nftables() -> dict:
    installed, stdout, _ = _try_run(["nft", "list", "ruleset"])
    if not installed:
        return {"installed": False}
    return {"installed": True, "has_rules": bool(stdout.strip()), "ruleset": stdout.strip()}


def probe_firewalld() -> dict:
    installed, stdout, _ = _try_run(["firewall-cmd", "--state"])
    if not installed:
        return {"installed": False}
    running = stdout.strip() == "running"
    zones_out = ""
    if running:
        _, zones_out, _ = _try_run(["firewall-cmd", "--list-all"])
    return {"installed": True, "running": running, "state_output": stdout.strip(), "active_zone_config": zones_out.strip()}


# Firewall-relevant systemd units worth an is-enabled/is-active check --
# a fixed, small allowlist (not "every unit on the system") matching the
# same "bounded, not exhaustive" posture as system_checks.py's world-
# writable scan. openvpn-iptables is this project's own installer-
# generated unit (see firewall_checks.py's own comment on it); the others
# are the firewall backends this module already probes above.
_FIREWALL_UNITS = ("ufw.service", "firewalld.service", "openvpn-iptables.service", "nftables.service")


def probe_firewall_units() -> dict:
    out = {}
    for unit in _FIREWALL_UNITS:
        installed, enabled_stdout, _ = _try_run(["systemctl", "is-enabled", unit], timeout=5)
        if not installed:
            continue
        _, active_stdout, _ = _try_run(["systemctl", "is-active", unit], timeout=5)
        out[unit] = {"enabled": enabled_stdout.strip(), "active": active_stdout.strip()}
    return out


def probe_firewall() -> dict:
    """The single entry point openvpn_admin.py's `audit-firewall` action
    calls -- one JSON-serializable snapshot of everything this module can
    determine about the host's live firewall state."""
    return {
        "ufw": probe_ufw(),
        "iptables": probe_iptables(),
        "nftables": probe_nftables(),
        "firewalld": probe_firewalld(),
        "units": probe_firewall_units(),
    }
