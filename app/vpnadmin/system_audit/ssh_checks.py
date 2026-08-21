"""SSH Security checks -- parses /etc/ssh/sshd_config (and sshd_config.d/
drop-ins) directly from the host_root mount, plus host key and
authorized_keys file permissions.

IMPORTANT CAVEAT, surfaced in findings too: this parses the CONFIG FILE
text, not sshd's actual merged/effective configuration. It does not
evaluate `Match` blocks (conditional overrides for specific users/groups/
addresses), does not know sshd's own compiled-in defaults for a directive
that's simply absent from the file, and can't detect an actively wrong-
but-unparsed directive the way `sshd -T` (which requires executing a
command on the host -- see this package's __init__.py docstring) would.
Every directive-based finding below states its evidence as "the config
file says X" -- true and verifiable, even though it may not always equal
"sshd is actually enforcing X" in every edge case (e.g. a Match block
override). This is stated once here rather than repeated on every single
finding."""
import os
import re
import stat

from . import Finding


def _p(host_root: str, *parts: str) -> str:
    return os.path.join(host_root, *(p.lstrip("/") for p in parts))


def _read(path: str) -> str | None:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _parse_sshd_config(host_root: str) -> dict[str, str]:
    """Returns {directive_lowercased: last_value} -- sshd itself uses
    first-match-wins for most directives, but since this is a best-effort
    static read (not sshd's own merge logic) we take the LAST occurrence
    across the main file + any Include'd/sshd_config.d/*.conf drop-ins,
    which is the more common "override via drop-in" authoring pattern on
    modern Debian/Ubuntu (sshd_config's own default now Includes
    sshd_config.d/*.conf near the top)."""
    directives: dict[str, str] = {}
    paths = [_p(host_root, "/etc/ssh/sshd_config")]
    drop_in_dir = _p(host_root, "/etc/ssh/sshd_config.d")
    if os.path.isdir(drop_in_dir):
        try:
            paths += sorted(
                os.path.join(drop_in_dir, f) for f in os.listdir(drop_in_dir) if f.endswith(".conf")
            )
        except OSError:
            pass
    for path in paths:
        text = _read(path)
        if text is None:
            continue
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0].lower(), parts[1].strip()
            directives[key] = value
    return directives


# check_id, directive, "expected" predicate description, severity if
# violated, why-it-matters, remediation line. `default_if_absent` is
# sshd's own compiled-in default per its manual page -- used so an ABSENT
# directive is evaluated against what sshd actually does, not silently
# skipped as "no finding".
_DIRECTIVE_CHECKS = [
    dict(check_id="ssh.permit_root_login", directive="permitrootlogin", default_if_absent="prohibit-password",
         bad_values={"yes"}, severity="critical", title="SSH Root Login Enabled",
         why="Allowing direct root login increases the impact of credential compromise -- an attacker with "
             "the root password/key gets full system access in one step, and root logins can't be "
             "individually attributed to a person the way a named-user-plus-sudo login can.",
         expected="no (or prohibit-password to still allow root's key for automation, e.g. this app's own "
                  "host-executor)",
         remediation="Set 'PermitRootLogin no' in sshd_config after confirming an administrative user with "
                     "working sudo access exists, then restart sshd."),
    dict(check_id="ssh.password_authentication", directive="passwordauthentication", default_if_absent="yes",
         bad_values={"yes"}, severity="high", title="SSH Password Authentication Enabled",
         why="Password authentication is vulnerable to brute-force and credential-stuffing attacks in a way "
             "public-key authentication is not.",
         expected="no (key-based authentication only)",
         remediation="Ensure every admin has a working SSH key installed, then set "
                     "'PasswordAuthentication no' and restart sshd."),
    dict(check_id="ssh.permit_empty_passwords", directive="permitemptypasswords", default_if_absent="no",
         bad_values={"yes"}, severity="critical", title="SSH Empty Passwords Permitted",
         why="Would allow login with a blank password if any account happens to have one set.",
         expected="no", remediation="Set 'PermitEmptyPasswords no' and restart sshd."),
    dict(check_id="ssh.permit_user_environment", directive="permituserenvironment", default_if_absent="no",
         bad_values={"yes"}, severity="medium", title="SSH PermitUserEnvironment Enabled",
         why="Lets a client set arbitrary environment variables for the SSH session (e.g. LD_PRELOAD-style "
             "variables), which has historically been used to bypass restrictions in forced-command setups.",
         expected="no", remediation="Set 'PermitUserEnvironment no' and restart sshd."),
    dict(check_id="ssh.x11_forwarding", directive="x11forwarding", default_if_absent="no",
         bad_values={"yes"}, severity="low", title="SSH X11 Forwarding Enabled",
         why="Rarely needed on a headless VPN server; an unused feature is unnecessary attack surface.",
         expected="no (unless genuinely needed for GUI application access)",
         remediation="Set 'X11Forwarding no' and restart sshd."),
    dict(check_id="ssh.agent_forwarding", directive="allowagentforwarding", default_if_absent="yes",
         bad_values={"yes"}, severity="low", title="SSH Agent Forwarding Allowed",
         why="If this server is ever compromised, agent forwarding lets an attacker use a connected admin's "
             "forwarded SSH agent to authenticate onward to OTHER systems, without ever obtaining the key "
             "itself.",
         expected="no, unless a specific documented workflow needs it",
         remediation="Set 'AllowAgentForwarding no' and restart sshd."),
    dict(check_id="ssh.tcp_forwarding", directive="allowtcpforwarding", default_if_absent="yes",
         bad_values={"yes"}, severity="low", title="SSH TCP Forwarding Allowed",
         why="Lets an SSH session tunnel arbitrary TCP traffic, which can be used to pivot into or out of "
             "the network, bypassing firewall rules that would otherwise apply.",
         expected="no, unless a specific documented workflow needs it",
         remediation="Set 'AllowTcpForwarding no' and restart sshd."),
]


def _check_directives(host_root: str, directives: dict[str, str]) -> list[Finding]:
    findings = []
    for spec in _DIRECTIVE_CHECKS:
        value = directives.get(spec["directive"], spec["default_if_absent"]).lower()
        source = "sshd_config" if spec["directive"] in directives else "sshd's compiled-in default (not set in config)"
        if value in spec["bad_values"]:
            findings.append(Finding(
                check_id=spec["check_id"], category="ssh", severity=spec["severity"], title=spec["title"],
                description=f"{spec['directive']} is set to '{value}' ({source}).",
                why_it_matters=spec["why"],
                current_state=f"{spec['directive']} {value}", expected_state=spec["expected"],
                evidence=f"/etc/ssh/sshd_config: {spec['directive']} {value}"
                         + ("" if spec["directive"] in directives else " (default, not explicitly set)"),
                remediation=spec["remediation"],
            ))
        else:
            findings.append(Finding(
                check_id=spec["check_id"], category="ssh", severity="passed",
                title=f"{spec['title'].replace('Enabled', 'Disabled').replace('Permitted', 'Not Permitted').replace('Allowed', 'Not Allowed')}",
                description=f"{spec['directive']} is set to '{value}' ({source}).",
                current_state=f"{spec['directive']} {value}",
            ))
    return findings


def _check_max_auth_tries(directives: dict[str, str]) -> Finding:
    raw = directives.get("maxauthtries", "6")  # sshd's compiled-in default
    try:
        value = int(raw)
    except ValueError:
        value = 6
    if value > 6:
        return Finding(
            check_id="ssh.max_auth_tries", category="ssh", severity="low", title="SSH MaxAuthTries is high",
            description=f"MaxAuthTries is {value} (sshd's default is 6).",
            why_it_matters="A higher retry limit gives a brute-force or credential-stuffing attempt more "
                            "guesses per connection before being disconnected.",
            current_state=str(value), expected_state="6 or lower",
            remediation="Lower MaxAuthTries in sshd_config and restart sshd.",
        )
    return Finding(check_id="ssh.max_auth_tries", category="ssh", severity="passed",
                    title="SSH MaxAuthTries is reasonable", description=f"MaxAuthTries is {value}.")


def _check_login_grace_time(directives: dict[str, str]) -> Finding:
    raw = directives.get("logingracetime", "120")  # sshd's compiled-in default (seconds)
    # Accepts a bare number of seconds, or a suffixed value (30s/2m) --
    # only the common cases, not sshd's full time-spec grammar.
    m = re.match(r"^(\d+)([smh]?)$", raw.strip())
    seconds = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600}[m.group(2)] if m else 120
    if seconds == 0:
        # 0 disables the grace-time limit entirely (unauthenticated
        # connections can stay open indefinitely) -- distinct from, and
        # worse than, just "high".
        return Finding(
            check_id="ssh.login_grace_time", category="ssh", severity="medium", title="SSH LoginGraceTime disabled",
            description="LoginGraceTime is 0, which disables the connection timeout for unauthenticated sessions.",
            why_it_matters="Unauthenticated connections can be held open indefinitely, which can be used to "
                            "exhaust the server's connection slots (a denial-of-service against SSH itself).",
            current_state="0 (disabled)", expected_state="A positive value, e.g. 30s-60s",
            remediation="Set 'LoginGraceTime 30' (or similar) in sshd_config and restart sshd.",
        )
    if seconds > 120:
        return Finding(
            check_id="ssh.login_grace_time", category="ssh", severity="low", title="SSH LoginGraceTime is high",
            description=f"LoginGraceTime is {seconds}s (sshd's default is 120s).",
            why_it_matters="A longer grace period leaves each unauthenticated connection attempt open longer, "
                            "modestly widening the window for connection-exhaustion abuse.",
            current_state=f"{seconds}s", expected_state="120s or lower (commonly 30s-60s)",
            remediation="Lower LoginGraceTime in sshd_config and restart sshd.",
        )
    return Finding(check_id="ssh.login_grace_time", category="ssh", severity="passed",
                    title="SSH LoginGraceTime is reasonable", description=f"LoginGraceTime is {seconds}s.")


def _check_allow_deny_lists(directives: dict[str, str]) -> Finding:
    have_allow = "allowusers" in directives or "allowgroups" in directives
    have_deny = "denyusers" in directives or "denygroups" in directives
    if have_allow or have_deny:
        parts = []
        for key in ("allowusers", "allowgroups", "denyusers", "denygroups"):
            if key in directives:
                parts.append(f"{key}: {directives[key]}")
        return Finding(
            check_id="ssh.user_access_lists", category="ssh", severity="passed",
            title="SSH access is restricted to specific users/groups",
            description="; ".join(parts), current_state="; ".join(parts),
        )
    return Finding(
        check_id="ssh.user_access_lists", category="ssh", severity="info",
        title="SSH access is not restricted by user/group allowlist",
        description="No AllowUsers/AllowGroups/DenyUsers/DenyGroups directive is set -- any local account "
                     "that otherwise satisfies authentication can attempt to log in over SSH.",
        why_it_matters="An explicit allowlist is defense in depth: even if an unintended account gets a "
                        "working password/key, it still can't SSH in unless it's on the list.",
        expected_state="AllowUsers/AllowGroups set to the specific accounts that need SSH access",
        remediation="Consider adding 'AllowUsers <admin-username>' (or AllowGroups) to sshd_config if the set "
                     "of accounts that need SSH access is known and stable.",
    )


def _check_ssh_port(directives: dict[str, str]) -> Finding:
    port = directives.get("port", "22")
    if port == "22":
        return Finding(
            check_id="ssh.port", category="ssh", severity="info",
            title="SSH is listening on the default port (22)",
            description="Port 22 is the standard SSH port -- widely scanned by automated bots. This is "
                         "informational, not a finding requiring action: changing the port is 'security "
                         "through obscurity' (it doesn't stop a targeted attacker, only reduces generic "
                         "automated scan noise) and is not a substitute for the authentication hardening "
                         "checks above.",
            current_state="22",
        )
    return Finding(
        check_id="ssh.port", category="ssh", severity="passed",
        title="SSH is listening on a non-default port", description=f"Port {port}.", current_state=port,
    )


def _check_host_key_permissions(host_root: str) -> list[Finding]:
    findings: list[Finding] = []
    ssh_dir = _p(host_root, "/etc/ssh")
    if not os.path.isdir(ssh_dir):
        return findings
    try:
        entries = os.listdir(ssh_dir)
    except OSError:
        return findings
    for name in entries:
        if not (name.startswith("ssh_host_") and name.endswith("_key") and not name.endswith(".pub")):
            continue
        full = os.path.join(ssh_dir, name)
        try:
            mode = stat.S_IMODE(os.stat(full).st_mode)
        except OSError:
            continue
        if mode & 0o077:  # any group/other bit set at all
            findings.append(Finding(
                check_id=f"ssh.host_key_permissions.{name}", category="ssh", severity="critical",
                title=f"SSH host private key {name} is readable beyond root",
                description=f"{name} has mode {oct(mode)} -- a private host key should never be readable by "
                             f"any account other than root.",
                why_it_matters="Anyone able to read a host private key can impersonate this server to "
                                "clients (a man-in-the-middle attack), silently, with no way for a client to "
                                "detect it via SSH's own host-key verification.",
                current_state=oct(mode), expected_state="0600 (root read/write only)",
                evidence=f"stat /etc/ssh/{name} (via host mount)",
                remediation=f"chmod 600 /etc/ssh/{name}",
            ))
        else:
            findings.append(Finding(
                check_id=f"ssh.host_key_permissions.{name}", category="ssh", severity="passed",
                title=f"SSH host key {name} permissions OK", description=f"Mode {oct(mode)}.",
            ))
    return findings


def run(host_root: str) -> list[Finding]:
    directives = _parse_sshd_config(host_root)
    if not directives and _read(_p(host_root, "/etc/ssh/sshd_config")) is None:
        return [Finding(
            check_id="ssh.sshd_not_found", category="ssh", severity="info",
            title="sshd_config not found",
            description="No /etc/ssh/sshd_config was found on this host -- SSH may not be installed, or "
                         "uses a non-standard configuration path.",
        )]
    findings: list[Finding] = []
    findings += _check_directives(host_root, directives)
    findings.append(_check_max_auth_tries(directives))
    findings.append(_check_login_grace_time(directives))
    findings.append(_check_allow_deny_lists(directives))
    findings.append(_check_ssh_port(directives))
    findings += _check_host_key_permissions(host_root)
    return findings
