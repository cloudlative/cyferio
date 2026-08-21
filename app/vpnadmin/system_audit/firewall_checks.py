"""Firewall checks -- LIVE kernel/service state when the host-executor SSH
channel is configured (Phase 2, added 2026-08-22: services/system/
audit_probe.py's probe_firewall(), dispatched via openvpn_admin.py's
`audit-firewall` action -- the same one whitelisted script that channel
already runs, so no sudoers/authorized_keys change was needed). Falls
back to BEST-EFFORT file reads (Phase 1's original scope) when that
channel isn't configured or the call fails for any reason -- see
_live_probe() below and this package's __init__.py module docstring for
the full "why file reads, not subprocess" story that made file-reads the
Phase 1 default in the first place.

The fallback's own caveat still applies whenever live data isn't
available: this project's own installer (openvpn-install.sh) uses bare
iptables via a generated systemd unit (openvpn-iptables.service) rather
than ufw or firewalld -- iptables rules loaded that way live ONLY in the
kernel's netfilter tables, with no rules file on disk to read (unless the
host separately runs iptables-persistent, which does write one). Without
live access, this module can only confirm the SERVICE that would have
loaded the rules is enabled -- it explicitly says so, rather than
reporting "no firewall" when one may well be active. Do not treat a
"could not verify" Informational finding here as "no firewall is
running" -- it means what it says."""
import os
import re

from . import Finding

# Same check_ids on both the live and file-based paths where they're
# semantically equivalent (firewall.ufw_enabled, firewall.firewalld_enabled,
# firewall.openvpn_iptables_unit) -- so a host that starts using the
# host-executor channel after already having audit history doesn't get a
# spurious "check_id disappeared, new one appeared" discontinuity in that
# history; it just starts getting a more accurate answer to the same
# question. Only genuinely new capabilities (real iptables rule/policy
# inspection) get new check_ids, since there's no static-check
# equivalent for them to continue from.


def _p(host_root: str, *parts: str) -> str:
    return os.path.join(host_root, *(p.lstrip("/") for p in parts))


def _read(path: str) -> str | None:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _service_enabled(host_root: str, unit_name: str) -> bool | None:
    """A unit is "enabled" if a symlink to it exists under any of
    systemd's *.wants/ directories (the standard result of `systemctl
    enable`) -- reading the symlink directly, not calling `systemctl
    is-enabled` (see module docstring). Returns None if neither the
    enabled-symlink location nor the unit file itself could be found at
    all (distinct from "found the unit file but it's not enabled" ->
    False), so callers can tell "definitely disabled" from "couldn't
    determine anything about this service"."""
    wants_dirs = [
        _p(host_root, "/etc/systemd/system/multi-user.target.wants"),
        _p(host_root, "/etc/systemd/system/sockets.target.wants"),
    ]
    unit_paths = [
        _p(host_root, "/etc/systemd/system", unit_name),
        _p(host_root, "/lib/systemd/system", unit_name),
        _p(host_root, "/usr/lib/systemd/system", unit_name),
    ]
    unit_exists = any(os.path.exists(p) for p in unit_paths)
    for d in wants_dirs:
        if os.path.exists(os.path.join(d, unit_name)):
            return True
    if unit_exists:
        return False
    return None


def _check_ufw(host_root: str) -> list[Finding]:
    ufw_conf = _read(_p(host_root, "/etc/ufw/ufw.conf"))
    if ufw_conf is None:
        return []  # ufw not installed on this host -- not a finding, just not applicable
    enabled_match = re.search(r"^ENABLED\s*=\s*(yes|no)", ufw_conf, re.MULTILINE | re.IGNORECASE)
    enabled = enabled_match is not None and enabled_match.group(1).lower() == "yes"
    findings = []
    if not enabled:
        findings.append(Finding(
            check_id="firewall.ufw_enabled", category="firewall", severity="high",
            title="UFW is installed but disabled",
            description="ufw is present on this system (/etc/ufw/ufw.conf) but its ENABLED setting is 'no'.",
            why_it_matters="An installed-but-disabled firewall provides no protection -- every port a "
                            "service listens on is reachable unless something else (a cloud provider "
                            "security group, iptables rules from elsewhere) is filtering traffic.",
            current_state="ENABLED=no", expected_state="ENABLED=yes (after confirming the rule set is correct)",
            evidence="/etc/ufw/ufw.conf",
            remediation="Review 'ufw status verbose' rules for correctness, then 'ufw enable'. Ensure SSH is "
                         "explicitly allowed BEFORE enabling, to avoid losing remote access.",
        ))
    else:
        findings.append(Finding(
            check_id="firewall.ufw_enabled", category="firewall", severity="passed",
            title="UFW is enabled", description="ufw's ENABLED setting is 'yes'.",
        ))
        findings += _check_ufw_rules(host_root)
    return findings


def _check_ufw_rules(host_root: str) -> list[Finding]:
    findings = []
    for rules_file, proto in (("/etc/ufw/user.rules", "IPv4"), ("/etc/ufw/user6.rules", "IPv6")):
        text = _read(_p(host_root, rules_file))
        if not text:
            continue
        # ufw's own rules files are iptables-restore syntax, e.g.:
        #   -A ufw-user-input -p tcp --dport 22 -j ACCEPT
        # A rule with no -s (source) restriction and no explicit deny is
        # effectively 0.0.0.0/0 -- ufw's own default when a rule is added
        # without "from <subnet>".
        open_rules = [
            line.strip() for line in text.splitlines()
            if line.strip().startswith("-A ufw-user-input") and "-j ACCEPT" in line and " -s " not in line
        ]
        if open_rules:
            findings.append(Finding(
                check_id=f"firewall.ufw_open_rules_{proto.lower()}", category="firewall", severity="medium",
                title=f"UFW has {proto} rules open to any source",
                description=f"{len(open_rules)} ACCEPT rule(s) in {rules_file} have no source restriction, "
                             f"meaning they apply to any source address (0.0.0.0/0 equivalent).",
                why_it_matters="A rule with no source restriction accepts traffic from anywhere on the "
                                "internet, not just from trusted networks. This may be intentional for a "
                                "public service (VPN, HTTPS) but is worth deliberately confirming for anything "
                                "else, especially management ports.",
                current_state="\n".join(open_rules[:15]) + (f"\n... and {len(open_rules) - 15} more" if len(open_rules) > 15 else ""),
                evidence=rules_file,
                remediation="For each rule, confirm the port is meant to be publicly reachable. Add a source "
                             "restriction ('ufw allow from <ip/cidr> to any port <port>') for anything that "
                             "should be limited to specific networks (e.g. an SSH management port).",
            ))
    if not findings:
        findings.append(Finding(
            check_id="firewall.ufw_open_rules_ipv4", category="firewall", severity="passed",
            title="No unrestricted-source UFW rules found",
            description="No ACCEPT rules without a source restriction were found in ufw's rule files.",
        ))
    return findings


def _check_firewalld(host_root: str) -> list[Finding]:
    firewalld_conf = _p(host_root, "/etc/firewalld")
    if not os.path.isdir(firewalld_conf):
        return []
    enabled = _service_enabled(host_root, "firewalld.service")
    if enabled is False:
        return [Finding(
            check_id="firewall.firewalld_enabled", category="firewall", severity="high",
            title="firewalld is installed but not enabled",
            description="firewalld's configuration directory is present, but firewalld.service is not "
                         "enabled to start at boot.",
            why_it_matters="An installed-but-not-running firewall provides no protection.",
            expected_state="firewalld.service enabled",
            remediation="Review firewalld's configured zones/rules for correctness, then enable and start "
                         "the service. Ensure SSH access is preserved before doing so.",
        )]
    if enabled is True:
        return [Finding(
            check_id="firewall.firewalld_enabled", category="firewall", severity="passed",
            title="firewalld is enabled", description="firewalld.service is enabled to start at boot.",
        )]
    return [Finding(
        check_id="firewall.firewalld_enabled", category="firewall", severity="info",
        title="firewalld presence detected, enabled state could not be determined",
        description="firewalld's config directory exists but this check could not determine whether "
                     "firewalld.service is enabled from the host filesystem alone.",
    )]


def _check_project_iptables_unit(host_root: str) -> list[Finding]:
    """This project's own installer (openvpn-install.sh) writes a
    dedicated openvpn-iptables.service unit that applies narrowly-scoped
    NAT/forward rules for the VPN subnet/port at boot -- not a general
    host firewall policy. Checking whether THAT unit is enabled is the
    most concrete thing this module can verify about iptables without
    live rule access; it deliberately does not claim to know about any
    OTHER iptables rules the host might have (from cloud-init, a
    separately installed iptables-persistent, etc.)."""
    unit_name = "openvpn-iptables.service"
    enabled = _service_enabled(host_root, unit_name)
    if enabled is False:
        return [Finding(
            check_id="firewall.openvpn_iptables_unit", category="firewall", severity="medium",
            title="openvpn-iptables.service is not enabled",
            description=f"{unit_name} (this project's own installer-generated unit for VPN NAT/forward "
                         f"rules) exists but is not enabled to start at boot.",
            why_it_matters="If this unit doesn't run at boot, the VPN's NAT/forwarding rules won't be "
                            "reapplied after a reboot, which can silently break client connectivity even if "
                            "the OpenVPN process itself starts fine.",
            expected_state=f"{unit_name} enabled",
            remediation=f"systemctl enable {unit_name}",
        )]
    if enabled is True:
        return [Finding(
            check_id="firewall.openvpn_iptables_unit", category="firewall", severity="passed",
            title="openvpn-iptables.service is enabled", description=f"{unit_name} is enabled to start at boot.",
        )]
    return [Finding(
        check_id="firewall.openvpn_iptables_unit", category="firewall", severity="info",
        title="No dedicated iptables/firewall service detected",
        description=f"No ufw, firewalld, or {unit_name} was found. Live iptables/nftables rule state cannot "
                     f"be read from this container regardless (see this module's own note on why) -- this "
                     f"does NOT mean no firewall is active, only that this check found no evidence either "
                     f"way from static host configuration alone.",
    )]


def _live_probe() -> dict | None:
    """Attempts to fetch live firewall state over the host-executor SSH
    channel -- returns None (never raises) if the channel isn't
    configured (HOST_SSH_TARGET/HOST_SSH_KEY_PATH unset, the common case
    for an install that hasn't set up the deploy key -- see
    docker-compose.override.yml.example) or the call fails for any
    reason at all (SSH unreachable, timeout, remote error). A firewall
    probe failing must never fail the whole audit run -- it just means
    this module falls back to the file-based checks below, same as if
    the channel didn't exist."""
    try:
        from services.system.host_executor import HostExecutorConfig, run_host_command
        from vpnadmin.config import settings
        if not settings.HOST_SSH_TARGET or not settings.HOST_SSH_KEY_PATH:
            return None
        config = HostExecutorConfig(
            ssh_key_path=settings.HOST_SSH_KEY_PATH,
            ssh_target=settings.HOST_SSH_TARGET,
            remote_script_path=settings.HOST_SSH_REMOTE_SCRIPT_PATH,
            use_sudo=settings.HOST_SSH_USE_SUDO,
            timeout_seconds=settings.HOST_SSH_TIMEOUT_SECONDS,
            ssh_port=settings.HOST_SSH_PORT,
        )
        data = run_host_command(config, "audit-firewall")
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _live_findings(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    ufw = data.get("ufw", {})
    if ufw.get("installed"):
        if ufw.get("active"):
            findings.append(Finding(
                check_id="firewall.ufw_enabled", category="firewall", severity="passed",
                title="UFW is active", description="`ufw status` reports active.",
                evidence=ufw.get("status_output"),
            ))
        else:
            findings.append(Finding(
                check_id="firewall.ufw_enabled", category="firewall", severity="high",
                title="UFW is installed but not active",
                description="`ufw status` reports inactive.",
                why_it_matters="An installed-but-inactive firewall provides no protection -- every port a "
                                "service listens on is reachable unless something else is filtering traffic.",
                current_state="inactive", expected_state="active (after confirming the rule set is correct)",
                evidence=ufw.get("status_output"),
                remediation="Review 'ufw status verbose' rules for correctness, then 'ufw enable'. Ensure SSH "
                             "is explicitly allowed BEFORE enabling, to avoid losing remote access.",
            ))

    iptables = data.get("iptables", {})
    if iptables.get("installed") is None and iptables.get("error"):
        # Ran but couldn't read rule data (most likely a permission error
        # if the host-executor's sudo elevation is ever misconfigured) --
        # never silently treated as "confirmed zero rules", see
        # audit_probe.py's probe_iptables() docstring.
        findings.append(Finding(
            check_id="firewall.iptables_readable", category="firewall", severity="info",
            title="Could not read live iptables rules",
            description=f"The live firewall probe ran but could not read iptables rule state: {iptables.get('error')}",
        ))
    if iptables.get("installed"):
        input_policy = iptables.get("policies", {}).get("INPUT")
        if input_policy == "ACCEPT":
            findings.append(Finding(
                check_id="firewall.iptables_input_policy", category="firewall", severity="medium",
                title="iptables INPUT chain default policy is ACCEPT",
                description="The INPUT chain's default policy accepts any packet that doesn't match an "
                             "explicit rule, rather than dropping/rejecting it.",
                why_it_matters="With an ACCEPT default policy, only explicit DROP/REJECT rules block traffic -- "
                                "any port not specifically closed is open by default. A DROP/REJECT default "
                                "with explicit ACCEPT rules for needed services is the more defensible posture "
                                "(deny-by-default).",
                current_state="INPUT ACCEPT", expected_state="INPUT DROP or REJECT, with explicit ACCEPT rules "
                               "for needed services (SSH, the VPN port, ...)",
                evidence="\n".join(f"-P {k} {v}" for k, v in iptables.get("policies", {}).items()),
                remediation="Add explicit ACCEPT rules for every port that needs to stay reachable, THEN set "
                             "the INPUT default policy to DROP -- in that order, to avoid locking yourself out.",
            ))
        elif input_policy:
            findings.append(Finding(
                check_id="firewall.iptables_input_policy", category="firewall", severity="passed",
                title="iptables INPUT chain has a deny-by-default policy",
                description=f"INPUT chain default policy is {input_policy}.",
            ))
        open_rules = iptables.get("unrestricted_accept_rules") or []
        if open_rules:
            findings.append(Finding(
                check_id="firewall.iptables_unrestricted_rules", category="firewall", severity="medium",
                title="iptables has ACCEPT rules open to any source, on specific ports",
                description=f"{len(open_rules)} rule(s) accept traffic on a specific port from any source "
                             f"(no -s restriction).",
                why_it_matters="A rule with no source restriction accepts traffic from anywhere on the "
                                "internet. This may be intentional for a public service (VPN, HTTPS) but is "
                                "worth deliberately confirming for anything else, especially management ports.",
                current_state="\n".join(open_rules[:15]) + (f"\n... and {len(open_rules) - 15} more" if len(open_rules) > 15 else ""),
                evidence="iptables -S",
                remediation="For each rule, confirm the port is meant to be publicly reachable. Add "
                             "'-s <ip/cidr>' for anything that should be limited to specific networks.",
            ))

    firewalld = data.get("firewalld", {})
    if firewalld.get("installed"):
        if firewalld.get("running"):
            findings.append(Finding(
                check_id="firewall.firewalld_enabled", category="firewall", severity="passed",
                title="firewalld is running", description="`firewall-cmd --state` reports running.",
            ))
        else:
            findings.append(Finding(
                check_id="firewall.firewalld_enabled", category="firewall", severity="high",
                title="firewalld is installed but not running",
                description="`firewall-cmd --state` reports not running.",
                why_it_matters="An installed-but-not-running firewall provides no protection.",
                expected_state="firewalld running",
                remediation="Review firewalld's configured zones/rules for correctness, then start the "
                             "service. Ensure SSH access is preserved before doing so.",
            ))

    unit_states = data.get("units", {})
    unit_state = unit_states.get("openvpn-iptables.service")
    if unit_state:
        if unit_state.get("enabled") == "enabled":
            findings.append(Finding(
                check_id="firewall.openvpn_iptables_unit", category="firewall", severity="passed",
                title="openvpn-iptables.service is enabled",
                description=f"systemctl is-enabled: {unit_state.get('enabled')}, is-active: {unit_state.get('active')}.",
            ))
        else:
            findings.append(Finding(
                check_id="firewall.openvpn_iptables_unit", category="firewall", severity="medium",
                title="openvpn-iptables.service is not enabled",
                description=f"systemctl is-enabled reports: {unit_state.get('enabled')}.",
                why_it_matters="If this unit doesn't run at boot, the VPN's NAT/forwarding rules won't be "
                                "reapplied after a reboot, which can silently break client connectivity even "
                                "if the OpenVPN process itself starts fine.",
                expected_state="enabled",
                remediation="systemctl enable openvpn-iptables.service",
            ))

    if not findings:
        # The probe ran and returned data, but none of ufw/iptables/
        # firewalld were detected as installed at all -- genuinely
        # different from "couldn't check" (Phase 1's Informational
        # fallback): this IS the live answer, and the live answer is
        # "no recognized firewall found".
        findings.append(Finding(
            check_id="firewall.openvpn_iptables_unit", category="firewall", severity="high",
            title="No firewall detected",
            description="Live probe found none of ufw, firewalld, or iptables rules on this host.",
            why_it_matters="With no firewall active, every port a service listens on is reachable from "
                            "anywhere.",
            remediation="Install and configure a firewall (ufw is the simplest option) allowing only the "
                         "ports actually needed (SSH, the VPN port, HTTP/HTTPS if applicable).",
        ))
    return findings


def run(host_root: str) -> list[Finding]:
    live = _live_probe()
    if live is not None:
        return _live_findings(live)
    findings: list[Finding] = []
    findings += _check_ufw(host_root)
    findings += _check_firewalld(host_root)
    findings += _check_project_iptables_unit(host_root)
    return findings
