"""Firewall checks -- BEST-EFFORT ONLY, from readable host config files,
not live kernel netfilter state. See this package's __init__.py module
docstring for the full "why file reads, not subprocess" explanation.

Concretely, this means: ufw's enabled/disabled bit and its rule FILES
(/etc/ufw/*.rules) can be read directly, so ufw gets real (if static)
findings. firewalld's config directory can similarly be read. But this
project's own installer (openvpn-install.sh) uses bare iptables via a
generated systemd unit (openvpn-iptables.service) rather than ufw or
firewalld -- iptables rules loaded that way live ONLY in the kernel's
netfilter tables, with no rules file on disk to read (unless the host
separately runs iptables-persistent, which does write one). For that
common case, this module can only confirm the SERVICE that would have
loaded the rules is enabled -- it explicitly says so, rather than
reporting "no firewall" when one may well be active. Do not treat a
"could not verify" Informational finding here as "no firewall is
running" -- it means what it says: this check cannot see live rule
state from inside the container."""
import os
import re

from . import Finding


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


def run(host_root: str) -> list[Finding]:
    findings: list[Finding] = []
    findings += _check_ufw(host_root)
    findings += _check_firewalld(host_root)
    findings += _check_project_iptables_unit(host_root)
    return findings
