"""sysctl (IP forwarding) + iptables NAT/INPUT/FORWARD rules -- Python port
of openvpn-install.sh:1309-1318 (sysctl) and :1337-1371 (iptables path
only; the firewalld path at :1319-1336 is intentionally not ported this
phase -- see the Phase 1 plan's module scope table, this box has no
firewalld). Uninstall counterparts mirror :1568-1571 and :1310→removal.
"""
from __future__ import annotations

import os
import shutil

from ..system.process_manager import run
from . import service_manager
from .exceptions import FirewallConfigError

SYSCTL_DROPIN = "/etc/sysctl.d/99-openvpn-forward.conf"
IPTABLES_UNIT = "openvpn-iptables.service"
IPTABLES_UNIT_PATH = f"/etc/systemd/system/{IPTABLES_UNIT}"
VPN_SUBNET = "10.8.0.0/24"
VPN_SUBNET6 = "fddd:1194:1194:1194::/64"


def enable_ip_forward(*, ipv6: bool = False) -> None:
    """Mirrors :1309-1318."""
    lines = ["net.ipv4.ip_forward=1"]
    if ipv6:
        lines.append("net.ipv6.conf.all.forwarding=1")
    with open(SYSCTL_DROPIN, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    _write_proc_sys("/proc/sys/net/ipv4/ip_forward", "1")
    if ipv6:
        _write_proc_sys("/proc/sys/net/ipv6/conf/all/forwarding", "1")


def disable_ip_forward() -> None:
    """Mirrors the uninstall step at :1577 (`rm -f
    /etc/sysctl.d/99-openvpn-forward.conf`) -- deliberately does not flip
    the live /proc/sys value back to 0, matching the bash script (which
    also never does that on uninstall)."""
    if os.path.exists(SYSCTL_DROPIN):
        os.remove(SYSCTL_DROPIN)


def _write_proc_sys(path: str, value: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(value)
    except OSError as e:
        # Non-fatal: a test/dev environment (or a container without
        # NET_ADMIN on this specific sysctl) may not have this writable --
        # the sysctl.d drop-in above still takes effect on next boot/service
        # restart, same fallback the bash script implicitly relies on.
        raise FirewallConfigError(f"Failed to apply {path}={value} immediately: {e}") from e


def resolve_iptables_paths() -> tuple[str, str]:
    """Mirrors :1339-1346 -- locates iptables/ip6tables, falling back to the
    *-legacy variants under OpenVZ with an nf_tables-backed iptables
    binary. This box (34.182.51.24) is a plain GCP VM, not OpenVZ, so the
    legacy-fallback branch is ported for parity but not expected to trigger
    there."""
    iptables_path = shutil.which("iptables")
    ip6tables_path = shutil.which("ip6tables")
    if not iptables_path:
        raise FirewallConfigError("iptables binary not found on PATH.")
    if _is_openvz() and _is_nft_backed(iptables_path) and shutil.which("iptables-legacy"):
        iptables_path = shutil.which("iptables-legacy") or iptables_path
        ip6tables_path = shutil.which("ip6tables-legacy") or ip6tables_path
    return iptables_path, ip6tables_path or ""


def _is_openvz() -> bool:
    result = run(["systemd-detect-virt"], timeout=5)
    return result.ok and result.stdout.strip() == "openvz"


def _is_nft_backed(iptables_path: str) -> bool:
    real = os.path.realpath(iptables_path)
    return "nft" in real


def render_iptables_unit(
    *, iptables_path: str, ip6tables_path: str, ip: str, port: int, protocol: str, ip6: str | None = None,
) -> str:
    """Mirrors the systemd unit generated at :1347-1369."""
    lines = [
        "[Unit]",
        "Before=network.target",
        "[Service]",
        "Type=oneshot",
        f"ExecStart={iptables_path} -t nat -A POSTROUTING -s {VPN_SUBNET} ! -d {VPN_SUBNET} -j SNAT --to {ip}",
        f"ExecStart={iptables_path} -I INPUT -p {protocol} --dport {port} -j ACCEPT",
        f"ExecStart={iptables_path} -I FORWARD -s {VPN_SUBNET} -j ACCEPT",
        f"ExecStart={iptables_path} -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
        f"ExecStop={iptables_path} -t nat -D POSTROUTING -s {VPN_SUBNET} ! -d {VPN_SUBNET} -j SNAT --to {ip}",
        f"ExecStop={iptables_path} -D INPUT -p {protocol} --dport {port} -j ACCEPT",
        f"ExecStop={iptables_path} -D FORWARD -s {VPN_SUBNET} -j ACCEPT",
        f"ExecStop={iptables_path} -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
    ]
    if ip6:
        lines += [
            f"ExecStart={ip6tables_path} -t nat -A POSTROUTING -s {VPN_SUBNET6} ! -d {VPN_SUBNET6} -j SNAT --to {ip6}",
            f"ExecStart={ip6tables_path} -I FORWARD -s {VPN_SUBNET6} -j ACCEPT",
            f"ExecStart={ip6tables_path} -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
            f"ExecStop={ip6tables_path} -t nat -D POSTROUTING -s {VPN_SUBNET6} ! -d {VPN_SUBNET6} -j SNAT --to {ip6}",
            f"ExecStop={ip6tables_path} -D FORWARD -s {VPN_SUBNET6} -j ACCEPT",
            f"ExecStop={ip6tables_path} -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ]
    lines += ["RemainAfterExit=yes", "[Install]", "WantedBy=multi-user.target"]
    return "\n".join(lines) + "\n"


def install_iptables_firewall(*, ip: str, port: int, protocol: str, ip6: str | None = None) -> None:
    """Mirrors :1337-1371 end-to-end: resolve binaries, render+write the
    unit, enable --now it."""
    iptables_path, ip6tables_path = resolve_iptables_paths()
    content = render_iptables_unit(
        iptables_path=iptables_path, ip6tables_path=ip6tables_path,
        ip=ip, port=port, protocol=protocol, ip6=ip6,
    )
    with open(IPTABLES_UNIT_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    service_manager.daemon_reload()
    service_manager.enable_and_start(IPTABLES_UNIT)


def remove_iptables_firewall() -> None:
    """Mirrors :1568-1571 -- disable --now, then delete the unit file. Its
    ExecStop lines (which actually remove the live iptables rules) run as
    part of `disable --now` since the unit's RemainAfterExit=yes keeps it
    "active" until then."""
    service_manager.disable_and_stop(IPTABLES_UNIT)
    if os.path.exists(IPTABLES_UNIT_PATH):
        os.remove(IPTABLES_UNIT_PATH)
    service_manager.daemon_reload()
