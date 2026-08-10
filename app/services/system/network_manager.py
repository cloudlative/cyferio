"""IPv4/IPv6 interface + public-IP (NAT) detection -- Python port of
openvpn-install.sh:1075-1121 (interface IP selection) and :1090-1103
(NAT / public-IP detection).
"""
from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass

from .process_manager import run

_PRIVATE_IPV4_RE = re.compile(
    r"^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)"
)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# Same public-IP lookup service the bash script uses (:1095) -- kept
# identical rather than swapping in a "better" one, since parity with what
# openvpn-install.sh actually queries is the point.
PUBLIC_IP_URL = "http://ip1.dynupdate.no-ip.com/"


@dataclass(frozen=True)
class InterfaceIPs:
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]


def list_interface_ips() -> InterfaceIPs:
    """Mirrors `ip -4 addr` / `ip -6 addr` filtering at :1075-1121 -- every
    non-loopback IPv4 address, and every "inet6 2..."/"inet6 3..." (global/
    unique-local scope) IPv6 address."""
    ipv4 = _run_ip_addr(["ip", "-4", "addr"])
    ipv4_addrs = [
        m for m in _IPV4_RE.findall(ipv4)
        if not m.startswith("127.")
    ]
    ipv6_raw = _run_ip_addr(["ip", "-6", "addr"])
    ipv6_addrs = []
    for line in ipv6_raw.splitlines():
        line = line.strip()
        if line.startswith(("inet6 2", "inet6 3")):
            m = _IPV6_RE.search(line)
            if m:
                ipv6_addrs.append(m.group(0).rstrip(":"))
    return InterfaceIPs(ipv4_addresses=ipv4_addrs, ipv6_addresses=ipv6_addrs)


def _run_ip_addr(args: list[str]) -> str:
    result = run(args, timeout=10)
    return result.stdout if result.ok else ""


def is_private_ipv4(ip: str) -> bool:
    """Mirrors the NAT-detection regex at :1091."""
    return bool(_PRIVATE_IPV4_RE.match(ip))


def detect_public_ip(timeout: int = 10) -> str | None:
    """Mirrors :1095 -- `wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/"
    || curl -m 10 -4Ls "..."`, sanitized with the same "must be a bare IPv4"
    grep. Returns None if the lookup fails or the response isn't a clean
    IPv4 address (bash falls back to prompting the user in that case; the
    Python caller does the equivalent -- see installer.py)."""
    try:
        req = urllib.request.Request(PUBLIC_IP_URL, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    m = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", body)
    return body if m else None


def resolve_install_ip(explicit_ip: str | None = None) -> str:
    """Convenience wrapper for non-interactive callers (installer.py/the CLI
    entrypoint): picks the explicit IP if given, else the sole non-loopback
    IPv4 address if there's exactly one, else raises -- non-interactive
    equivalent of the bash prompt at :1075-1089 (which lets a human pick
    when there's more than one)."""
    if explicit_ip:
        return explicit_ip
    addrs = list_interface_ips().ipv4_addresses
    if len(addrs) == 1:
        return addrs[0]
    if not addrs:
        raise RuntimeError("No non-loopback IPv4 address found on this host.")
    raise RuntimeError(
        f"Multiple IPv4 addresses found ({addrs}); pass one explicitly (install --ip <address>)."
    )
