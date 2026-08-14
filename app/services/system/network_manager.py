"""IPv4/IPv6 interface + public-IP (NAT) detection -- Python port of
openvpn-install.sh:1075-1121 (interface IP selection) and :1090-1103
(NAT / public-IP detection).
"""

from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass

from .process_manager import run

_PRIVATE_IPV4_RE = re.compile(r"^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# Same public-IP lookup service the bash script uses (:1095) -- kept
# identical rather than swapping in a "better" one, since parity with what
# openvpn-install.sh actually queries is the point.
PUBLIC_IP_URL = "http://ip1.dynupdate.no-ip.com/"


@dataclass(frozen=True)
class InterfaceAddress:
    address: str
    interface: str


@dataclass(frozen=True)
class InterfaceIPs:
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]
    ipv4_details: list[InterfaceAddress] = None  # type: ignore[assignment]


# Interface name prefixes created by Docker/container-networking, never a
# real "this host's own address" candidate -- bash's original interactive
# prompt (:1075-1089) has no equivalent filter (a human just recognizes and
# skips these when picking from the numbered list), but a non-interactive
# caller needs one: running installer.py on any Docker host (this project's
# whole premise -- the portal itself is deployed via docker-compose) would
# otherwise almost always hit the "multiple IPv4 addresses" ambiguity error
# purely from Docker's own bridge networks, never from a genuine ambiguity
# the admin needs to resolve.
_VIRTUAL_IFACE_PREFIXES = ("docker", "br-", "veth", "cni", "flannel", "cali", "tun", "tap")


def list_interface_ips() -> InterfaceIPs:
    """Mirrors `ip -4 addr` / `ip -6 addr` filtering at :1075-1121 -- every
    non-loopback IPv4 address, and every "inet6 2..."/"inet6 3..." (global/
    unique-local scope) IPv6 address. `ipv4_details` additionally carries
    each address's interface name, for resolve_install_ip()'s virtual-
    interface filtering below -- `ipv4_addresses` itself stays a plain list
    for exact parity with what the bash script's own extraction produces."""
    ipv4 = _run_ip_addr(["ip", "-4", "addr"])
    ipv4_addrs = []
    ipv4_details = []
    for line in ipv4.splitlines():
        line = line.strip()
        if not line.startswith("inet "):
            continue
        # Mirrors bash's `cut -d '/' -f 1` (:1076) -- take only the text
        # before the first '/', which is "inet <addr>", so the interface's
        # own address is matched and NOT the "brd <broadcast-addr>" that
        # can appear later on the same line (e.g. Docker's bridge:
        # "inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0") --
        # regex-matching the whole line for any IPv4-looking token would
        # wrongly pick up that broadcast address too.
        before_slash = line.split("/", 1)[0]
        m = _IPV4_RE.search(before_slash)
        if not m or m.group(0).startswith("127."):
            continue
        addr = m.group(0)
        ipv4_addrs.append(addr)
        # Interface name is the last whitespace-separated token on the line
        # (e.g. "...scope global docker0" -> "docker0").
        iface = line.rsplit(None, 1)[-1] if " " in line else ""
        ipv4_details.append(InterfaceAddress(address=addr, interface=iface))
    ipv6_raw = _run_ip_addr(["ip", "-6", "addr"])
    ipv6_addrs = []
    for line in ipv6_raw.splitlines():
        line = line.strip()
        if line.startswith(("inet6 2", "inet6 3")):
            m = _IPV6_RE.search(line)
            if m:
                ipv6_addrs.append(m.group(0).rstrip(":"))
    return InterfaceIPs(ipv4_addresses=ipv4_addrs, ipv6_addresses=ipv6_addrs, ipv4_details=ipv4_details)


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
    entrypoint): picks the explicit IP if given, else the sole non-loopback,
    non-virtual-interface IPv4 address if there's exactly one, else raises --
    non-interactive equivalent of the bash prompt at :1075-1089 (which lets a
    human pick when there's more than one). Docker/container-networking
    interfaces (see _VIRTUAL_IFACE_PREFIXES) are excluded from the ambiguity
    check first -- installer.py routinely runs on a Docker host (this
    project's own portal is deployed via docker-compose), so without this
    filter almost every real install would spuriously hit "multiple
    addresses found" purely from docker0/the compose network's own bridge,
    never from a real ambiguity the caller needs to resolve."""
    if explicit_ip:
        return explicit_ip
    details = list_interface_ips().ipv4_details or []
    real = [d for d in details if not d.interface.startswith(_VIRTUAL_IFACE_PREFIXES)]
    addrs = [d.address for d in real]
    if len(addrs) == 1:
        return addrs[0]
    if not addrs:
        raise RuntimeError("No non-loopback, non-virtual IPv4 address found on this host.")
    raise RuntimeError(f"Multiple IPv4 addresses found ({addrs}); pass one explicitly (install --ip <address>).")
