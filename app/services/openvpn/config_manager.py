"""server.conf / client-common.txt / per-client .ovpn generation -- Python
port of openvpn-install.sh's new_client() (:155-173) and the server.conf/
client-common.txt template blocks (:1230-1305, :1389-1402).

Templates are rendered from a small dataclass (InstallOptions) instead of
loose positional args, but every emitted line matches the bash script's
output for the equivalent choices -- this is what the Phase 1 parity check
(§5b of the plan) diffs against the bash-reference install's real output.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .exceptions import CertificateError
from .paths import OpenVPNPaths
from .validator import validate_dns_choice, validate_port, validate_protocol

DNS_PUSH_OPTIONS: dict[int, list[str]] = {
    2: ["8.8.8.8", "8.8.4.4"],  # Google
    3: ["1.1.1.1", "1.0.0.1"],  # 1.1.1.1
    4: ["208.67.222.222", "208.67.220.220"],  # OpenDNS
    5: ["9.9.9.9", "149.112.112.112"],  # Quad9
    6: ["94.140.14.14", "94.140.15.15"],  # AdGuard
}


@dataclass(frozen=True)
class InstallOptions:
    """Everything the bash installer's interactive prompts collect
    (:1075-1165), minus the client name (that's client_manager's job, not
    config_manager's)."""

    ip: str
    port: int | str = 1194
    protocol: str | int = "udp"
    dns: int | str = 1
    ip6: str | None = None
    public_ip: str | None = None  # set when behind NAT, replaces `ip` in client-common.txt
    group_name: str = "nogroup"

    def __post_init__(self) -> None:
        object.__setattr__(self, "port", validate_port(self.port))
        object.__setattr__(self, "protocol", validate_protocol(self.protocol))
        object.__setattr__(self, "dns", validate_dns_choice(self.dns))


def render_server_conf(paths: OpenVPNPaths, opts: InstallOptions) -> str:
    """Mirrors openvpn-install.sh:1230-1308. Returns the full file content;
    caller writes it (see installer.py)."""
    lines = [
        f"local {opts.ip}",
        f"port {opts.port}",
        f"proto {opts.protocol}",
        "dev tun",
        "ca ca.crt",
        "cert server.crt",
        "key server.key",
        "dh dh.pem",
        "auth SHA512",
        "tls-crypt tc.key",
        "topology subnet",
        "server 10.8.0.0 255.255.255.0",
    ]
    if not opts.ip6:
        lines.append('push "redirect-gateway def1 bypass-dhcp"')
    else:
        lines.append("server-ipv6 fddd:1194:1194:1194::/64")
        lines.append('push "redirect-gateway def1 ipv6 bypass-dhcp"')
    lines.append("ifconfig-pool-persist ipp.txt")

    if opts.dns == 1:
        for resolver in _system_resolvers():
            lines.append(f'push "dhcp-option DNS {resolver}"')
    else:
        for resolver in DNS_PUSH_OPTIONS[opts.dns]:
            lines.append(f'push "dhcp-option DNS {resolver}"')
    lines.append('push "block-outside-dns"')

    lines += [
        "keepalive 10 120",
        "cipher AES-256-CBC",
        "user nobody",
        f"group {opts.group_name}",
        "persist-key",
        "persist-tun",
        "verb 3",
        "crl-verify crl.pem",
        f"status {paths.status_log} 5",
    ]
    if opts.protocol == "udp":
        lines.append("explicit-exit-notify")
    return "\n".join(lines) + "\n"


def render_client_common(opts: InstallOptions) -> str:
    """Mirrors openvpn-install.sh:1389-1402. Uses `opts.public_ip` in place
    of `opts.ip` when set, matching the bash script's `[[ -n "$public_ip" ]]
    && ip="$public_ip"` at :1387."""
    remote_ip = opts.public_ip or opts.ip
    lines = [
        "client",
        "dev tun",
        f"proto {opts.protocol}",
        f"remote {remote_ip} {opts.port}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        "auth SHA512",
        "cipher AES-256-CBC",
        "ignore-unknown-option block-outside-dns",
        "push-peer-info",
        "verb 3",
    ]
    return "\n".join(lines) + "\n"


def _system_resolvers() -> list[str]:
    """Mirrors :1252-1264 -- picks /etc/resolv.conf unless it only lists
    the systemd-resolved stub (127.0.0.53), in which case it reads the real
    upstream resolvers from /run/systemd/resolve/resolv.conf instead."""
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

    def _nameservers(path: str) -> list[str]:
        if not os.path.exists(path):
            return []
        out = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith(("#", ";")) or not line.startswith("nameserver"):
                    continue
                _, _, addr = line.partition(" ")
                addr = addr.strip()
                if addr != "127.0.0.53" and ip_re.match(addr):
                    out.append(addr)
        return out

    primary = _nameservers("/etc/resolv.conf")
    if primary:
        return primary
    return _nameservers("/run/systemd/resolve/resolv.conf")


def generate_ovpn(paths: OpenVPNPaths, name: str) -> str:
    """Mirrors new_client() at openvpn-install.sh:155-173 -- assembles a
    client-common.txt-based .ovpn with inline <ca>/<cert>/<key>/<tls-crypt>
    blocks. Returns the content; caller (client_manager.add_client) writes
    it to paths.ovpn_output(name)."""
    try:
        with open(paths.client_common_file, encoding="utf-8") as f:
            common = f.read()
        with open(paths.ca_crt, encoding="utf-8") as f:
            ca = f.read()
        cert = _strip_to_begin_certificate(paths.issued_crt(name))
        with open(paths.private_key(name), encoding="utf-8") as f:
            key = f.read()
        tls_crypt = _strip_to_begin_static_key(paths.tc_key)
    except OSError as e:
        raise CertificateError(f"Failed to assemble .ovpn for {name!r}: {e}", client=name) from e

    parts = [
        common.rstrip("\n"),
        "<ca>", ca.rstrip("\n"), "</ca>",
        "<cert>", cert.rstrip("\n"), "</cert>",
        "<key>", key.rstrip("\n"), "</key>",
        "<tls-crypt>", tls_crypt.rstrip("\n"), "</tls-crypt>",
    ]
    return "\n".join(parts) + "\n"


def _strip_to_begin_certificate(path: str) -> str:
    """Mirrors `sed -ne '/BEGIN CERTIFICATE/,$ p'` (:164) -- drops
    easyrsa's human-readable cert-text preamble, keeping only the PEM
    block."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    idx = text.find("-----BEGIN CERTIFICATE-----")
    if idx == -1:
        raise CertificateError(f"No BEGIN CERTIFICATE marker found in {path!r}")
    return text[idx:]


def _strip_to_begin_static_key(path: str) -> str:
    """Mirrors `sed -ne '/BEGIN OpenVPN Static key/,$ p'` (:170)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    idx = text.find("-----BEGIN OpenVPN Static key")
    if idx == -1:
        raise CertificateError(f"No BEGIN OpenVPN Static key marker found in {path!r}")
    return text[idx:]
