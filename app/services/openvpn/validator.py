"""Input validation -- Python port of the whitelist regexes/checks
openvpn-install.sh applies throughout (name sanitization :258/:1164/:1439,
MAC normalization :209-220, port/protocol/DNS/menu selection :1083,:1127,
:1142,:1156). Every other module in this package calls through here rather
than re-validating inline, so there is exactly one place that defines what a
valid client name/MAC/port/protocol looks like.
"""

from __future__ import annotations

import re

from .exceptions import ValidationError

# openvpn-install.sh:258 -- sed 's/[^0-9a-zA-Z_-]/_/g'. Bash *substitutes*
# invalid characters with '_' rather than rejecting the input outright, then
# rejects only if the result is empty. sanitize_client_name() below mirrors
# that substitution behavior exactly (not a strict validate-or-reject),
# since callers (e.g. the interactive install's client-name prompt) rely on
# it silently cleaning up minor input, not bouncing it.
_NAME_ALLOWED_CHARS = re.compile(r"[^0-9a-zA-Z_-]")
_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")
_PORT_RANGE = (1, 65535)
VALID_PROTOCOLS = ("udp", "tcp")
VALID_DNS_CHOICES = (1, 2, 3, 4, 5, 6)


def sanitize_client_name(raw: str) -> str:
    """Mirrors openvpn-install.sh:258 -- replaces every character outside
    [0-9a-zA-Z_-] with '_'. Raises ValidationError if the result is empty
    (mirrors the bash script's own "invalid name" rejection at :259-262,
    :1439-1444), which happens for e.g. an all-whitespace or all-symbol
    input."""
    sanitized = _NAME_ALLOWED_CHARS.sub("_", raw or "")
    if not sanitized:
        raise ValidationError(f"Invalid client name: {raw!r}.", raw_name=raw)
    return sanitized


def normalize_mac(raw: str) -> str:
    """Mirrors normalize_mac() at openvpn-install.sh:209-220 -- strips any
    of ':', '.', '-' separators, lowercases, and requires exactly 12 hex
    characters. Returns the normalized colon-separated form (e.g.
    "aa:bb:cc:dd:ee:ff"); raises ValidationError otherwise."""
    hex_only = re.sub(r"[:.\-]", "", raw or "").lower()
    if not _MAC_HEX.match(hex_only):
        raise ValidationError(
            f"Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff), got {raw!r}.",
            raw_mac=raw,
        )
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def validate_port(raw: str | int) -> int:
    """Mirrors openvpn-install.sh:1142 (`^[0-9]+$` and `<=65535`)."""
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValidationError(f"Invalid port: {raw!r}.", raw_port=raw) from None
    if not (_PORT_RANGE[0] <= port <= _PORT_RANGE[1]):
        raise ValidationError(f"Invalid port: {raw!r} (must be 1-65535).", raw_port=raw)
    return port


def validate_protocol(raw: str | int) -> str:
    """Mirrors openvpn-install.sh:1127-1138 -- selection "1"/"" -> udp,
    "2" -> tcp; also accepts "udp"/"tcp" directly for non-interactive
    callers (the CLI entrypoint), which the bash script's interactive-only
    prompt has no equivalent for."""
    if raw in ("", None, 1, "1"):
        return "udp"
    if raw in (2, "2"):
        return "tcp"
    if isinstance(raw, str) and raw.lower() in VALID_PROTOCOLS:
        return raw.lower()
    raise ValidationError(f"Invalid protocol selection: {raw!r}.", raw_protocol=raw)


def validate_dns_choice(raw: str | int) -> int:
    """Mirrors openvpn-install.sh:1156 (`^[1-6]$`); empty/None defaults to 1
    ("current system resolvers"), matching the bash prompt's default."""
    if raw in ("", None):
        return 1
    try:
        choice = int(raw)
    except (TypeError, ValueError):
        raise ValidationError(f"Invalid DNS choice: {raw!r}.", raw_dns=raw) from None
    if choice not in VALID_DNS_CHOICES:
        raise ValidationError(f"Invalid DNS choice: {raw!r} (must be 1-6).", raw_dns=raw)
    return choice


def require_mac(raw: str | None) -> str:
    """Mirrors the "A MAC address is required." checks that precede
    normalize_mac() calls throughout the bash script (e.g. :268-271,
    :528-531, :562-565)."""
    if not raw:
        raise ValidationError("A MAC address is required.")
    return normalize_mac(raw)


def require_name(raw: str | None) -> str:
    """Mirrors the "Client name required." checks that precede most do_*
    functions (e.g. :307-310, :341-344, :368-371)."""
    if not raw:
        raise ValidationError("Client name required.")
    return raw
