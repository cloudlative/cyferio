"""
Shared validators for the four "list of allowed X" restriction fields --
countries, cities, ASNs, IP addresses -- used identically by two different
owners of this data:

  routes/users.py    -- User.allowed_login_countries/cities/asns/ips
                         (portal LOGIN restrictions)
  policy_store.py     -- client_policy.json's allowed_countries/cities/
                         asns/ips (VPN CONNECTION restrictions, enforced by
                         host-scripts/openvpn-mac-addr-check.py)

Extracted here (rather than staying private to routes/users.py, where they
originally lived) once policy_store.py needed the exact same rules for the
Manage Restrictions dialog on the Clients page -- one set of "what's a
valid country code / IP / city / ASN" rules, not two copies that could
quietly drift apart. See policy_store.py's module docstring for the fuller
User<->VPN-Profile synchronization picture these feed into.
"""

import ipaddress

from . import geo_lists


def valid_country_list(v: list[str]) -> list[str]:
    """Lightweight "2-letter alpha shape" check, not a fixed enum against a
    real ISO list -- less to maintain, and this app's own country dropdown
    (app.js's ISO_3166_COUNTRIES) is already the real source of truth for
    what a human picks from in the UI. Normalizes to uppercase and dedupes,
    preserving first-seen order."""
    seen = []
    for code in v:
        code = (code or "").strip().upper()
        if not code:
            continue
        if len(code) != 2 or not code.isalpha():
            raise ValueError(f"Invalid country code: '{code}' -- expected an ISO 3166-1 alpha-2 code (e.g. PK).")
        if code not in seen:
            seen.append(code)
    return seen


def valid_ip_list(v: list[str]) -> list[str]:
    """Each entry is either a single IP address or a CIDR range, dual-stack
    (IPv4/IPv6). Normalizes each entry to str(ipaddress...) form (consistent
    formatting regardless of how the admin typed it, e.g. leading zeros)
    and dedupes, preserving first-seen order."""
    seen = []
    for entry in v:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            normalized = str(ipaddress.ip_network(entry, strict=False)) if "/" in entry else str(ipaddress.ip_address(entry))
        except ValueError:
            raise ValueError(f"'{entry}' isn't a valid IP address or CIDR range (e.g. 203.0.113.5 or 10.0.0.0/24).")
        if normalized not in seen:
            seen.append(normalized)
    return seen


def valid_city_list(v: list[str]) -> list[str]:
    """Each entry must be a real city name from geo_lists.py's City
    pick-list -- picker-only, no free text (see users.html/clients.html's
    cascading country -> city selector): a hand-typed name GeoIP could
    never actually return at connect/login time would create a restriction
    that can never be satisfied, i.e. a silent, permanent lockout for that
    restriction type. Canonicalizes to the exact casing MaxMind uses and
    dedupes case-insensitively. If the city index hasn't finished its first
    build yet (fresh install / just-replaced mmdb, see geo_lists.py for the
    rebuild window), city_exists() returns None and this falls back to a
    shape-only check instead of blocking admins entirely during that
    window."""
    seen_lower = set()
    result = []
    for name in v:
        name = (name or "").strip()
        if not name:
            continue
        exists = geo_lists.city_exists(name)
        if exists is False:
            raise ValueError(f"'{name}' isn't a known city in the GeoIP database -- pick one from the list.")
        canonical = geo_lists.canonical_city(name) if exists else name
        if len(canonical) > 100:
            raise ValueError(f"City name too long (max 100 characters): '{canonical[:40]}...'")
        key = canonical.lower()
        if key not in seen_lower:
            seen_lower.add(key)
            result.append(canonical)
    return result


def valid_asn_list(v: list[str]) -> list[str]:
    """Each entry must be a real ASN from geo_lists.py's ASN pick-list --
    same picker-only rationale as valid_city_list. Normalizes shape
    ("15169" or "as15169" -> "AS15169") first, then checks membership;
    same not-yet-built fallback as valid_city_list via asn_exists()
    returning None."""
    seen = []
    for entry in v:
        entry = (entry or "").strip().upper()
        if not entry:
            continue
        digits = entry[2:] if entry.startswith("AS") else entry
        if not digits.isdigit():
            raise ValueError(f"'{entry}' isn't a valid AS number -- expected e.g. AS15169 or 15169.")
        normalized = f"AS{int(digits)}"
        exists = geo_lists.asn_exists(normalized)
        if exists is False:
            raise ValueError(f"'{normalized}' isn't a known network in the GeoIP database -- pick one from the list.")
        if normalized not in seen:
            seen.append(normalized)
    return seen
