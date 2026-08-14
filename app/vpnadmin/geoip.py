"""
GeoIP lookups for the web app's own login flow (country/city/ASN-based
login restriction, see routes/auth.py). Deliberately parallel to, but
separate from, host-scripts/policy_lib.py's geoip_lookup_country -- that
one runs outside Docker as part of the OpenVPN client-connect hook (VPN
client country restriction); this one runs inside the app container
against the same underlying GeoLite2 databases (see config.py's
GEOIP_DB_PATH/GEOIP_CITY_DB_PATH/GEOIP_ASN_DB_PATH), for a different
purpose (blocking a web login, not a VPN connection).

Three independent GeoLite2 editions, three independent readers -- Country,
City, and ASN (network operator) are separate MaxMind database files, each
enabled/usable on its own regardless of whether the other two are present.

Fails soft everywhere: a missing/corrupt database or an IP the database
doesn't recognize returns None, never raises. Callers (routes/auth.py)
decide the fail-safe policy themselves -- see that module's comment on why
a lookup failure fails CLOSED (blocks login) when a user actually has a
restriction of that kind enabled, same fail-safe stance host-scripts/
policy_lib.py's caller already takes for VPN client connections.
"""

import threading

from .config import settings

_readers: dict[str, object] = {}
_reader_lock = threading.Lock()
_reader_load_attempted: set[str] = set()


def _get_reader(kind: str, path: str):
    """Lazily opens (once per `kind`) and caches an mmdb Reader -- geoip2's
    Reader is backed by a read-only mmap, safe to share across the
    threadpool threads FastAPI runs sync route handlers in. Returns None if
    the database file is missing or the geoip2 package somehow isn't
    installed (defensive only -- it's in requirements.txt -- e.g. a
    partial/broken install)."""
    with _reader_lock:
        if kind in _readers:
            return _readers[kind]
        if kind in _reader_load_attempted:
            return None
        _reader_load_attempted.add(kind)
        if not path:
            return None
        try:
            import geoip2.database

            reader = geoip2.database.Reader(path)
        except Exception:
            return None
        _readers[kind] = reader
        return reader


def lookup_country(ip: str | None) -> str | None:
    """Returns the ISO 3166-1 alpha-2 country code for `ip`, or None if it
    can't be determined (no database, IP not found -- private/reserved
    ranges, etc. -- or any other lookup failure)."""
    if not ip:
        return None
    reader = _get_reader("country", settings.GEOIP_DB_PATH)
    if reader is None:
        return None
    try:
        import geoip2.errors

        return reader.country(ip).country.iso_code
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception:
        return None


def lookup_city(ip: str | None) -> str | None:
    """Returns the city name for `ip` (e.g. "Karachi"), or None if it can't
    be determined. GeoLite2's city-level accuracy is coarser than country
    (MaxMind's own docs put typical accuracy at city/region level, not
    exact) -- treat this as a useful signal, not a precise location."""
    if not ip:
        return None
    reader = _get_reader("city", settings.GEOIP_CITY_DB_PATH)
    if reader is None:
        return None
    try:
        import geoip2.errors

        name = reader.city(ip).city.name
        return name.strip() if name else None
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception:
        return None


def lookup_asn(ip: str | None) -> int | None:
    """Returns the autonomous system number for `ip` (e.g. 15169 for
    Google), or None if it can't be determined. This identifies the
    network/ISP a connection came from, not a physical location -- useful
    for e.g. always allowing a known corporate network's ASN regardless of
    which country its NAT gateway happens to geolocate to."""
    if not ip:
        return None
    reader = _get_reader("asn", settings.GEOIP_ASN_DB_PATH)
    if reader is None:
        return None
    try:
        import geoip2.errors

        return reader.asn(ip).autonomous_system_number
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception:
        return None
