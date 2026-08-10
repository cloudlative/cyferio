"""
GeoIP country lookup for the web app's own login flow (country-based login
restriction, see routes/auth.py). Deliberately parallel to, but separate
from, host-scripts/policy_lib.py's geoip_lookup_country -- that one runs
outside Docker as part of the OpenVPN client-connect hook (VPN client
country restriction); this one runs inside the app container against the
same underlying GeoLite2-Country database (see config.py's GEOIP_DB_PATH),
for a different purpose (blocking a web login, not a VPN connection).

Fails soft everywhere: a missing/corrupt database or an IP the database
doesn't recognize returns None, never raises. Callers (routes/auth.py)
decide the fail-safe policy themselves -- see that module's comment on why
a lookup failure fails CLOSED (blocks login) when a user actually has
country restriction enabled, same fail-safe stance host-scripts/
policy_lib.py's caller already takes for VPN client connections.
"""
import threading

from .config import settings

_reader = None
_reader_lock = threading.Lock()
_reader_load_attempted = False


def _get_reader():
    """Lazily opens (once) and caches the mmdb Reader -- geoip2's Reader is
    backed by a read-only mmap, safe to share across the threadpool threads
    FastAPI runs sync route handlers in. Returns None if the database file
    is missing or the geoip2 package somehow isn't installed (defensive
    only -- it's in requirements.txt -- e.g. a partial/broken install)."""
    global _reader, _reader_load_attempted
    with _reader_lock:
        if _reader is not None or _reader_load_attempted:
            return _reader
        _reader_load_attempted = True
        if not settings.GEOIP_DB_PATH:
            return None
        try:
            import geoip2.database
            _reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
        except Exception:
            _reader = None
        return _reader


def lookup_country(ip: str | None) -> str | None:
    """Returns the ISO 3166-1 alpha-2 country code for `ip`, or None if it
    can't be determined (no database, IP not found -- private/reserved
    ranges, etc. -- or any other lookup failure)."""
    if not ip:
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        import geoip2.errors
        return reader.country(ip).country.iso_code
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception:
        return None
