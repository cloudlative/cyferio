"""
Offline-built pick-lists for the login-restriction City and ASN fields
(routes/users.py, users.html, routes/geo.py) -- sourced directly from the
same GeoLite2-City/GeoLite2-ASN databases geoip.py queries at login time
(see config.py's GEOIP_CITY_DB_PATH/GEOIP_ASN_DB_PATH), so every value an
admin can pick is a value GeoIP could actually return for a real login --
no free-text entry, which could otherwise "restrict" an account to a
typo'd value that GeoIP would never return, i.e. a silent, permanent
lockout for that restriction type.

Building these lists means walking the *entire* mmdb -- MaxMind's binary
format has no native "list distinct cities" query. This walks the full
IPv4 address space via reader.get_with_prefix_len(), which -- critically
-- lets each step jump straight to the START of the NEXT network instead
of visiting every individual address (there are on the order of 3-4M
distinct networks in the City edition, not 4 billion individual
addresses). Takes roughly 90-100s for the City database and ~15s for ASN
on modest hardware (measured against the real production databases while
building this).

IPv4 only, deliberately: MaxMind's IPv6 tree covers an astronomically
larger address space, and this app's real traffic (admin logins to a
VPN management UI) is realistically IPv4 today. If that ever needs
revisiting, the same jump-by-network technique still applies to IPv6 --
see _walk_ipv4 below.

Because a full rebuild is too slow to run inside a request, results are
cached to disk (JSON, next to the source mmdb, which the app already
bind-mounts rw) and only rebuilt in a background thread when the source
file's mtime has moved past what's cached -- i.e. only after a human
replaces the mmdb with a newer MaxMind release. Until the first build
finishes (fresh install) or a rebuild finishes (mmdb just got replaced),
callers get whatever's cached (possibly None) rather than blocking a
request for ~100s.

ASN city index equivalent -- "which country does this ASN belong to" --
isn't a real MaxMind field (an ASN is a network operator, not inherently
tied to one country), so it's approximated: every IPv4 network in the ASN
database is cross-referenced against the Country database, and each ASN
is tagged with whichever country its announced ranges hit most often.
Works well for regional ISPs, is necessarily fuzzy for global operators
(Google, Cloudflare, ...) -- those remain findable via the "any country"
list in get_asns(None), just not confidently placed under one country.
"""

import ipaddress
import json
import os
import threading
import time

from .config import settings

_CITY_CACHE_SUFFIX = ".geo_city_index.json"
_ASN_CACHE_SUFFIX = ".geo_asn_index.json"

_lock = threading.Lock()
_city_index: dict | None = None
_asn_index: dict | None = None
_building: set[str] = set()  # subset of {"city", "asn"} currently rebuilding


def _cache_path(source_path: str, suffix: str) -> str:
    return os.path.join(os.path.dirname(source_path) or ".", suffix)


def _source_mtime(path: str) -> float | None:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def _walk_ipv4(reader):
    """Yields (ip, record, prefix_len) for every distinct IPv4 network in
    an open maxminddb.Reader, jumping straight to the next network's start
    address rather than visiting every individual IP in between."""
    ip_int = 0
    max_int = 2**32 - 1
    while ip_int <= max_int:
        ip = ipaddress.IPv4Address(ip_int)
        record, prefix_len = reader.get_with_prefix_len(ip)
        yield ip, record, prefix_len
        ip_int += 2 ** (32 - prefix_len)


def _load_cache(cache_path: str) -> dict | None:
    try:
        with open(cache_path) as f:
            return json.load(f)
    except Exception:
        return None


def _save_cache(cache_path: str, data: dict) -> None:
    tmp_path = cache_path + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, cache_path)
    except OSError:
        pass  # best-effort -- an unwritable cache dir just means every
        # process rebuilds from scratch each restart, not a hard failure


def _build_city_index() -> dict | None:
    import maxminddb

    path = settings.GEOIP_CITY_DB_PATH
    mtime = _source_mtime(path)
    if mtime is None:
        return None
    try:
        reader = maxminddb.open_database(path)
    except Exception:
        return None
    by_country: dict[str, set[str]] = {}
    all_cities: set[str] = set()
    try:
        for _ip, record, _prefix_len in _walk_ipv4(reader):
            if not record:
                continue
            country = (record.get("country") or {}).get("iso_code")
            city = ((record.get("city") or {}).get("names") or {}).get("en")
            if not country or not city:
                continue
            by_country.setdefault(country, set()).add(city)
            all_cities.add(city)
    finally:
        reader.close()
    sorted_cities = sorted(all_cities)
    return {
        "source_mtime": mtime,
        "built_at": time.time(),
        "by_country": {c: sorted(names) for c, names in by_country.items()},
        "all_cities": sorted_cities,
        # lowercase -> canonical casing, for O(1) case-insensitive lookup
        # in canonical_city() below rather than scanning all_cities.
        "lower_to_canonical": {c.lower(): c for c in sorted_cities},
    }


def _build_asn_index() -> dict | None:
    import maxminddb

    asn_path = settings.GEOIP_ASN_DB_PATH
    country_path = settings.GEOIP_DB_PATH
    mtime = _source_mtime(asn_path)
    if mtime is None:
        return None
    try:
        asn_reader = maxminddb.open_database(asn_path)
    except Exception:
        return None
    country_reader = None
    if country_path and _source_mtime(country_path) is not None:
        try:
            country_reader = maxminddb.open_database(country_path)
        except Exception:
            country_reader = None

    org_by_asn: dict[int, str] = {}
    # {asn_number: {country_iso_or_None: network_count}}
    country_tally: dict[int, dict[str | None, int]] = {}
    try:
        for ip, record, _prefix_len in _walk_ipv4(asn_reader):
            if not record:
                continue
            asn = record.get("autonomous_system_number")
            if asn is None:
                continue
            org_by_asn.setdefault(asn, record.get("autonomous_system_organization") or f"AS{asn}")
            country = None
            if country_reader is not None:
                try:
                    crec = country_reader.get(ip)
                    country = (crec or {}).get("country", {}).get("iso_code")
                except Exception:
                    country = None
            tally = country_tally.setdefault(asn, {})
            tally[country] = tally.get(country, 0) + 1
    finally:
        asn_reader.close()
        if country_reader:
            country_reader.close()

    by_country: dict[str, list[dict]] = {}
    all_asns: list[dict] = []
    for asn, org in org_by_asn.items():
        entry = {"asn": f"AS{asn}", "org": org}
        all_asns.append(entry)
        tally = country_tally.get(asn, {})
        real_counts = {c: n for c, n in tally.items() if c}
        if real_counts:
            top_country = max(real_counts.items(), key=lambda kv: kv[1])[0]
            by_country.setdefault(top_country, []).append(entry)
    for entries in by_country.values():
        entries.sort(key=lambda e: e["org"].lower())
    all_asns.sort(key=lambda e: e["org"].lower())
    return {
        "source_mtime": mtime,
        "built_at": time.time(),
        "by_country": by_country,
        "all": all_asns,
        # for O(1) membership checks in asn_exists() below.
        "all_asn_numbers": sorted({e["asn"] for e in all_asns}),
    }


def _rebuild(kind: str) -> None:
    try:
        if kind == "city":
            result = _build_city_index()
        else:
            result = _build_asn_index()
        if result is None:
            return
        source_path = settings.GEOIP_CITY_DB_PATH if kind == "city" else settings.GEOIP_ASN_DB_PATH
        suffix = _CITY_CACHE_SUFFIX if kind == "city" else _ASN_CACHE_SUFFIX
        _save_cache(_cache_path(source_path, suffix), result)
        global _city_index, _asn_index
        with _lock:
            if kind == "city":
                _city_index = result
            else:
                _asn_index = result
    finally:
        with _lock:
            _building.discard(kind)


def ensure_fresh() -> None:
    """Call at the start of any route that reads the geo pick-lists. Cheap
    (just stats two small files) -- loads a disk cache into memory if one
    exists and this process hasn't seen it yet, and kicks a background
    rebuild (non-blocking) if the source mmdb is newer than what's
    cached, or nothing is cached at all yet."""
    global _city_index, _asn_index
    for kind, source_path, suffix in (
        ("city", settings.GEOIP_CITY_DB_PATH, _CITY_CACHE_SUFFIX),
        ("asn", settings.GEOIP_ASN_DB_PATH, _ASN_CACHE_SUFFIX),
    ):
        current_mtime = _source_mtime(source_path)
        if current_mtime is None:
            continue  # source db not present -- nothing to build
        with _lock:
            in_memory = _city_index if kind == "city" else _asn_index
            already_building = kind in _building
        if in_memory is not None and in_memory.get("source_mtime") == current_mtime:
            continue  # already fresh in this process
        if in_memory is None:
            cached = _load_cache(_cache_path(source_path, suffix))
            if cached is not None:
                with _lock:
                    if kind == "city":
                        _city_index = cached
                    else:
                        _asn_index = cached
                if cached.get("source_mtime") == current_mtime:
                    continue  # disk cache was already fresh
        if already_building:
            continue
        with _lock:
            _building.add(kind)
        threading.Thread(target=_rebuild, args=(kind,), daemon=True).start()


def get_status() -> dict:
    with _lock:
        return {
            "city_ready": _city_index is not None,
            "asn_ready": _asn_index is not None,
            "building": sorted(_building),
        }


# Hard cap on any single /api/geo/cities or /api/geo/asns response --
# some countries have thousands-to-tens-of-thousands of entries (the US
# alone has ~18.6k known ASNs and ~11.7k cities in these databases), and
# "any country" ASN search spans the full ~78k-entry global list. Handing
# all of that to the browser in one response -- and then rendering it as
# that many checkboxes -- is what made the Users page slow to begin with
# (see the fix that added this cap: a users.html regression report).
# Ranked results (prefix match first) mean the cap rarely matters in
# practice once an admin types a real search term.
_MAX_RESULTS = 200


def get_countries_with_cities() -> list[str] | None:
    with _lock:
        idx = _city_index
    return sorted(idx["by_country"].keys()) if idx else None


def _rank_and_cap(values: list, q: str | None, key) -> tuple[list, int]:
    """Returns (capped results, total matches before capping). With no
    query, just the first _MAX_RESULTS in `values`' existing (alphabetical
    for cities, org-name for ASNs) order -- browsing, not searching, so
    admins are expected to type rather than scroll thousands of entries.
    With a query, prefix matches rank before substring matches."""
    if not q:
        return values[:_MAX_RESULTS], len(values)
    q = q.strip().lower()
    starts, contains = [], []
    for v in values:
        k = key(v).lower()
        if k.startswith(q):
            starts.append(v)
        elif q in k:
            contains.append(v)
    matches = starts + contains
    return matches[:_MAX_RESULTS], len(matches)


def get_cities(country: str, q: str | None = None) -> tuple[list[str], int] | None:
    with _lock:
        idx = _city_index
    if idx is None:
        return None
    values = idx["by_country"].get(country.upper(), [])
    return _rank_and_cap(values, q, key=lambda v: v)


def get_countries_with_asns() -> list[str] | None:
    with _lock:
        idx = _asn_index
    return sorted(idx["by_country"].keys()) if idx else None


def get_asns(country: str | None, q: str | None = None) -> tuple[list[dict], int] | None:
    with _lock:
        idx = _asn_index
    if idx is None:
        return None
    values = idx["all"] if country is None else idx["by_country"].get(country.upper(), [])
    return _rank_and_cap(values, q, key=lambda v: f"{v['org']} {v['asn']}")


def canonical_city(name: str) -> str | None:
    """Case-insensitive lookup returning the exact casing MaxMind uses
    (e.g. "karachi" -> "Karachi"), or None if either the index isn't
    ready yet or the name genuinely isn't in it -- callers can't tell
    those two apart from this alone, use city_exists() first if that
    distinction matters (routes/users.py's validator does)."""
    with _lock:
        idx = _city_index
    if idx is None:
        return None
    return idx["lower_to_canonical"].get(name.strip().lower())


def city_exists(name: str) -> bool | None:
    """True/False if the city index is ready, None if it isn't built yet
    (caller should fall back to shape-only validation in that case, not
    block admins during the startup/rebuild window)."""
    with _lock:
        idx = _city_index
    if idx is None:
        return None
    return canonical_city(name) is not None


_asn_number_set_cache: tuple[float, set[str]] | None = None


def asn_exists(normalized_asn: str) -> bool | None:
    """`normalized_asn` like "AS15169". Same None-means-not-ready contract
    as city_exists(). Memoizes a set() built from the index's
    all_asn_numbers list (~78k entries) keyed by that index's
    source_mtime, so repeated calls against the same loaded index (e.g.
    validating several entries in one request) don't rebuild it each
    time, but a background rebuild that swaps in a fresher index is
    picked up automatically."""
    global _asn_number_set_cache
    with _lock:
        idx = _asn_index
    if idx is None:
        return None
    mtime = idx["source_mtime"]
    if _asn_number_set_cache is None or _asn_number_set_cache[0] != mtime:
        _asn_number_set_cache = (mtime, set(idx["all_asn_numbers"]))
    return normalized_asn in _asn_number_set_cache[1]
