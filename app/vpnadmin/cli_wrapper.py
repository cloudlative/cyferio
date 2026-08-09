"""
Thin, safety-conscious wrapper around the two CLI tools this app is a
frontend for: openvpn-install.sh and vpn-status.py.

Every call here uses subprocess with an explicit argument list -- never
shell=True or a string-interpolated command -- so there is no command
injection surface even though some of these arguments (client names) are
ultimately user-supplied from the web UI. The scripts themselves remain the
single source of truth for validation (name sanitization, MAC
normalization, etc.); this wrapper does not re-implement that logic, only
invokes it and relays the result.
"""
import json
import subprocess
import threading
import time

from .config import settings

# The two wrapped scripts spawn a fresh python3/bash interpreter per
# invocation, and the dashboard fires several of these concurrently
# (Promise.all over /api/status, /api/status/all, /api/clients, ...). On a
# small box (e.g. a 1 vCPU/~1GB droplet) that concurrent spawn burst can
# exceed available memory and trigger the *host's* OOM killer -- observed
# in production killing app subprocesses (exit code -9) and, worse, nearly
# killing unrelated processes (openvpn itself, containerd) before the app
# was even at fault. Serializing script execution trades a little latency
# (calls queue instead of running in parallel) for never spiking multiple
# heavy interpreters into memory at once.
_script_lock = threading.Lock()

# Short-lived cache for read-only calls: the dashboard, and a user simply
# clicking between pages, can easily re-request the same status/list data
# within a couple of seconds. Each call is a real subprocess spawn (see
# _script_lock above for why that's expensive on this box), so a small TTL
# turns "reload the dashboard twice quickly" from 2 full spawn-bursts into 1.
# Keyed by (function name, args tuple); not used for mutating calls.
_CACHE_TTL_SECONDS = 3
_cache: dict[tuple, tuple[float, object]] = {}
_cache_lock = threading.Lock()


def _cached(key: tuple, fn):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None and now - hit[0] < _CACHE_TTL_SECONDS:
            return hit[1]
    result = fn()
    with _cache_lock:
        _cache[key] = (now, result)
    return result


class ScriptError(Exception):
    """Raised when a wrapped script exits non-zero (unexpectedly) or times
    out. Carries enough detail for API routes to turn into a clean error
    response without leaking raw tracebacks to the frontend."""

    def __init__(self, message: str, *, stdout: str = "", stderr: str = "", returncode: int | None = None):
        super().__init__(message)
        self.message = message
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _run(args: list[str]) -> subprocess.CompletedProcess:
    if settings.USE_SUDO:
        # -n (non-interactive): fail fast with a clear error instead of
        # hanging on a password prompt this app has no way to answer.
        args = ["sudo", "-n"] + args
    try:
        with _script_lock:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=settings.SCRIPT_TIMEOUT_SECONDS,
                check=False,
                shell=False,  # explicit: never let this become shell=True
            )
    except subprocess.TimeoutExpired as e:
        raise ScriptError(
            f"Command timed out after {settings.SCRIPT_TIMEOUT_SECONDS}s"
        ) from e
    except FileNotFoundError as e:
        raise ScriptError(
            f"Command not found: {args[0]} -- check OPENVPN_INSTALL_SCRIPT/"
            f"VPN_STATUS_SCRIPT/sudo paths in the app's config"
        ) from e


def _run_install_script(*args: str) -> subprocess.CompletedProcess:
    return _run(["bash", settings.OPENVPN_INSTALL_SCRIPT, *args])


def _run_status_script(*args: str) -> subprocess.CompletedProcess:
    return _run(["python3", settings.VPN_STATUS_SCRIPT, *args])


def _parse_json_or_raise(proc: subprocess.CompletedProcess, *, allow_nonzero_json: bool = False):
    """Most read-only --json commands print valid JSON on success. --check-certs,
    --lint-mac-db, and --macs intentionally exit 1 (with still-valid JSON) when
    they find issues / an empty result -- that's informative output, not a
    failed call, so callers for those pass allow_nonzero_json=True."""
    if proc.returncode != 0 and not allow_nonzero_json:
        raise ScriptError(
            proc.stderr.strip() or f"Command failed with exit code {proc.returncode}",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScriptError(
            "Command did not return valid JSON",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        ) from e


# --- openvpn-install.sh ------------------------------------------------------

def list_clients() -> list[dict]:
    return _cached(("list_clients",), lambda:
        _parse_json_or_raise(_run_install_script("--list-users", "--json")))


def list_revoked() -> list[dict]:
    return _cached(("list_revoked",), lambda:
        _parse_json_or_raise(_run_install_script("--list-revoked-users", "--json")))


def list_macs(name: str) -> dict:
    def _do():
        proc = _run_install_script("--macs", name, "--json")
        return _parse_json_or_raise(proc, allow_nonzero_json=True)
    return _cached(("list_macs", name), _do)


def add_mac(name: str, mac: str) -> str:
    proc = _run_install_script("--add-mac", name, mac)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to add MAC address",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    _invalidate_client_caches(name)
    return proc.stdout.strip()


def remove_mac(name: str, mac: str) -> str:
    proc = _run_install_script("--remove-mac", name, mac)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to remove MAC address",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    _invalidate_client_caches(name)
    return proc.stdout.strip()


def _invalidate_client_caches(name: str) -> None:
    """After a mutating client/MAC action, drop any cached read-only results
    that would now be stale -- otherwise a change could appear not to have
    taken effect for up to _CACHE_TTL_SECONDS."""
    with _cache_lock:
        for key in [k for k in _cache if k[0] in ("list_clients", "list_revoked", "check_consistency", "lint_db")
                    or (k[0] == "list_macs" and len(k) > 1 and k[1] == name)]:
            _cache.pop(key, None)


def check_consistency() -> dict:
    return _cached(("check_consistency",), lambda:
        _parse_json_or_raise(_run_install_script("--check-certs", "--json"), allow_nonzero_json=True))


def lint_db() -> dict:
    return _cached(("lint_db",), lambda:
        _parse_json_or_raise(_run_install_script("--lint-mac-db", "--json"), allow_nonzero_json=True))


def add_client(name: str, mac: str) -> str:
    """Returns the script's plain-text confirmation on success. --add-user has
    no --json support by design (see openvpn-install.sh --help) -- it's a
    mutating action best surfaced with its real stdout, not silently
    swallowed. Raises ScriptError with the script's own stderr message on
    failure (bad name, bad MAC, duplicate client, etc.) -- already
    human-readable, written for exactly this purpose."""
    proc = _run_install_script("--add-user", name, mac)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to add client",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    _invalidate_client_caches(name)
    return proc.stdout.strip()


def revoke_client(name: str) -> str:
    proc = _run_install_script("--revoke-user", name)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to revoke client",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    _invalidate_client_caches(name)
    return proc.stdout.strip()


def show_ovpn(name: str) -> str:
    """Returns an existing client's already-generated .ovpn config content.
    Not cached (unlike the list-style calls above) -- this returns key
    material, so every call should reflect the file on disk right now."""
    proc = _run_install_script("--show-ovpn", name)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to read .ovpn file",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    return proc.stdout


def purge_revoked(name: str) -> str:
    """Permanently deletes a revoked client's leftover PKI/.ovpn files (see
    openvpn-install.sh's do_purge_revoked for exactly what is and isn't
    removed)."""
    proc = _run_install_script("--purge-revoked", name)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to purge revoked client",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    _invalidate_client_caches(name)
    return proc.stdout.strip()


def clean_stale_db_entry(name: str) -> str:
    """Removes a revoked client's leftover openvpn_db.txt (MAC-binding)
    entry -- the "stale_db_entry" flag surfaced by get_revoked_snapshot
    below. The script itself refuses (non-zero exit -> ScriptError) if the
    name still has a currently-valid certificate, so this can't accidentally
    break a live client's MAC check."""
    proc = _run_install_script("--clean-stale-db", name)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to clean stale db entry",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    _invalidate_client_caches(name)
    return proc.stdout.strip()


def restore_client(name: str, mac: str) -> str:
    """Reissues a brand-new certificate under a revoked client's name -- see
    openvpn-install.sh's do_restore_client docstring for why this is NOT
    the same as un-revoking the old certificate."""
    proc = _run_install_script("--restore", name, mac)
    if proc.returncode != 0:
        raise ScriptError(
            proc.stderr.strip() or "Failed to restore client",
            stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode,
        )
    _invalidate_client_caches(name)
    return proc.stdout.strip()


# --- vpn-status.py ------------------------------------------------------------

def status_connected() -> list[dict]:
    return _cached(("status_connected",), lambda:
        _parse_json_or_raise(_run_status_script("--json")))


def status_all() -> list[dict]:
    return _cached(("status_all",), lambda:
        _parse_json_or_raise(_run_status_script("--all-clients", "--json")))


def status_rejected(limit: int = 20) -> list[dict]:
    return _cached(("status_rejected", limit), lambda:
        _parse_json_or_raise(_run_status_script("--rejected-connections", str(limit), "--json")))


def status_session_history(limit: int = 20) -> list[dict]:
    """Connection History page's data source -- past (ended) sessions, each
    with connected/disconnected timestamps, duration, source IP, and byte
    counts. See vpn-status.py's cmd_session_history / host-scripts/
    policy_lib.py's append_session_history for what's actually in each
    row. Not part of the shared dashboard snapshot below (that snapshot is
    scoped to what Dashboard/Clients/Revoked/Diagnostics need on every
    load; Connection History is its own page with its own fetch, same as
    e.g. /api/lint-db)."""
    return _cached(("status_session_history", limit), lambda:
        _parse_json_or_raise(_run_status_script("--session-history", str(limit), "--json")))


# --- Combined dashboard summary ------------------------------------------

def dashboard_summary(rejected_limit: int = 20) -> dict:
    """One call for everything the dashboard (and, via the shared background
    snapshot below, the Clients/Revoked/Diagnostics pages) needs, instead of
    each page independently hitting the script lock/cache on its own timer.
    Still N underlying script calls (each individually cached above), but
    callers only pay one HTTP request and one JSON parse.

    Note "all_clients" (vpn-status.py --all-clients) and "clients" (openvpn-install.sh
    --list-users) are deliberately both included and are NOT interchangeable:
    "all_clients" carries live status/last-seen/single-MAC-in-use info,
    while "clients" carries MAC-*db* registration counts (mac_count,
    in_db) -- a dashboard stat about "how many MACs are registered" must
    read from "clients", not "all_clients" (which has no mac_count field
    at all, and previously produced a misleadingly-large "missing MAC"
    count as a result).

    "rejected" stays capped at rejected_limit (20 by default) -- that's
    what the dashboard's "Recent Rejections" stat literally means, and
    changing what feeds it would silently change that number's meaning.
    "rejected_full" is a separate, much larger pull (500, matching what
    the Diagnostics page's own rejected-connections table/filters need)
    riding along on the same timer -- see get_rejected_snapshot() below for
    why this doesn't affect the dashboard at all.

    "check_consistency" and "lint_db" are the Diagnostics page's two other
    cards. Adding them here means Diagnostics rides the same background
    refresh loop as the Dashboard instead of needing its own separate timer
    and subprocess-spawn burst -- see main.py's lifespan, which only ever
    starts one such loop."""
    return {
        "connected": status_connected(),
        "all_clients": status_all(),
        "clients": list_clients(),
        "revoked": list_revoked(),
        "rejected": status_rejected(rejected_limit),
        "rejected_full": status_rejected(500),
        "check_consistency": check_consistency(),
        "lint_db": lint_db(),
    }


# --- Background-refreshed app-wide snapshot ----------------------------
# GET /api/dashboard used to call dashboard_summary() directly per request:
# several sequential script spawns (each individually cached above, but
# that only helps a *second* request within the 3s TTL), so a cold page
# load was genuinely slow -- and _script_lock intentionally serializes
# them (see its own comment), so making the route async/threaded wouldn't
# have helped at all; every one of those calls would just queue on the
# same lock anyway.
#
# Instead, a periodic background task (started in main.py's lifespan) calls
# refresh_dashboard_snapshot() on a timer, independent of any request. Every
# read-only route below just returns whatever's currently cached here --
# near-instant, at the cost of the data being up to one refresh interval
# stale, which is a reasonable trade for pages that already have a manual
# Refresh button for "I want it *right now*". The name is a holdover from
# when this only backed the Dashboard; it now backs Clients, Revoked, and
# Diagnostics too (see dashboard_summary()'s docstring) since they read
# from the exact same underlying CLI calls -- one shared snapshot instead
# of four separate background loops each doing their own spawn burst.
_dashboard_snapshot: dict | None = None
_dashboard_snapshot_lock = threading.Lock()


def get_dashboard_snapshot() -> dict | None:
    """Returns the most recently computed snapshot, or None if the
    background refresh loop hasn't completed its first tick yet (e.g. right
    after a fresh app startup)."""
    with _dashboard_snapshot_lock:
        return _dashboard_snapshot


def refresh_dashboard_snapshot(rejected_limit: int = 20) -> dict:
    """Computes a fresh dashboard_summary() and stores it as the snapshot
    get_dashboard_snapshot() serves. Still goes through the same
    _script_lock-serialized, individually-cached calls as always -- this
    doesn't change how the underlying scripts are invoked, only who's
    calling them and when (a timer, not a request)."""
    global _dashboard_snapshot
    result = dashboard_summary(rejected_limit)
    with _dashboard_snapshot_lock:
        _dashboard_snapshot = result
    return result


# --- Snapshot-first accessors for the Clients/Revoked/Diagnostics pages -----
# Each mirrors the shape of its "live" counterpart above (list_clients(),
# status_all(), ...): serve the shared snapshot when it's warm, otherwise
# fall back to a direct (blocking, _script_lock-serialized) call -- same
# fallback rule as get_dashboard()'s route, so a request is never served
# nothing just because it landed before the first background tick.


def get_clients_snapshot() -> list[dict]:
    snap = get_dashboard_snapshot()
    return snap["clients"] if snap is not None else list_clients()


def get_revoked_snapshot() -> list[dict]:
    snap = get_dashboard_snapshot()
    return snap["revoked"] if snap is not None else list_revoked()


def get_status_all_snapshot() -> list[dict]:
    snap = get_dashboard_snapshot()
    return snap["all_clients"] if snap is not None else status_all()


def get_status_connected_snapshot() -> list[dict]:
    snap = get_dashboard_snapshot()
    return snap["connected"] if snap is not None else status_connected()


def get_status_rejected_snapshot(limit: int = 20) -> list[dict]:
    """The snapshot carries two pre-fetched rejected-connections windows --
    "rejected" (20, what the dashboard's stat needs) and "rejected_full"
    (500, what Diagnostics' table/filters need). "rejected_full" was
    fetched with limit=500, so it already holds every available record up
    to that cap regardless of how many actually exist -- any requested
    limit up to 500 (the API's own cap, see routes/status.py) is served by
    slicing it. Only a limit above 500 -- not reachable via the API today,
    but this stays correct if that cap ever changes -- falls back to a
    fresh call."""
    snap = get_dashboard_snapshot()
    if snap is not None and limit <= 500:
        return snap["rejected_full"][:limit]
    return status_rejected(limit)


def get_check_consistency_snapshot() -> dict:
    snap = get_dashboard_snapshot()
    return snap["check_consistency"] if snap is not None else check_consistency()


def get_lint_db_snapshot() -> dict:
    snap = get_dashboard_snapshot()
    return snap["lint_db"] if snap is not None else lint_db()
