"""
Data-gathering for the Health page. Deliberately pure stdlib (no psutil,
no requests/httpx) -- this app's dependency list has stayed intentionally
small (see requirements.txt), and everything needed here (parsing /proc,
statvfs, a couple of short-timeout HTTP GETs to Traefik's internal API) is
straightforward without a new dependency.

Every function here is defensive by design: a missing mount, an
unreachable Traefik container, or a database hiccup should make its own
card show "unavailable"/an error message, never take down the whole
Health page or the process. None of these raise for the "not available in
this environment" case (e.g. local dev has no /hostproc, no traefik
container) -- only get_database_health() can return ok=False for a real
connectivity problem, which is the one case actually worth surfacing as
unhealthy rather than just "not applicable here".
"""
import importlib.metadata
import json
import logging
import os
import platform
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from sqlalchemy import text

from .config import settings
from .db import engine, get_db_engine_info

logger = logging.getLogger(__name__)

# Recorded once, at import time (which happens once per worker process, at
# startup) -- the simplest possible "how long has this process been up"
# clock, matching the single-worker/single-process deployment this app
# actually runs as (see docker-compose.yml -- one `app` container, no
# multi-worker uvicorn flag).
_PROCESS_STARTED_AT = time.time()


def _pkg_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def get_app_health() -> dict:
    """Process-level health: how long this worker has been running, what
    it's running (versions), and how fresh the background dashboard
    snapshot is -- a stalled background loop (see main.py's
    _dashboard_refresh_loop) wouldn't crash the app, so it needs its own
    explicit staleness signal rather than just "the process didn't die"."""
    from . import cli_wrapper

    now = time.time()
    return {
        "status": "ok",
        "started_at": datetime.fromtimestamp(_PROCESS_STARTED_AT, tz=timezone.utc).isoformat(),
        "uptime_seconds": round(now - _PROCESS_STARTED_AT, 1),
        "app_version": os.environ.get("APP_VERSION", "unknown"),
        "python_version": platform.python_version(),
        "fastapi_version": _pkg_version("fastapi"),
        "uvicorn_version": _pkg_version("uvicorn"),
        "db_engine": get_db_engine_info(),
        "background_snapshot_age_seconds": cli_wrapper.get_dashboard_snapshot_age_seconds(),
    }


def get_database_health() -> dict:
    """Live connectivity check (SELECT 1, with real round-trip latency) plus
    -- for PostgreSQL specifically -- database size and active connection
    count. SQLite has neither concept in the same way (it's a single file,
    "connections" don't apply), so those two fields stay null there rather
    than reporting something misleading."""
    result = {
        "ok": False,
        "engine": get_db_engine_info(),
        "latency_ms": None,
        "size_bytes": None,
        "active_connections": None,
        "error": None,
    }
    try:
        start = time.monotonic()
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
            result["latency_ms"] = round((time.monotonic() - start) * 1000, 2)
            if engine.dialect.name == "postgresql":
                result["size_bytes"] = conn.exec_driver_sql(
                    "SELECT pg_database_size(current_database())"
                ).scalar()
                result["active_connections"] = conn.exec_driver_sql(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                ).scalar()
        result["ok"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def gather_db_stats(conn) -> dict:
    """The raw, whole-database Postgres numbers both write_db_stat_snapshot
    (below, persisted) and routes/reports.py's live "current" reading
    (not persisted) need -- kept as one function so the two call sites
    can't silently drift apart on what "active"/"idle" or "long-running"
    mean. Callers are responsible for the `engine.dialect.name ==
    "postgresql"` guard -- this assumes it's already true."""
    stats: dict = {
        "db_size_bytes": None, "active_connections": None, "idle_connections": None,
        "xact_commit": None, "xact_rollback": None, "blks_hit": None, "blks_read": None,
        "waiting_locks_count": None, "long_running_query_count": None,
    }
    stats["db_size_bytes"] = conn.execute(text("SELECT pg_database_size(current_database())")).scalar()

    state_counts = dict(conn.execute(text(
        "SELECT state, count(*) FROM pg_stat_activity WHERE datname = current_database() GROUP BY state"
    )).all())
    stats["active_connections"] = state_counts.get("active", 0)
    # Every non-"active" state (idle, idle in transaction, idle in
    # transaction (aborted), etc.) counted as "idle" here -- a coarser
    # split than pg_stat_activity's own state enum, but "active vs
    # everything else" is the operationally meaningful distinction for
    # the Connections chart.
    stats["idle_connections"] = sum(v for k, v in state_counts.items() if k != "active")

    pgstat_row = conn.execute(text(
        "SELECT xact_commit, xact_rollback, blks_hit, blks_read FROM pg_stat_database "
        "WHERE datname = current_database()"
    )).one_or_none()
    if pgstat_row:
        stats["xact_commit"], stats["xact_rollback"], stats["blks_hit"], stats["blks_read"] = pgstat_row

    stats["waiting_locks_count"] = conn.execute(text("SELECT count(*) FROM pg_locks WHERE NOT granted")).scalar()

    # Fixed 5-second threshold -- a reasonable first cut, not yet an admin
    # setting (same stance reports.py's 80%-quota-approaching-threshold
    # constant already takes).
    stats["long_running_query_count"] = conn.execute(text(
        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
        "AND state = 'active' AND now() - query_start > interval '5 seconds'"
    )).scalar()
    return stats


def get_top_tables(limit: int = 10) -> list[dict]:
    """Live, point-in-time only -- deliberately NOT part of DbStatSnapshot's
    time series (see that model's docstring for why). Postgres-only;
    returns [] on SQLite (there's no equivalent system view, and this
    app's SQLite usage is dev-only anyway)."""
    if engine.dialect.name != "postgresql":
        return []
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT c.relname, pg_total_relation_size(c.oid) AS size_bytes "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "JOIN pg_stat_user_tables s ON s.relid = c.oid "
            "WHERE n.nspname = 'public' AND c.relkind = 'r' "
            "ORDER BY size_bytes DESC LIMIT :limit"
        ), {"limit": limit}).all()
    return [{"table": r[0], "size_bytes": r[1]} for r in rows]


def write_db_stat_snapshot(db) -> None:
    """Takes one point-in-time sample of whole-database Postgres statistics
    and inserts a DbStatSnapshot row -- called periodically by main.py's
    _db_snapshot_loop(), roughly every DB_SNAPSHOT_INTERVAL_SECONDS. `db`
    is a SQLAlchemy ORM Session (not a raw Connection like the other
    functions in this file use) -- the caller owns its lifecycle (opening/
    closing), matching every other place in this app that writes via a
    Session rather than through cli_wrapper's subprocess calls.

    Always inserts a row, even on SQLite or if a stat query fails --
    every numeric field just stays None -- so the time series has no
    silent gaps to explain later; same "NULL, not missing/broken" stance
    get_database_health() already takes for non-Postgres engines."""
    from .models import DbStatSnapshot

    row = DbStatSnapshot()
    if engine.dialect.name == "postgresql":
        try:
            stats = gather_db_stats(db.connection())
            for key, value in stats.items():
                setattr(row, key, value)
        except Exception:
            logger.exception("Failed gathering one or more DB stats for this snapshot -- inserting a partial/empty row rather than skipping it entirely")
    db.add(row)
    db.commit()


def _read_file(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _parse_meminfo(content: str) -> dict[str, int]:
    # Each line looks like "MemTotal:       16374856 kB" -- value is
    # always in kB regardless of the field, per proc(5).
    out = {}
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, _, rest = line.partition(":")
        parts = rest.strip().split()
        if parts and parts[0].isdigit():
            out[key.strip()] = int(parts[0]) * 1024  # kB -> bytes
    return out


def _cpu_times(stat_content: str) -> tuple[int, int] | None:
    # First "cpu " line: user nice system idle iowait irq softirq steal ...
    # (all in USER_HZ ticks, but only used here as relative deltas between
    # two samples, so the tick-vs-second unit never actually matters).
    for line in stat_content.splitlines():
        if line.startswith("cpu "):
            fields = [int(x) for x in line.split()[1:]]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)  # idle + iowait
            total = sum(fields)
            return idle, total
    return None


# Cross-request CPU sample state: (idle+iowait, total, wall_clock) from the
# last call, keyed by nothing (this app is single-process -- see
# docker-compose.yml, no multi-worker uvicorn flag -- so one shared pair of
# module-level values is safe, same assumption cli_wrapper.py's caches and
# app_settings.py's `runtime` already make).
#
# NOT a short in-request sleep-then-resample (an earlier version of this
# function did that): confirmed by hand on the actual production droplet
# that /proc/stat's idle+iowait counters here only advance in coarse
# ~10-15s jumps while user/system advance every tick -- a sub-15-second
# window reliably sees an idle delta of exactly 0 while real work keeps
# ticking, producing a falsely pinned ~100% reading regardless of actual
# load (verified: 0.5s and even 5s windows both read 100% while `top`
# showed the host mostly idle; a 15s window read correctly). Blocking an
# HTTP request for 15s isn't viable, so instead each call diffs against
# whatever the previous call's sample was -- which, since Health is a
# human clicking Refresh or loading a page, is naturally many seconds to
# minutes old, comfortably past that ~15s granularity. The very first call
# after a process start (or the first call in over CPU_SAMPLE_MAX_AGE_SECONDS)
# has no usable previous sample, so it returns None rather than a number
# computed from stale/absent state -- the Health page shows "—" for that
# one request, not a wrong number.
CPU_SAMPLE_MAX_AGE_SECONDS = 600  # beyond this, the delta itself is too coarse to mean "right now"
_cpu_sample: tuple[int, int, float] | None = None


def _sample_cpu_percent(proc_path: str) -> float | None:
    global _cpu_sample
    stat_content = _read_file(os.path.join(proc_path, "stat"))
    times = _cpu_times(stat_content) if stat_content else None
    if times is None:
        return None
    idle, total = times
    now = time.monotonic()

    previous = _cpu_sample
    _cpu_sample = (idle, total, now)

    if previous is None:
        return None
    prev_idle, prev_total, prev_at = previous
    if now - prev_at > CPU_SAMPLE_MAX_AGE_SECONDS:
        return None
    idle_delta = idle - prev_idle
    total_delta = total - prev_total
    if total_delta <= 0:
        return None
    return round(100 * (1 - idle_delta / total_delta), 1)


def get_host_health() -> dict:
    """Real droplet-level CPU/RAM/disk/uptime, read from the host's /proc,
    /sys, and root filesystem -- bind-mounted read-only into this
    container specifically for this page (see config.py's HOST_*_PATH
    docstring for why the container's own /proc isn't good enough here).
    Returns available=False (not an error) when those mounts aren't
    present at all, e.g. local/dev runs -- that's an expected, normal
    state there, not a fault."""
    proc, root = settings.HOST_PROC_PATH, settings.HOST_ROOT_PATH
    if not os.path.isdir(proc):
        return {"available": False, "reason": f"{proc} is not mounted (expected in local/dev runs)."}

    result: dict = {"available": True, "error": None}

    # NOT /hostproc/sys/kernel/hostname: unlike /proc/stat, /proc/meminfo,
    # etc. (genuinely global, kernel-wide counters), /proc/sys/kernel/
    # hostname is backed by the READING PROCESS's own UTS namespace, which
    # bind-mounting the host's /proc does not change -- it reliably
    # returns this container's own hostname (its container id) even
    # through /hostproc, not the droplet's. /etc/hostname is a plain file,
    # not namespace-aware, so read it from the bind-mounted host root
    # filesystem instead (see config.py's HOST_ROOT_PATH).
    hostname = _read_file(os.path.join(root, "etc/hostname"))
    result["hostname"] = hostname.strip() if hostname else None

    uptime_raw = _read_file(os.path.join(proc, "uptime"))
    result["uptime_seconds"] = float(uptime_raw.split()[0]) if uptime_raw else None

    loadavg_raw = _read_file(os.path.join(proc, "loadavg"))
    result["load_avg"] = [float(x) for x in loadavg_raw.split()[:3]] if loadavg_raw else None

    cpuinfo = _read_file(os.path.join(proc, "cpuinfo")) or ""
    result["cpu_count"] = sum(1 for line in cpuinfo.splitlines() if line.split(":")[0].strip() == "processor")

    result["cpu_percent"] = _sample_cpu_percent(proc)

    meminfo_raw = _read_file(os.path.join(proc, "meminfo"))
    if meminfo_raw:
        mem = _parse_meminfo(meminfo_raw)
        total = mem.get("MemTotal", 0)
        available = mem.get("MemAvailable", 0)
        used = max(0, total - available)
        result["memory"] = {
            "total_bytes": total,
            "used_bytes": used,
            "percent": round(100 * used / total, 1) if total else None,
        }
    else:
        result["memory"] = None

    if os.path.isdir(root):
        try:
            st = os.statvfs(root)
            total = st.f_frsize * st.f_blocks
            free = st.f_frsize * st.f_bavail
            used = total - free
            result["disk"] = {
                "total_bytes": total,
                "used_bytes": used,
                "percent": round(100 * used / total, 1) if total else None,
                "path": "/",
            }
        except OSError as e:
            result["disk"] = None
            result["error"] = f"Could not read disk usage: {e}"
    else:
        result["disk"] = None

    return result


def _traefik_get(path: str, timeout: float = 3.0):
    req = urllib.request.Request(f"{settings.TRAEFIK_API_URL}{path}", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _traefik_get_text(path: str, timeout: float = 3.0) -> str:
    req = urllib.request.Request(f"{settings.TRAEFIK_API_URL}{path}", headers={"Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


# Bare-bones Prometheus text-exposition-format parser -- deliberately not a
# real dependency (prometheus_client has no *parsing* helper anyway; the
# real client for that is a separate package) for a handful of counters/
# histograms we already know the shape of. Handles the two line shapes
# Traefik actually emits: `name value` and `name{label="val",...} value`.
# Not a general-purpose parser (doesn't handle every exposition-format edge
# case like multi-line HELP/TYPE continuation) -- good enough for scraping
# our own known Traefik metric names.
_METRIC_LINE_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)$')
_LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def _parse_prometheus_text(text: str) -> dict:
    """Returns {metric_name: [(labels_dict, float_value), ...]}."""
    out: dict[str, list] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = _METRIC_LINE_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        labels = dict(_LABEL_RE.findall(m.group("labels") or ""))
        try:
            value = float(m.group("value"))
        except ValueError:
            continue
        out.setdefault(name, []).append((labels, value))
    return out


def _summarize_traefik_metrics(text: str) -> dict:
    """Reduces the raw Prometheus scrape down to what the Health page
    actually shows: per-service and per-entrypoint request totals broken
    down by status-code class, plus average latency. Average, not p50/p99
    -- Traefik's histograms use fixed buckets, so an exact percentile needs
    interpolation across them; sum/count (which Traefik always emits
    alongside the buckets) gives a real, exact average with no
    approximation, which is the honester number to show here."""
    metrics = _parse_prometheus_text(text)

    def _bucket(rows: list, key_label: str) -> dict:
        buckets: dict[str, dict] = {}
        for labels, value in rows:
            key = labels.get(key_label)
            if not key:
                continue
            b = buckets.setdefault(key, {"total": 0, "by_code": {}})
            code = labels.get("code", "?")
            n = int(value)
            b["total"] += n
            b["by_code"][code] = b["by_code"].get(code, 0) + n
        return buckets

    services = _bucket(metrics.get("traefik_service_requests_total", []), "service")
    entrypoints = _bucket(metrics.get("traefik_entrypoint_requests_total", []), "entrypoint")

    def _attach_latency(buckets: dict, sum_rows: list, count_rows: list, key_label: str):
        sums: dict[str, float] = {}
        for labels, value in sum_rows:
            key = labels.get(key_label)
            if key:
                sums[key] = sums.get(key, 0.0) + value
        counts: dict[str, float] = {}
        for labels, value in count_rows:
            key = labels.get(key_label)
            if key:
                counts[key] = counts.get(key, 0.0) + value
        for key, b in buckets.items():
            total_count = counts.get(key, 0)
            b["avg_latency_ms"] = round((sums.get(key, 0.0) / total_count) * 1000, 1) if total_count else None

    _attach_latency(
        services,
        metrics.get("traefik_service_request_duration_seconds_sum", []),
        metrics.get("traefik_service_request_duration_seconds_count", []),
        "service",
    )
    _attach_latency(
        entrypoints,
        metrics.get("traefik_entrypoint_request_duration_seconds_sum", []),
        metrics.get("traefik_entrypoint_request_duration_seconds_count", []),
        "entrypoint",
    )

    return {
        "services": [{"name": k, **v} for k, v in sorted(services.items())],
        "entrypoints": [{"name": k, **v} for k, v in sorted(entrypoints.items())],
    }


def get_traefik_health() -> dict:
    """Pings Traefik's own internal API (see config.py's TRAEFIK_API_URL --
    reachable only from other containers on the same compose network, see
    docker-compose.yml) for router/service/entrypoint/middleware status,
    plus a summarized scrape of its Prometheus metrics endpoint for actual
    request counts and latency (the JSON API alone never reports traffic,
    only current config + up/down state -- see docker-compose.yml's
    --metrics.prometheus=* comment). available=False (not an error) if the
    API is simply unreachable, e.g. local dev with no traefik container
    running at all."""
    try:
        urllib.request.urlopen(f"{settings.TRAEFIK_API_URL}/ping", timeout=2.0)
        ping_ok = True
    except (urllib.error.URLError, OSError, TimeoutError):
        return {"available": False, "reason": "Traefik's internal API is unreachable from this container."}

    result: dict = {
        "available": True,
        "ping_ok": ping_ok,
        "error": None,
        "routers": [],
        "services": [],
        "entrypoints": [],
        "middlewares": [],
        "metrics": None,
        "metrics_error": None,
    }
    try:
        routers = _traefik_get("/api/http/routers")
        result["routers"] = [
            {
                "name": r.get("name"),
                "rule": r.get("rule"),
                "status": r.get("status"),
                "provider": r.get("provider"),
                "middlewares": r.get("middlewares") or [],
                "errors": r.get("error") or [],
            }
            for r in routers
            if r.get("provider") != "internal"  # the api@internal router itself -- noise, not a real backend
        ]
    except Exception as e:
        result["error"] = f"Could not read router list: {e}"

    try:
        services = _traefik_get("/api/http/services")
        result["services"] = [
            {
                "name": s.get("name"),
                "status": s.get("status"),
                "provider": s.get("provider"),
                # Per-backend UP/DOWN -- e.g. {"http://app-blue:8000": "UP",
                # "http://app-green:8000": "DOWN"} -- this is the actual
                # blue/green cutover signal, straight from Traefik's own
                # active health check.
                "server_status": s.get("serverStatus") or {},
            }
            for s in services
            if s.get("provider") != "internal"
        ]
    except Exception as e:
        if not result["error"]:
            result["error"] = f"Could not read service list: {e}"

    try:
        entrypoints = _traefik_get("/api/entrypoints")
        result["entrypoints"] = [
            {"name": e.get("name"), "address": e.get("address")} for e in entrypoints
        ]
    except Exception as e:
        if not result["error"]:
            result["error"] = f"Could not read entrypoint list: {e}"

    try:
        middlewares = _traefik_get("/api/http/middlewares")
        result["middlewares"] = [
            {"name": m.get("name"), "type": m.get("type"), "provider": m.get("provider")}
            for m in middlewares
            if m.get("provider") != "internal"
        ]
    except Exception as e:
        if not result["error"]:
            result["error"] = f"Could not read middleware list: {e}"

    try:
        result["metrics"] = _summarize_traefik_metrics(_traefik_get_text("/metrics"))
    except Exception as e:
        # Not folded into the top-level "error" field -- an unreachable
        # /metrics (e.g. an older running Traefik container from before
        # --metrics.prometheus=true was added, mid-rollout) shouldn't mark
        # the whole card unhealthy when routers/services above read fine.
        result["metrics_error"] = f"Could not read request metrics: {e}"

    return result
