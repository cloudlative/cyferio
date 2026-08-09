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
import os
import platform
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from sqlalchemy import text

from .config import settings
from .db import engine, get_db_engine_info

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

    hostname = _read_file(os.path.join(proc, "sys/kernel/hostname"))
    result["hostname"] = hostname.strip() if hostname else None

    uptime_raw = _read_file(os.path.join(proc, "uptime"))
    result["uptime_seconds"] = float(uptime_raw.split()[0]) if uptime_raw else None

    loadavg_raw = _read_file(os.path.join(proc, "loadavg"))
    result["load_avg"] = [float(x) for x in loadavg_raw.split()[:3]] if loadavg_raw else None

    cpuinfo = _read_file(os.path.join(proc, "cpuinfo")) or ""
    result["cpu_count"] = sum(1 for line in cpuinfo.splitlines() if line.split(":")[0].strip() == "processor")

    # CPU percent needs two samples -- a short, deliberate blocking sleep.
    # Fine here: FastAPI runs sync route handlers in a threadpool, so this
    # never blocks the event loop, and it's a low-traffic admin-only page
    # (same tradeoff this app already makes for its subprocess calls).
    # 0.5s, not something shorter: /proc/stat advances in whole USER_HZ
    # ticks (10ms each on the standard 100Hz clock), so on this project's
    # actual 1-vCPU production droplet a too-short window samples only
    # ~15 ticks -- observed in practice swinging wildly between 0% and
    # 100% purely from sampling noise, not real load. ~50 ticks at 0.5s
    # is enough to average that out into a meaningful reading.
    stat1 = _read_file(os.path.join(proc, "stat"))
    times1 = _cpu_times(stat1) if stat1 else None
    if times1:
        time.sleep(0.5)
        stat2 = _read_file(os.path.join(proc, "stat"))
        times2 = _cpu_times(stat2) if stat2 else None
        if times2:
            idle_delta = times2[0] - times1[0]
            total_delta = times2[1] - times1[1]
            result["cpu_percent"] = round(100 * (1 - idle_delta / total_delta), 1) if total_delta > 0 else None
        else:
            result["cpu_percent"] = None
    else:
        result["cpu_percent"] = None

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


def get_traefik_health() -> dict:
    """Pings Traefik's own internal API (see config.py's TRAEFIK_API_URL --
    reachable only from other containers on the same compose network, see
    docker-compose.yml) for router/service status. available=False (not
    an error) if the API is simply unreachable, e.g. local dev with no
    traefik container running at all."""
    try:
        urllib.request.urlopen(f"{settings.TRAEFIK_API_URL}/ping", timeout=2.0)
        ping_ok = True
    except (urllib.error.URLError, OSError, TimeoutError):
        return {"available": False, "reason": "Traefik's internal API is unreachable from this container."}

    result: dict = {"available": True, "ping_ok": ping_ok, "error": None, "routers": [], "services": []}
    try:
        routers = _traefik_get("/api/http/routers")
        result["routers"] = [
            {
                "name": r.get("name"),
                "rule": r.get("rule"),
                "status": r.get("status"),
                "provider": r.get("provider"),
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
                "server_status": s.get("serverStatus") or {},
            }
            for s in services
            if s.get("provider") != "internal"
        ]
    except Exception as e:
        if not result["error"]:
            result["error"] = f"Could not read service list: {e}"

    return result
