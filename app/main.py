"""
OpenVPN Toolkit web app -- entrypoint.

Run directly with:
    uvicorn main:app --host 0.0.0.0 --port 8000
or via the Dockerfile's CMD.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from vpnadmin import cli_wrapper, health
from vpnadmin.app_settings import prune_audit_log, prune_db_stat_snapshots, refresh_runtime_cache
from vpnadmin.auth import bootstrap_admin, ensure_bootstrap_admin_flag
from vpnadmin.config import settings
from vpnadmin.db import SessionLocal, init_db, promote_bootstrap_admin_to_super_admin
from vpnadmin import geo_lists
from vpnadmin.routes import auth, clients, diagnostics, geo, health, me_vpn, openvpn_install, pages, reports, roles, settings as settings_routes, status, teams, users

logger = logging.getLogger(__name__)

# How often the background task recomputes the /api/dashboard snapshot --
# see cli_wrapper.py's refresh_dashboard_snapshot()/get_dashboard_snapshot()
# docstrings for the full reasoning. 10s: frequent enough that "stale"
# never really registers for a human looking at the page, infrequent enough
# not to matter for script-spawn load on a small box (still fully
# serialized through the same _script_lock as ever -- this doesn't add any
# concurrent spawning, just moves the existing sequential spawns off the
# request path and onto a timer).
DASHBOARD_REFRESH_INTERVAL_SECONDS = 10

# How often the background task takes one Postgres stats sample for
# Database Reporting's trend charts (routes/reports.py's GET
# /api/reports/database, health.write_db_stat_snapshot) -- 10 minutes:
# frequent enough for meaningful trend granularity on charts spanning
# days/weeks, infrequent enough that ~144 rows/day is a non-issue for
# storage or the retention pruning below. A fixed code constant, not an
# admin setting -- unlike how LONG snapshots are kept
# (runtime.db_snapshot_retention_days, Settings-page-configurable), how
# OFTEN they're taken isn't, matching DASHBOARD_REFRESH_INTERVAL_SECONDS's
# own precedent of not being admin-configurable either.
DB_SNAPSHOT_INTERVAL_SECONDS = 600


async def _dashboard_refresh_loop():
    # Despite the name, this one snapshot now backs the Dashboard, Clients,
    # Revoked, and Diagnostics pages -- see cli_wrapper.dashboard_summary()'s
    # docstring for why they all ride the same timer instead of each having
    # their own background loop and subprocess-spawn burst.
    while True:
        try:
            await asyncio.to_thread(cli_wrapper.refresh_dashboard_snapshot)
        except Exception:
            # A transient script failure (e.g. a momentary timeout) should
            # never kill the background loop -- the next tick just tries
            # again, and every route reading this snapshot falls back to
            # the last-good one (or a direct call if there's genuinely
            # never been one yet).
            logger.exception("Background snapshot refresh failed; will retry next tick")
        await asyncio.sleep(DASHBOARD_REFRESH_INTERVAL_SECONDS)


async def _db_snapshot_loop():
    # Independent of _dashboard_refresh_loop above -- a much longer
    # interval, and writes to the DB itself (via a real ORM Session) rather
    # than spawning a subprocess, so it doesn't share cli_wrapper's
    # _script_lock/cache machinery at all.
    while True:
        try:
            db = SessionLocal()
            try:
                await asyncio.to_thread(health.write_db_stat_snapshot, db)
            finally:
                db.close()
        except Exception:
            # Same fail-soft stance as _dashboard_refresh_loop -- a
            # transient DB hiccup should never kill the loop; the next
            # tick just tries again, leaving a gap in the time series
            # rather than crashing the whole app.
            logger.exception("DB stat snapshot write failed; will retry next tick")
        await asyncio.sleep(DB_SNAPSHOT_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        bootstrap_admin(db)
        ensure_bootstrap_admin_flag(db)
        # Covers the fresh-install case: init_db() (above) already ran
        # this once as part of its own RBAC seeding, but on a brand-new
        # database that first call was necessarily a no-op -- the bootstrap
        # account didn't exist yet until bootstrap_admin() just created it.
        # See db.py's promote_bootstrap_admin_to_super_admin docstring.
        promote_bootstrap_admin_to_super_admin(db)
        # Load the DB-backed settings override (Settings page) into the
        # in-process cache templates/mailer.py/auth.py actually read, then
        # prune the audit log per whatever retention that config specifies.
        # See app_settings.py's docstring for the full env->DB->cache chain.
        refresh_runtime_cache(db)
        prune_audit_log(db)
        prune_db_stat_snapshots(db)
    finally:
        db.close()
    # Kick the City/ASN pick-list build (or a disk-cache load) off in a
    # background thread now rather than waiting for the first admin to
    # open the Users page -- see geo_lists.py's ensure_fresh docstring.
    # Non-blocking either way: a disk cache load is near-instant, and a
    # full rebuild (~100s) just continues in its own thread while the app
    # finishes starting up normally.
    geo_lists.ensure_fresh()
    refresh_task = asyncio.create_task(_dashboard_refresh_loop())
    db_snapshot_task = asyncio.create_task(_db_snapshot_loop())
    try:
        yield
    finally:
        refresh_task.cancel()
        db_snapshot_task.cancel()
        for task in (refresh_task, db_snapshot_task):
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(title="OpenVPN Toolkit Admin", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=settings.SESSION_MAX_AGE_SECONDS,
    session_cookie=settings.SESSION_COOKIE_NAME,
    https_only=settings.SESSION_HTTPS_ONLY,  # set SESSION_HTTPS_ONLY=true in .env once served behind TLS (see docker-compose.yml's traefik service)
)

app.mount("/static", StaticFiles(directory="vpnadmin/static"), name="static")

app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(clients.router)
app.include_router(status.router)
app.include_router(status.dashboard_router)
app.include_router(diagnostics.router)
app.include_router(health.router)
app.include_router(users.router)
app.include_router(geo.router)
app.include_router(teams.router)
app.include_router(settings_routes.router)
app.include_router(roles.router)
app.include_router(me_vpn.router)
app.include_router(openvpn_install.router)
app.include_router(reports.router)


@app.get("/healthz")
def healthz():
    """Unauthenticated liveness check -- for Docker/orchestrator health
    probes, deliberately reveals nothing about the app's internal state."""
    return {"status": "ok"}
