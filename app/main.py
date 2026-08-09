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

from vpnadmin import cli_wrapper
from vpnadmin.app_settings import prune_audit_log, refresh_runtime_cache
from vpnadmin.auth import bootstrap_admin, ensure_bootstrap_admin_flag
from vpnadmin.config import settings
from vpnadmin.db import SessionLocal, init_db
from vpnadmin.routes import auth, clients, diagnostics, health, pages, settings as settings_routes, status, teams, users

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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        bootstrap_admin(db)
        ensure_bootstrap_admin_flag(db)
        # Load the DB-backed settings override (Settings page) into the
        # in-process cache templates/mailer.py/auth.py actually read, then
        # prune the audit log per whatever retention that config specifies.
        # See app_settings.py's docstring for the full env->DB->cache chain.
        refresh_runtime_cache(db)
        prune_audit_log(db)
    finally:
        db.close()
    refresh_task = asyncio.create_task(_dashboard_refresh_loop())
    try:
        yield
    finally:
        refresh_task.cancel()
        try:
            await refresh_task
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
app.include_router(teams.router)
app.include_router(settings_routes.router)


@app.get("/healthz")
def healthz():
    """Unauthenticated liveness check -- for Docker/orchestrator health
    probes, deliberately reveals nothing about the app's internal state."""
    return {"status": "ok"}
