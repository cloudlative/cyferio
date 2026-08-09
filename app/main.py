"""
OpenVPN Toolkit web app -- entrypoint.

Run directly with:
    uvicorn main:app --host 0.0.0.0 --port 8000
or via the Dockerfile's CMD.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from vpnadmin.app_settings import prune_audit_log, refresh_runtime_cache
from vpnadmin.auth import bootstrap_admin, ensure_bootstrap_admin_flag
from vpnadmin.config import settings
from vpnadmin.db import SessionLocal, init_db
from vpnadmin.routes import auth, clients, diagnostics, pages, settings as settings_routes, status, teams, users


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
    yield


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
app.include_router(users.router)
app.include_router(teams.router)
app.include_router(settings_routes.router)


@app.get("/healthz")
def healthz():
    """Unauthenticated liveness check -- for Docker/orchestrator health
    probes, deliberately reveals nothing about the app's internal state."""
    return {"status": "ok"}
