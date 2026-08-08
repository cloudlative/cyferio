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

from vpnadmin.auth import bootstrap_admin
from vpnadmin.config import settings
from vpnadmin.db import SessionLocal, init_db
from vpnadmin.routes import auth, clients, diagnostics, pages, status, teams, users


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        bootstrap_admin(db)
    finally:
        db.close()
    yield


app = FastAPI(title="OpenVPN Toolkit Admin", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=settings.SESSION_MAX_AGE_SECONDS,
    session_cookie=settings.SESSION_COOKIE_NAME,
    https_only=False,  # set True once served behind TLS (e.g. the planned Traefik front-end)
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


@app.get("/healthz")
def healthz():
    """Unauthenticated liveness check -- for Docker/orchestrator health
    probes, deliberately reveals nothing about the app's internal state."""
    return {"status": "ok"}
