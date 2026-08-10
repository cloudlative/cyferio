"""
Shared pytest fixtures.

Tests run against an in-memory SQLite DB (never the real DATABASE_URL) and
never invoke the real openvpn-install.sh/vpn-status.py -- cli_wrapper calls
are monkeypatched per-test where needed. No test here requires a real
OpenVPN install or root access.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("USE_SUDO", "false")
os.environ.setdefault("OPENVPN_INSTALL_SCRIPT", "/nonexistent/openvpn-install.sh")
os.environ.setdefault("VPN_STATUS_SCRIPT", "/nonexistent/vpn-status.py")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from vpnadmin.auth import hash_password
from vpnadmin.db import Base
from vpnadmin.models import Role, User


@pytest.fixture(autouse=True)
def _reset_runtime_settings():
    """app_settings.runtime is a module-level singleton (see app_settings.py)
    mutated in place by refresh_runtime_cache() -- including via the real
    lifespan startup every app_client fixture triggers, and directly by the
    Settings API routes during tests that exercise them. Reset it to pure
    env-var defaults before and after every test so a settings change made
    in one test can never leak into an unrelated one, regardless of
    whichever DB/connection-pool path happened to touch it."""
    from vpnadmin import app_settings
    from vpnadmin.config import settings as env_settings

    def _reset():
        r = app_settings.runtime
        r.app_name = env_settings.APP_NAME
        r.app_tagline = env_settings.APP_TAGLINE
        r.app_footer_credit = env_settings.APP_FOOTER_CREDIT
        r.smtp_host = env_settings.SMTP_HOST
        r.smtp_port = env_settings.SMTP_PORT
        r.smtp_username = env_settings.SMTP_USERNAME
        r.smtp_password = env_settings.SMTP_PASSWORD
        r.smtp_from = env_settings.SMTP_FROM
        r.smtp_use_tls = env_settings.SMTP_USE_TLS
        r.min_password_length = 8
        r.session_timeout_minutes = max(1, env_settings.SESSION_MAX_AGE_SECONDS // 60)
        r.audit_retention_days = None

    _reset()
    yield
    _reset()


@pytest.fixture(autouse=True)
def _clear_cli_wrapper_cache():
    """cli_wrapper caches read-only script results for a few seconds (see
    its own docstring) to avoid redundant subprocess spawns in production.
    That module-level cache would otherwise leak between tests -- e.g. a
    test asserting list_clients() succeeds, followed immediately by one
    asserting it raises on a non-zero exit, could see the first test's
    cached success instead of actually re-invoking the (differently)
    mocked subprocess.run. Clear it before and after every test."""
    from vpnadmin import cli_wrapper
    cli_wrapper._cache.clear()
    yield
    cli_wrapper._cache.clear()


@pytest.fixture()
def db_session():
    """A fresh in-memory SQLite DB per test -- fast, isolated, no shared state.
    StaticPool is required here: a plain sqlite:///:memory: engine hands out
    a brand new (empty) in-memory database on every new connection, so
    without pinning all checkouts to one shared connection, code running in
    a different thread (e.g. FastAPI's run_in_threadpool for sync routes)
    would silently see an empty, table-less database."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    # Dynamic-RBAC role seeding (see permissions.py's seed_system_roles) --
    # production gets this from db.init_db()'s _seed_rbac() on every
    # startup, but this fixture builds its schema straight from
    # Base.metadata rather than going through init_db(), so it has to be
    # called explicitly here too. Without it, every require_permission
    # check in the app fails closed (no RoleDef rows to match against),
    # regardless of what any test user's role_id/legacy role is set to.
    from vpnadmin.permissions import seed_system_roles
    seed_system_roles(session)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def app_client(db_session, monkeypatch):
    """A FastAPI TestClient wired to the in-memory db_session instead of the
    real database, with an admin and a viewer user pre-created."""
    from fastapi.testclient import TestClient

    from main import app
    from vpnadmin.db import get_db

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    admin = User(username="admin", password_hash=hash_password("adminpass123"), role=Role.admin)
    viewer = User(username="viewer", password_hash=hash_password("viewerpass123"), role=Role.viewer)
    db_session.add_all([admin, viewer])
    db_session.commit()

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})
