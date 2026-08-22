"""
Shared pytest fixtures.

Tests run against an in-memory SQLite DB (never the real DATABASE_URL) and
never invoke the real openvpn-install.sh/vpn-status.py -- cli_wrapper calls
are monkeypatched per-test where needed. No test here requires a real
OpenVPN install or root access.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("USE_SUDO", "false")
os.environ.setdefault("OPENVPN_INSTALL_SCRIPT", "/nonexistent/openvpn-install.sh")
os.environ.setdefault("VPN_STATUS_SCRIPT", "/nonexistent/vpn-status.py")
os.environ.setdefault("TICKET_ATTACHMENTS_DIR", tempfile.mkdtemp(prefix="cyferio-test-ticket-attachments-"))

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
        r.smtp_host = env_settings.SMTP_HOST
        r.smtp_port = env_settings.SMTP_PORT
        r.smtp_username = env_settings.SMTP_USERNAME
        r.smtp_password = env_settings.SMTP_PASSWORD
        r.smtp_from = env_settings.SMTP_FROM
        r.smtp_use_tls = env_settings.SMTP_USE_TLS
        r.min_password_length = 8
        r.session_timeout_minutes = max(1, env_settings.SESSION_MAX_AGE_SECONDS // 60)
        r.audit_retention_days = None
        # Optional integrations (see features.py) -- same leak risk as the
        # fields above, e.g. test_settings.py saving a CAPTCHA/GeoIP config
        # via the real PATCH endpoint must not bleed into an unrelated
        # auth test that expects CAPTCHA disabled and GeoIP degraded.
        r.geoip_enabled = True  # see app_settings.py's own comment on why True, not False, is the "untouched" default
        r.maxmind_license_key = None
        r.captcha_provider = env_settings.CAPTCHA_PROVIDER
        r.turnstile_site_key = env_settings.TURNSTILE_SITE_KEY
        r.turnstile_secret_key = env_settings.TURNSTILE_SECRET_KEY
        r.recaptcha_site_key = env_settings.RECAPTCHA_SITE_KEY
        r.recaptcha_secret_key = env_settings.RECAPTCHA_SECRET_KEY
        # Support Ticketing System -- same leak risk as everything above
        # (test_settings.py's TestMacDuplicationPolicy-style tests PATCH
        # these via the real endpoint).
        r.support_ticket_rate_limit_count = 5
        r.support_ticket_rate_limit_window_minutes = 60
        r.support_max_attachment_size_mb = 10
        r.support_max_attachments_per_message = 5
        r.notify_admin_on_ticket_created = False
        # Release Availability Indicator/Popup -- same leak risk (test_
        # release_check.py/test_settings.py save these via the real PATCH
        # endpoint or by mutating the row directly).
        r.release_check_enabled = True
        r.release_check_interval_minutes = 60
        r.release_check_critical_major_bump = True
        r.github_repo = env_settings.RELEASE_CHECK_REPO
        r.last_release_notified_tag = None
        # VPN Device Availability Monitoring & Offline Alert Notifications --
        # same leak risk as everything above (test_device_monitoring.py/
        # test_settings.py save these via the real PATCH endpoint).
        r.device_monitoring_check_interval_minutes = 5
        r.device_monitoring_default_offline_threshold_minutes = 15
        r.device_monitoring_default_cooldown_minutes = 60
        r.device_monitoring_default_recovery_notify = True

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


@pytest.fixture(autouse=True)
def _reset_release_check_cache():
    """release_check.py's in-process `_cache` dict (see that module's own
    docstring) would otherwise leak between tests the same way
    cli_wrapper's cache would -- e.g. a test asserting a "critical_update"
    classification followed by one expecting a fresh "never checked" state
    could see the first test's cached result instead of a real recheck."""
    from vpnadmin import release_check
    release_check.reset_cache()
    yield
    release_check.reset_cache()


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

    # Single-group/single-role permissions: role= (the legacy enum, above)
    # and the role_id it backfills (via models.py's _default_role_id_from_
    # legacy_role listener) are no longer consulted for permission checks
    # at all -- see permissions.py's effective_role_ids. Without an actual
    # group+role, "admin" and "viewer" here would each have ZERO effective
    # permissions, and every require_permission-gated route in every test
    # using this fixture would 403. Unlike production startup (db.py's
    # _seed_rbac / main.py's lifespan), which resolves this via the
    # migrate_groups_and_users_to_single_assignment() migration for an
    # UPGRADING deployment's pre-existing data, this fixture is building a
    # brand-new test database from scratch every time -- there's no
    # legacy data to migrate, so it creates the two groups it needs
    # directly, same as any other test would.
    from vpnadmin.models import Group, RoleDef

    admin_role = db_session.query(RoleDef).filter_by(slug="admin").one()
    viewer_role = db_session.query(RoleDef).filter_by(slug="viewer").one()
    admin_group = Group(name="Admins", slug="admins", role_id=admin_role.id)
    viewer_group = Group(name="Viewers", slug="viewers", role_id=viewer_role.id)
    db_session.add_all([admin_group, viewer_group])
    db_session.flush()

    admin = User(username="admin", password_hash=hash_password("adminpass123"), role=Role.admin, group_id=admin_group.id)
    viewer = User(username="viewer", password_hash=hash_password("viewerpass123"), role=Role.viewer, group_id=viewer_group.id)
    db_session.add_all([admin, viewer])
    db_session.commit()

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password})


@pytest.fixture()
def default_group_id(db_session):
    """A ready-made, role-bearing Group id for tests that create a user via
    POST /api/users but don't care which group they land in -- group_id is
    now mandatory on that endpoint (see routes/users.py's
    CreateUserRequest), so every test exercising create_user() needs a
    real one. Saves every such test from constructing its own throwaway
    Group just to satisfy that requirement."""
    from vpnadmin.models import Group, RoleDef

    role = db_session.query(RoleDef).filter_by(slug="user").one()
    group = Group(name="Default Test Group", role_id=role.id)
    db_session.add(group)
    db_session.commit()
    return group.id
