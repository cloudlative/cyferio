"""Covers Settings -> Security's account lockout (already implemented in
routes/auth.py's login_submit, but had zero test coverage): after
account_lockout_threshold consecutive failed login attempts, the account
is locked for account_lockout_minutes; a threshold of 0 (the default)
disables it entirely; a successful login or password reset clears the
counter/lock."""
from datetime import datetime, timedelta, timezone

from vpnadmin import app_settings
from vpnadmin.models import User

from .conftest import login


class TestAccountLockout:
    def test_disabled_by_default_unlimited_failed_attempts(self, app_client):
        for _ in range(10):
            r = app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})
            assert r.status_code == 401
        # Still not locked -- the real password works.
        r = login(app_client, "viewer", "viewerpass123")
        assert r.status_code == 200

    def test_locks_after_threshold_and_rejects_correct_password_while_locked(self, app_client, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "account_lockout_threshold", 3)
        monkeypatch.setattr(app_settings.runtime, "account_lockout_minutes", 15)

        for _ in range(3):
            r = app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})
            assert r.status_code == 401

        # Locked now -- even the CORRECT password is rejected.
        r = app_client.post("/login", data={"username": "viewer", "password": "viewerpass123"})
        assert r.status_code == 423
        assert "too many failed" in r.text.lower()

    def test_lock_expires_after_the_configured_minutes(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "account_lockout_threshold", 3)
        monkeypatch.setattr(app_settings.runtime, "account_lockout_minutes", 15)
        for _ in range(3):
            app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})

        viewer = db_session.query(User).filter(User.username == "viewer").one()
        assert viewer.locked_until is not None
        # Simulate the lock window having already elapsed.
        viewer.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        db_session.commit()

        r = login(app_client, "viewer", "viewerpass123")
        assert r.status_code == 200

    def test_successful_login_resets_the_failed_counter(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "account_lockout_threshold", 3)
        monkeypatch.setattr(app_settings.runtime, "account_lockout_minutes", 15)

        app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})
        app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})
        r = login(app_client, "viewer", "viewerpass123")
        assert r.status_code == 200

        viewer = db_session.query(User).filter(User.username == "viewer").one()
        assert viewer.failed_login_attempts == 0
        assert viewer.locked_until is None

        # The counter genuinely reset, not just cosmetically -- 2 more
        # wrong attempts (which alone wouldn't have hit a threshold of 3
        # from a fresh count) still don't lock the account.
        app_client.post("/logout")
        app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})
        app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})
        r = login(app_client, "viewer", "viewerpass123")
        assert r.status_code == 200

    def test_admin_password_reset_clears_an_active_lock(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "account_lockout_threshold", 3)
        monkeypatch.setattr(app_settings.runtime, "account_lockout_minutes", 15)
        for _ in range(3):
            app_client.post("/login", data={"username": "viewer", "password": "wrongpass"})
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        assert viewer.locked_until is not None

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{viewer.id}", json={"password": "AdminSetPass1!"})
        assert r.status_code == 200

        app_client.post("/logout")
        # The forced-reset flag from the admin password reset means the
        # very next login must succeed and reach /change-password, not be
        # blocked by a stale lock.
        r = login(app_client, "viewer", "AdminSetPass1!")
        assert r.status_code == 200

    def test_settings_expose_and_validate_the_thresholds(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"account_lockout_threshold": 5, "account_lockout_minutes": 30})
        assert r.status_code == 200
        body = r.json()
        assert body["account_lockout_threshold"] == 5
        assert body["account_lockout_minutes"] == 30

        r = app_client.patch("/api/settings", json={"account_lockout_minutes": 0})
        assert r.status_code == 422
