"""Tests for the admin-only Settings page (branding/security/audit
retention) -- routes/settings.py, app_settings.py. Outbound email
provider configuration/testing moved to routes/email_providers.py --
see tests/test_email_providers.py for that."""
from vpnadmin.app_settings import runtime as runtime_settings

from .conftest import login


class TestGetSettings:
    def test_admin_can_view_settings(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/settings")
        assert r.status_code == 200
        body = r.json()
        assert "app_name" not in body
        assert "app_tagline" not in body
        assert "app_footer_credit" not in body
        # SMTP fields moved to /api/email-providers -- no longer part of
        # this response at all.
        assert "smtp_host" not in body
        assert "smtp_password" not in body
        assert "smtp_configured" not in body

    def test_viewer_cannot_view_settings(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/settings")
        assert r.status_code == 403

    def test_unauthenticated_cannot_view_settings(self, app_client):
        r = app_client.get("/api/settings")
        assert r.status_code == 401


class TestUpdateSettings:
    def test_admin_can_update_portal_url(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"portal_url": "https://vpn.example.com"})
        assert r.status_code == 200
        assert r.json()["portal_url"] == "https://vpn.example.com"
        assert runtime_settings.portal_url == "https://vpn.example.com"  # in-process cache refreshed immediately

    def test_viewer_cannot_update_settings(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/settings", json={"portal_url": "https://nope.example.com"})
        assert r.status_code == 403

    def test_blank_portal_url_falls_back_to_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"portal_url": "https://vpn.example.com"})
        r = app_client.patch("/api/settings", json={"portal_url": None})
        assert r.status_code == 200
        assert r.json()["portal_url"] is None  # no APP_DOMAIN set in the test env, so no fallback either

    def test_min_password_length_out_of_range_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"min_password_length": 2})
        assert r.status_code == 422

    def test_negative_audit_retention_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"audit_retention_days": -5})
        assert r.status_code == 422

    def test_password_length_setting_affects_new_user_validation(self, app_client, db_session, monkeypatch):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"min_password_length": 12})
        assert r.status_code == 200

        r = app_client.post("/api/users", json={
            "username": "shortpw", "password": "short123", "first_name": "Short",
            "email": "shortpw@example.com", "mac": "aa:bb:cc:dd:ee:ff",
        })
        assert r.status_code == 422

        r = app_client.post("/api/users", json={
            "username": "longenough", "password": "Longenoughpassword123!", "first_name": "Long",
            "email": "longenough@example.com", "mac": "aa:bb:cc:dd:ee:ff",
        })
        assert r.status_code == 201

    def test_settings_change_audit_logged(self, app_client, db_session):
        from vpnadmin.models import AuditLog

        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"portal_url": "https://vpn.example.com"})
        entry = db_session.query(AuditLog).filter(AuditLog.action == "update_settings").one()
        assert entry.username == "admin"


class TestGeoipSettings:
    """MaxMind GeoIP -- see features.py / routes/settings.py's geoip
    endpoints. Doesn't exercise /api/settings/geoip/refresh's actual host
    action (needs HOST_SSH_TARGET + a real/mocked SSH round-trip, out of
    scope for these unit tests) -- just the DB-round-trip half."""

    def test_enabling_without_a_key_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"geoip_enabled": True})
        assert r.status_code == 400

    def test_key_round_trips_masked(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"maxmind_license_key": "test-fixture-0000000000"})
        assert r.status_code == 200
        assert r.json()["maxmind_license_key"] == "••••••••"

    def test_placeholder_leaves_existing_key_unchanged(self, app_client, db_session):
        from vpnadmin.models import AppSettings

        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"maxmind_license_key": "test-fixture-0000000000"})
        r = app_client.patch("/api/settings", json={"maxmind_license_key": "••••••••", "portal_url": "https://vpn.example.com"})
        assert r.status_code == 200
        row = db_session.query(AppSettings).one()
        assert row.maxmind_license_key == "test-fixture-0000000000"

    def test_malformed_key_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"maxmind_license_key": "short"})
        assert r.status_code == 422

    def test_enable_with_key_in_same_request_succeeds(self, app_client, db_session):
        from vpnadmin.models import AppSettings

        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={
            "geoip_enabled": True, "maxmind_license_key": "test-fixture-0000000000",
        })
        assert r.status_code == 200
        row = db_session.query(AppSettings).one()
        assert row.geoip_enabled is True


class TestCaptchaSettings:
    def test_provider_without_keys_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"captcha_provider": "turnstile"})
        assert r.status_code == 400

    def test_turnstile_with_keys_saved(self, app_client, db_session):
        from vpnadmin.models import AppSettings

        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={
            "captcha_provider": "turnstile",
            "turnstile_site_key": "site123", "turnstile_secret_key": "secret123",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["captcha_provider"] == "turnstile"
        assert body["turnstile_site_key"] == "site123"  # site key is public, never masked
        assert body["turnstile_secret_key"] == "••••••••"
        row = db_session.query(AppSettings).one()
        assert row.turnstile_secret_key == "secret123"

    def test_invalid_provider_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"captcha_provider": "not-a-real-provider"})
        assert r.status_code == 422

    def test_disabling_captcha_with_blank_string(self, app_client, db_session):
        from vpnadmin.models import AppSettings

        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={
            "captcha_provider": "turnstile",
            "turnstile_site_key": "site123", "turnstile_secret_key": "secret123",
        })
        r = app_client.patch("/api/settings", json={"captcha_provider": ""})
        assert r.status_code == 200
        assert r.json()["captcha_provider"] == ""
        row = db_session.query(AppSettings).one()
        assert row.captcha_provider is None

    def test_secret_key_placeholder_preserved_on_provider_resave(self, app_client, db_session):
        from vpnadmin.models import AppSettings

        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={
            "captcha_provider": "turnstile",
            "turnstile_site_key": "site123", "turnstile_secret_key": "secret123",
        })
        # Re-save with the site key changed but the secret key round-tripped
        # as the masked placeholder (exactly what the Settings page's own
        # JS does when a secret field is left untouched).
        r = app_client.patch("/api/settings", json={
            "captcha_provider": "turnstile",
            "turnstile_site_key": "site456", "turnstile_secret_key": "••••••••",
        })
        assert r.status_code == 200
        row = db_session.query(AppSettings).one()
        assert row.turnstile_site_key == "site456"
        assert row.turnstile_secret_key == "secret123"
