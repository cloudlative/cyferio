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


class TestCaptchaTestEndpoint:
    """/api/settings/captcha/test -- regression coverage for a real bug
    found live: this used to test whatever provider/secret was already
    SAVED (or, if nothing was ever saved, the env-var fallback), not the
    provider/secret actually in the request body. On a box with working
    Turnstile env-var credentials, typing a dummy reCAPTCHA secret and
    clicking Test reported "turnstile is reachable and the secret key is
    accepted" -- true, but not what was tested. See captcha.py's
    diagnostic_check() and this route's own docstrings for the fix."""

    def test_tests_the_given_provider_not_the_saved_one(self, app_client, monkeypatch):
        # Turnstile is the actually-saved/active provider (with a real,
        # working secret) -- but the request body asks to test reCAPTCHA
        # with a dummy secret. The result must reflect reCAPTCHA, not
        # silently re-test the already-working Turnstile config.
        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={
            "captcha_provider": "turnstile",
            "turnstile_site_key": "site123", "turnstile_secret_key": "real-working-secret",
        })

        import json

        from vpnadmin import captcha

        def boom(req, timeout=10):
            # Simulates a fabricated reCAPTCHA secret: Google always
            # returns 200+JSON with error-codes: ["invalid-input-response"]
            # regardless of secret validity (see diagnostic_check's own
            # docstring) -- so this endpoint must never claim the secret
            # itself was verified for reCAPTCHA.
            class FakeResponse:
                status = 200

                def read(self):
                    return json.dumps({"success": False, "error-codes": ["invalid-input-response"]}).encode()

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return FakeResponse()

        monkeypatch.setattr(captcha.urllib.request, "urlopen", boom)
        r = app_client.post("/api/settings/captcha/test", json={
            "provider": "recaptcha", "secret_key": "totally-fake-dummy-value",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "recaptcha"
        assert body["secret_verifiable"] is False

    def test_masked_secret_falls_back_to_that_providers_own_saved_value(self, app_client, monkeypatch):
        # A blank/masked secret_key means "test whatever's already saved
        # for the GIVEN provider" -- not the active provider, and not "no
        # secret at all" (which would 400).
        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={
            "captcha_provider": "turnstile",
            "turnstile_site_key": "tsite", "turnstile_secret_key": "tsecret",
            "recaptcha_site_key": "rsite", "recaptcha_secret_key": "rsecret",
        })

        from vpnadmin import captcha

        captured = {}

        def fake_diagnostic_check(*, provider, secret_key):
            captured["provider"] = provider
            captured["secret_key"] = secret_key
            return {"reachable": True, "secret_verifiable": False, "error": None}

        monkeypatch.setattr(captcha, "diagnostic_check", fake_diagnostic_check)
        r = app_client.post("/api/settings/captcha/test", json={"provider": "recaptcha", "secret_key": "••••••••"})
        assert r.status_code == 200
        assert captured["provider"] == "recaptcha"
        assert captured["secret_key"] == "rsecret"

    def test_no_secret_at_all_is_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/settings/captcha/test", json={"provider": "recaptcha"})
        assert r.status_code == 400

    def test_unknown_provider_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/settings/captcha/test", json={"provider": "bogus", "secret_key": "x"})
        assert r.status_code == 422
