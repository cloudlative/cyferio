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
