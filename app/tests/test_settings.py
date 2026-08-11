"""Tests for the admin-only Settings page (branding/SMTP/security/audit
retention) -- routes/settings.py, app_settings.py, and mailer.py's
send_test_email path."""
import smtplib

import pytest

import vpnadmin.routes.settings as settings_mod
from vpnadmin.app_settings import SMTP_PASSWORD_PLACEHOLDER, runtime as runtime_settings

from .conftest import login


class TestGetSettings:
    def test_admin_can_view_settings(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/settings")
        assert r.status_code == 200
        body = r.json()
        assert body["app_name"] == "OpenVPN Toolkit"
        assert body["smtp_configured"] is False
        assert body["smtp_password"] == ""  # nothing set yet

    def test_viewer_cannot_view_settings(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/settings")
        assert r.status_code == 403

    def test_unauthenticated_cannot_view_settings(self, app_client):
        r = app_client.get("/api/settings")
        assert r.status_code == 401


class TestUpdateSettings:
    def test_admin_can_update_branding(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"app_name": "Acme VPN"})
        assert r.status_code == 200
        assert r.json()["app_name"] == "Acme VPN"
        assert runtime_settings.app_name == "Acme VPN"  # in-process cache refreshed immediately

    def test_viewer_cannot_update_settings(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/settings", json={"app_name": "Nope"})
        assert r.status_code == 403

    def test_blank_app_name_falls_back_to_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"app_name": "Acme VPN"})
        r = app_client.patch("/api/settings", json={"app_name": None})
        assert r.status_code == 200
        assert r.json()["app_name"] == "OpenVPN Toolkit"

    def test_invalid_smtp_port_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"smtp_port": 99999})
        assert r.status_code == 422

    def test_invalid_from_address_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"smtp_from": "not-an-email"})
        assert r.status_code == 422

    def test_username_without_host_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"smtp_username": "someone"})
        assert r.status_code == 400
        assert "host is required" in r.json()["detail"].lower()

    def test_min_password_length_out_of_range_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"min_password_length": 2})
        assert r.status_code == 422

    def test_negative_audit_retention_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"audit_retention_days": -5})
        assert r.status_code == 422

    def test_password_masked_in_response_not_overwritten_by_placeholder(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"smtp_host": "smtp.example.com", "smtp_password": "hunter2"})
        assert r.status_code == 200
        assert r.json()["smtp_password"] == SMTP_PASSWORD_PLACEHOLDER
        assert runtime_settings.smtp_password == "hunter2"

        # Sending the placeholder back (as the UI does when the field is
        # untouched) must NOT overwrite the real password with the literal
        # placeholder string.
        r = app_client.patch("/api/settings", json={"smtp_password": SMTP_PASSWORD_PLACEHOLDER})
        assert r.status_code == 200
        assert runtime_settings.smtp_password == "hunter2"

    def test_password_can_be_cleared_explicitly(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"smtp_host": "smtp.example.com", "smtp_password": "hunter2"})
        app_client.patch("/api/settings", json={"smtp_password": ""})
        assert runtime_settings.smtp_password == ""

    def test_password_length_setting_affects_new_user_validation(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"min_password_length": 12})
        assert r.status_code == 200

        r = app_client.post("/api/users", json={
            "username": "shortpw", "password": "short123", "first_name": "Short",
            "email": "shortpw@example.com",
        })
        assert r.status_code == 422

        r = app_client.post("/api/users", json={
            "username": "longenough", "password": "longenoughpassword", "first_name": "Long",
            "email": "longenough@example.com",
        })
        assert r.status_code == 201

    def test_settings_change_audit_logged(self, app_client, db_session):
        from vpnadmin.models import AuditLog

        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"app_name": "Acme VPN"})
        entry = db_session.query(AuditLog).filter(AuditLog.action == "update_settings").one()
        assert entry.username == "admin"


class TestSmtpTestEmail:
    def test_success_path(self, app_client, monkeypatch):
        sent = {}

        def fake_send(*, to_address, host, port, username, password, from_address, use_tls):
            sent.update(to_address=to_address, host=host, port=port)

        monkeypatch.setattr(settings_mod.mailer, "send_test_email", fake_send)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/settings/smtp/test", json={
            "email": "me@example.com", "smtp_host": "smtp.example.com", "smtp_port": 587,
        })
        assert r.status_code == 200
        assert sent == {"to_address": "me@example.com", "host": "smtp.example.com", "port": 587}

    def test_failure_surfaces_smtp_error_reason(self, app_client, monkeypatch):
        def fake_send(**kwargs):
            raise smtplib.SMTPAuthenticationError(535, b"Authentication failed")

        monkeypatch.setattr(settings_mod.mailer, "send_test_email", fake_send)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/settings/smtp/test", json={
            "email": "me@example.com", "smtp_host": "smtp.example.com",
        })
        assert r.status_code == 502
        assert "authentication failed" in r.json()["detail"].lower()

    def test_missing_host_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/settings/smtp/test", json={"email": "me@example.com", "smtp_host": ""})
        assert r.status_code == 422

    def test_invalid_destination_email_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/settings/smtp/test", json={"email": "nope", "smtp_host": "smtp.example.com"})
        assert r.status_code == 422

    def test_placeholder_password_substitutes_saved_password(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"smtp_host": "smtp.example.com", "smtp_password": "realpass"})

        seen = {}

        def fake_send(*, to_address, host, port, username, password, from_address, use_tls):
            seen["password"] = password

        monkeypatch.setattr(settings_mod.mailer, "send_test_email", fake_send)
        r = app_client.post("/api/settings/smtp/test", json={
            "email": "me@example.com", "smtp_host": "smtp.example.com",
            "smtp_password": SMTP_PASSWORD_PLACEHOLDER,
        })
        assert r.status_code == 200
        assert seen["password"] == "realpass"

    def test_viewer_cannot_test_smtp(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/settings/smtp/test", json={"email": "me@example.com", "smtp_host": "smtp.example.com"})
        assert r.status_code == 403

    def test_test_email_does_not_persist_settings(self, app_client, monkeypatch):
        monkeypatch.setattr(settings_mod.mailer, "send_test_email", lambda **kw: None)
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/settings/smtp/test", json={
            "email": "me@example.com", "smtp_host": "not-saved.example.com",
        })
        assert runtime_settings.smtp_host == ""  # unaffected -- dry run only
