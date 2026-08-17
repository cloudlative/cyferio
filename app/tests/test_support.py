"""Tests for the Contact Support form (routes/support.py) -- FAQ page's
"Contact Support" flow that emails an admin with Reply-To set back to the
requester."""
import vpnadmin.routes.support as support_mod
from vpnadmin.app_settings import runtime as runtime_settings
from vpnadmin.models import User

from .conftest import login


def _configure_smtp(monkeypatch):
    monkeypatch.setattr(runtime_settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(runtime_settings, "admin_notification_email", "admin-inbox@example.com")


class TestSupportPage:
    def test_requires_login(self, app_client):
        r = app_client.get("/support", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_loads_for_logged_in_user(self, app_client, db_session):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/support")
        assert r.status_code == 200
        assert 'value="admin@example.com"' in r.text

    def test_warns_when_no_email_on_file(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/support")
        assert r.status_code == 200
        assert "no email address on file" in r.text.lower()


class TestSubmitSupportRequest:
    def test_no_email_on_file_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "Help", "message": "Something is wrong."})
        assert r.status_code == 400
        assert "no email address on file" in r.json()["detail"].lower()

    def test_empty_subject_rejected(self, app_client, db_session):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "   ", "message": "Something is wrong."})
        assert r.status_code == 422

    def test_empty_message_rejected(self, app_client, db_session):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "Help", "message": ""})
        assert r.status_code == 422

    def test_oversized_subject_rejected(self, app_client, db_session):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "x" * 201, "message": "Something is wrong."})
        assert r.status_code == 422

    def test_oversized_message_rejected(self, app_client, db_session):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "Help", "message": "x" * 5001})
        assert r.status_code == 422

    def test_smtp_not_configured_returns_400(self, app_client, db_session):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "Help", "message": "Something is wrong."})
        assert r.status_code == 400
        assert "isn't configured" in r.json()["detail"].lower() or "not available" in r.json()["detail"].lower()

    def test_no_support_address_returns_400(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        monkeypatch.setattr(runtime_settings, "smtp_host", "smtp.example.com")
        monkeypatch.setattr(runtime_settings, "admin_notification_email", None)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "Help", "message": "Something is wrong."})
        assert r.status_code == 400

    def test_success_path_sends_mail_with_reply_to(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        admin.first_name = "Admin"
        db_session.commit()
        _configure_smtp(monkeypatch)

        sent = {}

        def fake_send(*, requester_name, requester_username, requester_email, subject, message, submitted_at):
            sent.update(
                requester_name=requester_name, requester_username=requester_username,
                requester_email=requester_email, subject=subject, message=message,
            )

        monkeypatch.setattr(support_mod.mailer, "send_support_request", fake_send)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "VPN Connection Issue", "message": "It won't connect."})
        assert r.status_code == 200
        assert "submitted successfully" in r.json()["message"].lower()
        assert sent["requester_email"] == "admin@example.com"
        assert sent["requester_username"] == "admin"
        assert sent["subject"] == "VPN Connection Issue"
        assert sent["message"] == "It won't connect."

    def test_send_failure_returns_502(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        _configure_smtp(monkeypatch)

        def fake_send(**kwargs):
            raise ConnectionRefusedError("smtp down")

        monkeypatch.setattr(support_mod.mailer, "send_support_request", fake_send)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/support", json={"subject": "Help", "message": "Something is wrong."})
        assert r.status_code == 502

    def test_rate_limit_enforced(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        _configure_smtp(monkeypatch)
        monkeypatch.setattr(support_mod.mailer, "send_support_request", lambda **kwargs: None)
        login(app_client, "admin", "adminpass123")

        for i in range(support_mod.SUPPORT_REQUEST_RATE_LIMIT):
            r = app_client.post("/api/support", json={"subject": f"Request {i}", "message": "Something is wrong."})
            assert r.status_code == 200

        r = app_client.post("/api/support", json={"subject": "One too many", "message": "Something is wrong."})
        assert r.status_code == 429

    def test_success_is_audit_logged(self, app_client, db_session, monkeypatch):
        from vpnadmin.models import AuditLog

        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        _configure_smtp(monkeypatch)
        monkeypatch.setattr(support_mod.mailer, "send_support_request", lambda **kwargs: None)
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/support", json={"subject": "Billing Question", "message": "Something is wrong."})

        entry = db_session.query(AuditLog).filter(AuditLog.action == "support_request_submitted").order_by(AuditLog.id.desc()).first()
        assert entry is not None
        assert entry.username == "admin"
        assert entry.target == "Billing Question"
        assert entry.success is True

    def test_requires_login(self, app_client):
        r = app_client.post("/api/support", json={"subject": "Help", "message": "Something is wrong."})
        assert r.status_code == 401


class TestSettingsPageRenders:
    """Catches Jinja/markup errors in settings.html's updated Admin /
    Support Contact Email field -- no prior test touched this page's
    render at all."""

    def test_settings_page_loads_for_admin(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/settings")
        assert r.status_code == 200
        assert "s-admin-notify-email" in r.text
