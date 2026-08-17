"""Tests for the multi-provider Outbound Email system:
- email_providers.py: the SMTP/Resend provider implementations themselves
  (unit-level, smtplib/urllib mocked -- no network).
- mailer.py's _resolve_default_provider/_send: DB-backed default-provider
  resolution.
- routes/email_providers.py: CRUD, single-default enforcement, delete/
  disable guards, per-profile test-send.
- app_settings.migrate_legacy_smtp_provider: the one-time backwards-
  compatibility backfill.
"""
import json
import smtplib
import urllib.error

import pytest

import vpnadmin.routes.email_providers as ep_mod
from vpnadmin import email_providers, mailer
from vpnadmin.app_settings import migrate_legacy_smtp_provider
from vpnadmin.config import settings as env_settings
from vpnadmin.models import EmailProvider

from .conftest import login


# --------------------------------------------------------------------------
# email_providers.py -- provider implementations, unit-level
# --------------------------------------------------------------------------

class TestSMTPProviderValidateConfig:
    def test_missing_host_rejected(self):
        with pytest.raises(email_providers.ProviderConfigError, match="Host"):
            email_providers.PROVIDERS["smtp"].validate_config({"port": 587, "from_email": "a@example.com"})

    def test_missing_from_email_rejected(self):
        with pytest.raises(email_providers.ProviderConfigError, match="From Email"):
            email_providers.PROVIDERS["smtp"].validate_config({"host": "smtp.example.com", "port": 587})

    def test_username_password_optional(self):
        cleaned = email_providers.PROVIDERS["smtp"].validate_config({
            "host": "smtp.example.com", "port": 587, "from_email": "a@example.com",
        })
        assert cleaned["username"] is None
        assert cleaned["password"] is None


class TestSMTPProviderSend:
    def test_starttls_path(self, monkeypatch):
        calls = []

        class FakeSMTP:
            def __init__(self, host, port, timeout):
                calls.append(("connect", host, port))

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self, context=None):
                calls.append(("starttls",))

            def login(self, username, password):
                calls.append(("login", username, password))

            def send_message(self, msg):
                calls.append(("send", msg["To"], msg["Subject"]))

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        provider = email_providers.PROVIDERS["smtp"]
        config = {"host": "smtp.example.com", "port": 587, "username": "user", "password": "pass", "encryption": "starttls", "from_email": "a@example.com"}
        message = email_providers.OutboundMessage(to_address="you@example.com", subject="Hi", text_body="Hello")
        provider.send(config=config, message=message)
        assert ("connect", "smtp.example.com", 587) in calls
        assert ("starttls",) in calls
        assert ("login", "user", "pass") in calls
        assert ("send", "you@example.com", "Hi") in calls

    def test_ssl_path_uses_smtp_ssl(self, monkeypatch):
        calls = []

        class FakeSMTPSSL:
            def __init__(self, host, port, timeout, context):
                calls.append(("connect_ssl", host, port))

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def login(self, username, password):
                pass

            def send_message(self, msg):
                calls.append(("send",))

        monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)
        provider = email_providers.PROVIDERS["smtp"]
        config = {"host": "smtp.example.com", "port": 465, "encryption": "ssl", "from_email": "a@example.com"}
        message = email_providers.OutboundMessage(to_address="you@example.com", subject="Hi", text_body="Hello")
        provider.send(config=config, message=message)
        assert ("connect_ssl", "smtp.example.com", 465) in calls
        assert ("send",) in calls

    def test_send_failure_wrapped_as_provider_send_error(self, monkeypatch):
        class FakeSMTP:
            def __init__(self, *a, **kw):
                raise smtplib.SMTPConnectError(421, "refused")

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        provider = email_providers.PROVIDERS["smtp"]
        config = {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"}
        message = email_providers.OutboundMessage(to_address="you@example.com", subject="Hi", text_body="Hello")
        with pytest.raises(email_providers.ProviderSendError):
            provider.send(config=config, message=message)

    def test_attachment_included(self, monkeypatch):
        captured = {}

        class FakeSMTP:
            def __init__(self, *a, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def send_message(self, msg):
                captured["payload"] = msg.get_payload()

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        provider = email_providers.PROVIDERS["smtp"]
        config = {"host": "smtp.example.com", "port": 587, "encryption": "none", "from_email": "a@example.com"}
        message = email_providers.OutboundMessage(
            to_address="you@example.com", subject="Hi", text_body="Hello",
            attachments=[("client.ovpn", b"config-content", "application/octet-stream")],
        )
        provider.send(config=config, message=message)
        # multipart payload: [0] text body, [1] the attachment
        filenames = [part.get_filename() for part in captured["payload"] if part.get_filename()]
        assert "client.ovpn" in filenames


class TestResendProviderValidateConfig:
    def test_missing_api_key_rejected(self):
        with pytest.raises(email_providers.ProviderConfigError, match="API Key"):
            email_providers.PROVIDERS["resend"].validate_config({"from_email": "a@example.com"})

    def test_malformed_api_key_rejected(self):
        with pytest.raises(email_providers.ProviderConfigError, match="re_"):
            email_providers.PROVIDERS["resend"].validate_config({"api_key": "not-a-real-key", "from_email": "a@example.com"})

    def test_valid_key_shape_accepted(self):
        cleaned = email_providers.PROVIDERS["resend"].validate_config({"api_key": "re_123abc", "from_email": "a@example.com"})
        assert cleaned["api_key"] == "re_123abc"


class TestResendProviderSend:
    def test_success(self, monkeypatch):
        captured = {}

        class FakeResponse:
            def read(self):
                return b'{"id":"abc"}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=15):
            captured["url"] = req.full_url
            captured["headers"] = dict(req.header_items())
            captured["body"] = json.loads(req.data.decode())
            return FakeResponse()

        monkeypatch.setattr(email_providers.urllib.request, "urlopen", fake_urlopen)
        provider = email_providers.PROVIDERS["resend"]
        config = {"api_key": "re_123", "from_email": "a@example.com", "from_name": "Cyferio"}
        message = email_providers.OutboundMessage(to_address="you@example.com", subject="Hi", text_body="Hello", reply_to="reply@example.com")
        provider.send(config=config, message=message)
        assert captured["url"] == "https://api.resend.com/emails"
        assert captured["body"]["to"] == ["you@example.com"]
        assert captured["body"]["reply_to"] == "reply@example.com"
        assert captured["body"]["from"] == "Cyferio <a@example.com>"

    def test_http_error_wrapped(self, monkeypatch):
        import io

        def fake_urlopen(req, timeout=15):
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"message":"Invalid API key"}'))

        monkeypatch.setattr(email_providers.urllib.request, "urlopen", fake_urlopen)
        provider = email_providers.PROVIDERS["resend"]
        config = {"api_key": "re_123", "from_email": "a@example.com"}
        message = email_providers.OutboundMessage(to_address="you@example.com", subject="Hi", text_body="Hello")
        with pytest.raises(email_providers.ProviderSendError, match="Invalid API key"):
            provider.send(config=config, message=message)

    def test_network_error_wrapped(self, monkeypatch):
        def fake_urlopen(req, timeout=15):
            raise urllib.error.URLError("no route to host")

        monkeypatch.setattr(email_providers.urllib.request, "urlopen", fake_urlopen)
        provider = email_providers.PROVIDERS["resend"]
        config = {"api_key": "re_123", "from_email": "a@example.com"}
        message = email_providers.OutboundMessage(to_address="you@example.com", subject="Hi", text_body="Hello")
        with pytest.raises(email_providers.ProviderSendError):
            provider.send(config=config, message=message)


# --------------------------------------------------------------------------
# mailer.py -- default-provider resolution
# --------------------------------------------------------------------------

class TestMailerResolvesDefaultProvider:
    def test_is_configured_false_with_no_rows(self, db_session):
        assert mailer.is_configured(db_session) is False

    def test_is_configured_false_when_default_is_disabled(self, db_session):
        row = EmailProvider(name="P", provider_type="smtp", is_active=False, is_default=True, config="{}")
        db_session.add(row)
        db_session.commit()
        assert mailer.is_configured(db_session) is False

    def test_is_configured_true_with_active_default(self, db_session):
        row = EmailProvider(name="P", provider_type="smtp", is_active=True, is_default=True, config="{}")
        db_session.add(row)
        db_session.commit()
        assert mailer.is_configured(db_session) is True

    def test_send_dispatches_to_default_providers_implementation(self, db_session, monkeypatch):
        config = {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"}
        row = EmailProvider(name="P", provider_type="smtp", is_active=True, is_default=True, config=json.dumps(config))
        db_session.add(row)
        db_session.commit()

        captured = {}
        monkeypatch.setattr(
            email_providers.PROVIDERS["smtp"], "send",
            lambda *, config, message: captured.update(config=config, to=message.to_address),
        )
        message = email_providers.OutboundMessage(to_address="you@example.com", subject="Hi", text_body="Hello")
        mailer._send(db_session, message)
        assert captured["to"] == "you@example.com"
        assert captured["config"]["host"] == "smtp.example.com"

    def test_send_raises_not_configured_with_no_default(self, db_session):
        with pytest.raises(mailer.MailerNotConfigured):
            mailer._send(db_session, email_providers.OutboundMessage(to_address="x@example.com", subject="s", text_body="b"))


# --------------------------------------------------------------------------
# app_settings.migrate_legacy_smtp_provider
# --------------------------------------------------------------------------

class TestMigrateLegacySmtpProvider:
    def test_noop_when_nothing_configured(self, db_session, monkeypatch):
        monkeypatch.setattr(env_settings, "SMTP_HOST", "")
        migrate_legacy_smtp_provider(db_session)
        assert db_session.query(EmailProvider).count() == 0

    def test_creates_default_provider_from_env_settings(self, db_session, monkeypatch):
        monkeypatch.setattr(env_settings, "SMTP_HOST", "smtp.legacy.example.com")
        monkeypatch.setattr(env_settings, "SMTP_PORT", 587)
        monkeypatch.setattr(env_settings, "SMTP_FROM", "legacy@example.com")
        monkeypatch.setattr(env_settings, "SMTP_USE_TLS", True)
        migrate_legacy_smtp_provider(db_session)
        row = db_session.query(EmailProvider).one()
        assert row.is_default is True
        assert row.is_active is True
        assert row.provider_type == "smtp"
        config = json.loads(row.config)
        assert config["host"] == "smtp.legacy.example.com"
        assert config["encryption"] == "starttls"

    def test_noop_when_a_provider_already_exists(self, db_session, monkeypatch):
        monkeypatch.setattr(env_settings, "SMTP_HOST", "smtp.legacy.example.com")
        db_session.add(EmailProvider(name="Existing", provider_type="resend", is_active=True, is_default=True, config="{}"))
        db_session.commit()
        migrate_legacy_smtp_provider(db_session)
        assert db_session.query(EmailProvider).count() == 1
        assert db_session.query(EmailProvider).one().name == "Existing"


# --------------------------------------------------------------------------
# routes/email_providers.py -- CRUD + set-default + test
# --------------------------------------------------------------------------

class TestListProviderTypes:
    def test_returns_registered_types(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/email-providers/types")
        assert r.status_code == 200
        keys = {t["type_key"] for t in r.json()}
        assert keys == {"smtp", "resend"}

    def test_viewer_forbidden(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/email-providers/types")
        assert r.status_code == 403


class TestCreateProvider:
    def test_first_provider_becomes_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/email-providers", json={
            "name": "Primary SMTP", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        })
        assert r.status_code == 200
        assert r.json()["is_default"] is True

    def test_second_provider_not_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/email-providers", json={
            "name": "Primary SMTP", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        })
        r = app_client.post("/api/email-providers", json={
            "name": "Resend Prod", "provider_type": "resend",
            "config": {"api_key": "re_123", "from_email": "b@example.com"},
        })
        assert r.status_code == 200
        assert r.json()["is_default"] is False

    def test_invalid_config_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/email-providers", json={"name": "Bad", "provider_type": "smtp", "config": {}})
        assert r.status_code == 400

    def test_unknown_provider_type_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/email-providers", json={"name": "X", "provider_type": "sendgrid", "config": {}})
        assert r.status_code == 400

    def test_secret_masked_in_response(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/email-providers", json={
            "name": "Resend", "provider_type": "resend",
            "config": {"api_key": "re_supersecret", "from_email": "a@example.com"},
        })
        assert r.status_code == 200
        assert r.json()["config"]["api_key"] != "re_supersecret"

    def test_viewer_forbidden(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/email-providers", json={"name": "X", "provider_type": "smtp", "config": {}})
        assert r.status_code == 403


class TestUpdateProvider:
    def _create(self, app_client, name="P1"):
        r = app_client.post("/api/email-providers", json={
            "name": name, "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "username": "user", "password": "secret1", "from_email": "a@example.com"},
        })
        return r.json()

    def test_rename(self, app_client):
        login(app_client, "admin", "adminpass123")
        row = self._create(app_client)
        r = app_client.patch(f"/api/email-providers/{row['id']}", json={"name": "Renamed", "provider_type": "smtp", "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"}})
        assert r.status_code == 200
        assert r.json()["name"] == "Renamed"

    def test_type_change_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        row = self._create(app_client)
        r = app_client.patch(f"/api/email-providers/{row['id']}", json={"name": row["name"], "provider_type": "resend", "config": {}})
        assert r.status_code == 400

    def test_placeholder_password_keeps_existing_secret(self, app_client, db_session):
        from vpnadmin.app_settings import SMTP_PASSWORD_PLACEHOLDER

        login(app_client, "admin", "adminpass123")
        row = self._create(app_client)
        # Round-trips the masked placeholder (as the real form does when
        # the admin didn't touch the password field) plus a real change to
        # another field -- the secret must survive unchanged.
        r = app_client.patch(f"/api/email-providers/{row['id']}", json={
            "name": "Updated Name", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "username": "user", "password": SMTP_PASSWORD_PLACEHOLDER, "from_email": "a@example.com"},
        })
        assert r.status_code == 200
        saved = db_session.query(EmailProvider).filter(EmailProvider.id == row["id"]).one()
        assert json.loads(saved.config)["password"] == "secret1"

    def test_disabling_the_default_provider_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        row = self._create(app_client)  # first provider -- becomes default
        r = app_client.patch(f"/api/email-providers/{row['id']}", json={
            "name": row["name"], "provider_type": "smtp", "is_active": False,
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        })
        assert r.status_code == 400

    def test_viewer_forbidden(self, app_client):
        login(app_client, "admin", "adminpass123")
        row = self._create(app_client)
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch(f"/api/email-providers/{row['id']}", json={"name": "X", "provider_type": "smtp", "config": {}})
        assert r.status_code == 403


class TestSetDefaultProvider:
    def test_switches_default_and_clears_previous(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        first = app_client.post("/api/email-providers", json={
            "name": "P1", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        }).json()
        second = app_client.post("/api/email-providers", json={
            "name": "P2", "provider_type": "resend",
            "config": {"api_key": "re_123", "from_email": "b@example.com"},
        }).json()
        assert first["is_default"] is True
        assert second["is_default"] is False

        r = app_client.post(f"/api/email-providers/{second['id']}/set-default")
        assert r.status_code == 200
        assert r.json()["is_default"] is True

        rows = {row.id: row.is_default for row in db_session.query(EmailProvider).all()}
        assert rows[first["id"]] is False
        assert rows[second["id"]] is True

    def test_disabled_profile_cannot_become_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/email-providers", json={
            "name": "P1", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        })
        second = app_client.post("/api/email-providers", json={
            "name": "P2", "provider_type": "smtp", "is_active": False,
            "config": {"host": "smtp2.example.com", "port": 587, "from_email": "b@example.com"},
        }).json()
        r = app_client.post(f"/api/email-providers/{second['id']}/set-default")
        assert r.status_code == 400


class TestDeleteProvider:
    def test_cannot_delete_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        row = app_client.post("/api/email-providers", json={
            "name": "P1", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        }).json()
        r = app_client.delete(f"/api/email-providers/{row['id']}")
        assert r.status_code == 400

    def test_can_delete_non_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/email-providers", json={
            "name": "P1", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        })
        second = app_client.post("/api/email-providers", json={
            "name": "P2", "provider_type": "resend",
            "config": {"api_key": "re_123", "from_email": "b@example.com"},
        }).json()
        r = app_client.delete(f"/api/email-providers/{second['id']}")
        assert r.status_code == 200
        r = app_client.get("/api/email-providers")
        assert len(r.json()) == 1


class TestTestProvider:
    def test_success(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        row = app_client.post("/api/email-providers", json={
            "name": "P1", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        }).json()
        monkeypatch.setattr(ep_mod.mailer, "send_test_email_via_config", lambda **kw: None)
        r = app_client.post(f"/api/email-providers/{row['id']}/test", json={"to_address": "me@example.com"})
        assert r.status_code == 200
        assert "me@example.com" in r.json()["message"]

    def test_failure_returns_502(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        row = app_client.post("/api/email-providers", json={
            "name": "P1", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        }).json()

        def boom(**kw):
            raise email_providers.ProviderSendError("connection refused")

        monkeypatch.setattr(ep_mod.mailer, "send_test_email_via_config", boom)
        r = app_client.post(f"/api/email-providers/{row['id']}/test", json={"to_address": "me@example.com"})
        assert r.status_code == 502

    def test_invalid_destination_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        row = app_client.post("/api/email-providers", json={
            "name": "P1", "provider_type": "smtp",
            "config": {"host": "smtp.example.com", "port": 587, "from_email": "a@example.com"},
        }).json()
        r = app_client.post(f"/api/email-providers/{row['id']}/test", json={"to_address": "nope"})
        assert r.status_code == 422
