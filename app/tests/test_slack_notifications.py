"""Tests for Slack Integration for Notifications -- slack_notifications.py's
fan-out module and routes/settings.py's Slack section. Every test mocks
the actual outbound HTTP call (slack_notifications._post_webhook) --
never hits a real Slack endpoint, per this feature's testing requirement."""
from vpnadmin import slack_notifications
from vpnadmin.models import SlackDeliveryLog, SlackWorkspace

from .conftest import login

VALID_WEBHOOK = "https://hooks.slack.com/services/T00/B00/xxxxxxxxxxxxxxxxxxxxxxxx"


class TestWebhookValidation:
    def test_valid_slack_url_accepted(self):
        assert slack_notifications.is_valid_webhook_url(VALID_WEBHOOK)

    def test_non_slack_url_rejected(self):
        assert not slack_notifications.is_valid_webhook_url("https://example.com/webhook")

    def test_http_scheme_rejected(self):
        assert not slack_notifications.is_valid_webhook_url("http://hooks.slack.com/services/T00/B00/xxx")

    def test_blank_rejected(self):
        assert not slack_notifications.is_valid_webhook_url("")
        assert not slack_notifications.is_valid_webhook_url(None)

    def test_workflow_builder_webhook_accepted(self):
        """Regression: the regex used to be anchored to "/services/" (the
        classic Incoming Webhooks app's URL shape) and rejected every
        genuinely valid Slack webhook that isn't that exact shape -- e.g. a
        Workflow Builder webhook trigger, which has no "/services/" segment
        at all. Found live 2026-08-21 via a real admin's "trying to save
        slack webhook but getting error" report."""
        # Same low-entropy "T00/B00/xxxx..." shape as VALID_WEBHOOK above --
        # a longer, more realistic-looking random token here previously
        # tripped gitleaks' own slack-webhook-url rule as a false-positive
        # secret, re-flagging on every future scan of this commit; fixed at
        # the fixture rather than allowlisted, same policy as this repo's
        # other test-fixture false positives (see .gitleaks.toml's header).
        assert slack_notifications.is_valid_webhook_url("https://hooks.slack.com/triggers/T00/000/xxxxxxxxxxxxxxxxxxxxxxxx")


class TestNotifyFanOut:
    def test_notify_skips_disabled_workspace(self, db_session, monkeypatch):
        called = []
        monkeypatch.setattr(slack_notifications, "_post_webhook", lambda *a, **k: called.append(a))
        ws = SlackWorkspace(name="W", webhook_url=VALID_WEBHOOK, is_enabled=False,
                             notify_types='{"ticket_created": true}')
        db_session.add(ws)
        db_session.commit()
        slack_notifications.notify(db_session, "ticket_created", "hello")
        assert called == []

    def test_notify_skips_type_not_enabled(self, db_session, monkeypatch):
        called = []
        monkeypatch.setattr(slack_notifications, "_post_webhook", lambda *a, **k: called.append(a))
        ws = SlackWorkspace(name="W", webhook_url=VALID_WEBHOOK, is_enabled=True,
                             notify_types='{"ticket_created": false}')
        db_session.add(ws)
        db_session.commit()
        slack_notifications.notify(db_session, "ticket_created", "hello")
        assert called == []

    def test_notify_sends_and_logs_success(self, db_session, monkeypatch):
        called = []
        monkeypatch.setattr(slack_notifications, "_post_webhook", lambda *a, **k: called.append(a))
        ws = SlackWorkspace(name="W", webhook_url=VALID_WEBHOOK, is_enabled=True,
                             notify_types='{"ticket_created": true}')
        db_session.add(ws)
        db_session.commit()
        slack_notifications.notify(db_session, "ticket_created", "New ticket #1")
        assert len(called) == 1
        logs = db_session.query(SlackDeliveryLog).all()
        assert len(logs) == 1
        assert logs[0].success is True
        assert logs[0].event_type == "ticket_created"
        assert logs[0].workspace_id == ws.id

    def test_notify_logs_failure_without_raising(self, db_session, monkeypatch):
        def _boom(*a, **k):
            raise RuntimeError("Slack returned HTTP 500")
        monkeypatch.setattr(slack_notifications, "_post_webhook", _boom)
        ws = SlackWorkspace(name="W", webhook_url=VALID_WEBHOOK, is_enabled=True,
                             notify_types='{"ticket_created": true}')
        db_session.add(ws)
        db_session.commit()
        # Must not raise -- best-effort, same posture as mailer.py.
        slack_notifications.notify(db_session, "ticket_created", "New ticket #1")
        logs = db_session.query(SlackDeliveryLog).all()
        assert len(logs) == 1
        assert logs[0].success is False
        assert "500" in logs[0].error_detail

    def test_notify_with_no_workspaces_is_a_noop(self, db_session, monkeypatch):
        called = []
        monkeypatch.setattr(slack_notifications, "_post_webhook", lambda *a, **k: called.append(a))
        slack_notifications.notify(db_session, "ticket_created", "hello")
        assert called == []
        assert db_session.query(SlackDeliveryLog).count() == 0


class TestSendTestNotification:
    def test_test_notification_success_is_logged(self, db_session, monkeypatch):
        monkeypatch.setattr(slack_notifications, "_post_webhook", lambda *a, **k: None)
        ok, detail = slack_notifications.send_test_notification(db_session, VALID_WEBHOOK)
        assert ok is True
        log = db_session.query(SlackDeliveryLog).one()
        assert log.event_type == "test"
        assert log.success is True

    def test_test_notification_failure_is_logged_and_reported(self, db_session, monkeypatch):
        def _boom(*a, **k):
            raise RuntimeError("connection refused")
        monkeypatch.setattr(slack_notifications, "_post_webhook", _boom)
        ok, detail = slack_notifications.send_test_notification(db_session, VALID_WEBHOOK)
        assert ok is False
        assert "connection refused" in detail
        log = db_session.query(SlackDeliveryLog).one()
        assert log.success is False


class TestSettingsRoutes:
    def test_admin_can_save_slack_settings(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings/slack", json={
            "webhook_url": VALID_WEBHOOK, "is_enabled": True,
            "notify_types": {"ticket_created": True, "mfa_disabled": True},
        })
        assert r.status_code == 200
        body = r.json()
        assert body["is_enabled"] is True
        assert body["notify_types"]["ticket_created"] is True
        assert body["notify_types"]["mfa_disabled"] is True
        assert body["notify_types"]["ticket_resolved"] is False
        # Secret masking, same convention as every other secret field.
        assert body["webhook_url"] == "••••••••"

    def test_resaving_the_masked_placeholder_does_not_422(self, app_client, monkeypatch):
        """Regression: the Settings page always round-trips the masked
        "••••••••" placeholder back into the webhook_url field once a
        webhook is already saved (see _serialize_slack_workspace) -- ANY
        subsequent save that doesn't touch that field (toggling Enable,
        editing the channel, checking a notify-type box) resubmits that
        placeholder, which used to 422 before the placeholder-is-a-no-op
        check was moved ahead of the format validator. Found live
        2026-08-21 alongside the webhook-format bug above."""
        login(app_client, "admin", "adminpass123")
        first = app_client.patch("/api/settings/slack", json={"webhook_url": VALID_WEBHOOK, "is_enabled": True})
        assert first.status_code == 200
        assert first.json()["webhook_url"] == "••••••••"

        second = app_client.patch("/api/settings/slack", json={"webhook_url": "••••••••", "channel_override": "#ops"})
        assert second.status_code == 200
        assert second.json()["channel_override"] == "#ops"

    def test_invalid_webhook_url_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings/slack", json={"webhook_url": "https://example.com/not-slack"})
        assert r.status_code == 422

    def test_enabling_without_webhook_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings/slack", json={"is_enabled": True})
        assert r.status_code == 400

    def test_viewer_cannot_update_slack_settings(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/settings/slack", json={"webhook_url": VALID_WEBHOOK})
        assert r.status_code == 403

    def test_unknown_notify_type_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings/slack", json={"notify_types": {"not_a_real_type": True}})
        assert r.status_code == 422

    def test_test_notification_endpoint_mocks_http(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        monkeypatch.setattr(slack_notifications, "_post_webhook", lambda *a, **k: None)
        r = app_client.post("/api/settings/slack/test", json={"webhook_url": VALID_WEBHOOK})
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_test_notification_endpoint_surfaces_failure(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")

        def _boom(*a, **k):
            raise RuntimeError("timed out")
        monkeypatch.setattr(slack_notifications, "_post_webhook", _boom)
        r = app_client.post("/api/settings/slack/test", json={"webhook_url": VALID_WEBHOOK})
        assert r.status_code == 502

    def test_test_notification_requires_a_url(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/settings/slack/test", json={})
        assert r.status_code == 400

    def test_delivery_log_endpoint(self, app_client, monkeypatch):
        login(app_client, "admin", "adminpass123")
        monkeypatch.setattr(slack_notifications, "_post_webhook", lambda *a, **k: None)
        app_client.post("/api/settings/slack/test", json={"webhook_url": VALID_WEBHOOK})
        r = app_client.get("/api/settings/slack/delivery-log")
        assert r.status_code == 200
        assert len(r.json()["deliveries"]) == 1
        assert r.json()["deliveries"][0]["event_type"] == "test"
