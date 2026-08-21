"""Tests for VPN Device Availability Monitoring & Offline Alert
Notifications -- device_monitoring.py's offline-check engine, config CRUD
(routes/clients.py's /monitoring endpoints), cooldown/maintenance-mode
suppression, recovery notifications, and RBAC. Every test mocks
cli_wrapper's status snapshot (never spawns vpn-status.py) and mailer/
Slack's actual send calls (never hits real SMTP/Slack), same testing
convention as test_release_check.py / test_slack_notifications.py."""
from datetime import datetime, timedelta, timezone

from vpnadmin import cli_wrapper, device_monitoring, mailer, slack_notifications
from vpnadmin.auth import hash_password
from vpnadmin.models import User, VpnDeviceOutage, VpnDeviceStatus, VpnProfileLink

from .conftest import login


def _make_link(db, username="asif", client_name="hq-gateway", **kwargs):
    user = User(username=username, password_hash=hash_password("password123"), email=f"{username}@example.com")
    db.add(user)
    db.commit()
    link = VpnProfileLink(user_id=user.id, vpn_client_name=client_name, link_source="created_with_profile", **kwargs)
    db.add(link)
    db.commit()
    return user, link


def _mock_status(monkeypatch, rows):
    monkeypatch.setattr(cli_wrapper, "get_status_all_snapshot", lambda: rows)


def _mock_channels(monkeypatch):
    """Captures every email/Slack send attempt without touching real I/O."""
    emails = []
    slacks = []
    monkeypatch.setattr(mailer, "_send", lambda db, message: emails.append(message))
    monkeypatch.setattr(slack_notifications, "notify", lambda db, event_type, text: slacks.append((event_type, text)))
    return emails, slacks


class TestConfigCrud:
    def test_save_and_read_monitoring_config(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        _make_link(db_session, username="bob", client_name="bob-laptop")

        resp = app_client.put("/api/clients/bob-laptop/monitoring", json={
            "monitoring_enabled": True,
            "monitoring_name": "Bob's Laptop",
            "offline_threshold_minutes": 10,
            "alert_cooldown_mode": "repeat",
            "alert_cooldown_repeat_minutes": 30,
        })
        assert resp.status_code == 200, resp.text
        assert resp.json()["config"]["monitoring_enabled"] is True
        assert resp.json()["config"]["monitoring_name"] == "Bob's Laptop"

        got = app_client.get("/api/clients/bob-laptop/monitoring")
        assert got.status_code == 200
        assert got.json()["config"]["offline_threshold_minutes"] == 10
        assert got.json()["status"]["current_status"] == "unknown"

    def test_invalid_threshold_rejected(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        _make_link(db_session, username="carol", client_name="carol-pc")
        resp = app_client.put("/api/clients/carol-pc/monitoring", json={"offline_threshold_minutes": 7})
        assert resp.status_code == 422

    def test_invalid_additional_email_rejected(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        _make_link(db_session, username="dana", client_name="dana-pc")
        resp = app_client.put("/api/clients/dana-pc/monitoring", json={"notify_additional_emails": ["not-an-email"]})
        assert resp.status_code == 422

    def test_unlinked_client_returns_404(self, app_client):
        login(app_client, "admin", "adminpass123")
        resp = app_client.get("/api/clients/no-such-client/monitoring")
        assert resp.status_code == 404

    def test_viewer_cannot_configure_monitoring(self, app_client, db_session):
        login(app_client, "viewer", "viewerpass123")
        _make_link(db_session, username="erin", client_name="erin-pc")
        resp = app_client.put("/api/clients/erin-pc/monitoring", json={"monitoring_enabled": True})
        assert resp.status_code == 403

    def test_viewer_can_read_monitoring_status(self, app_client, db_session):
        _make_link(db_session, username="frank", client_name="frank-pc")
        login(app_client, "viewer", "viewerpass123")
        resp = app_client.get("/api/clients/frank-pc/monitoring")
        assert resp.status_code == 200


class TestOfflineDetectionAndAlerting:
    def test_offline_past_threshold_triggers_alert(self, db_session, monkeypatch):
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = True
        link.offline_threshold_minutes = 15
        db_session.commit()

        # Seed a status row already offline for longer than the threshold --
        # simulates several prior ticks without needing to actually sleep.
        status = VpnDeviceStatus(vpn_client_name=link.vpn_client_name, check_type="connectivity",
                                  current_status="offline", offline_since=datetime.now(timezone.utc) - timedelta(minutes=20))
        db_session.add(status)
        db_session.add(VpnDeviceOutage(vpn_client_name=link.vpn_client_name, started_at=status.offline_since))
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "offline", "last_seen": "never"}])
        device_monitoring.run_offline_check(db_session)

        assert len(emails) == 1
        assert "Offline" in emails[0].text_body
        assert len(slacks) == 1
        assert slacks[0][0] == "vpn_device_offline"
        db_session.refresh(status)
        assert status.alert_count == 1
        assert status.last_alert_sent_at is not None

    def test_offline_within_grace_period_does_not_alert(self, db_session, monkeypatch):
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = True
        link.offline_threshold_minutes = 15
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "offline", "last_seen": "never"}])
        device_monitoring.run_offline_check(db_session)  # first tick just opens the episode

        assert emails == []
        assert slacks == []
        status = db_session.query(VpnDeviceStatus).filter_by(vpn_client_name=link.vpn_client_name).first()
        assert status.current_status == "offline"

    def test_cooldown_once_suppresses_repeat_alert(self, db_session, monkeypatch):
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = True
        link.offline_threshold_minutes = 15
        link.alert_cooldown_mode = "once"
        db_session.commit()

        status = VpnDeviceStatus(vpn_client_name=link.vpn_client_name, check_type="connectivity",
                                  current_status="offline", offline_since=datetime.now(timezone.utc) - timedelta(minutes=20),
                                  last_alert_sent_at=datetime.now(timezone.utc) - timedelta(minutes=5), alert_count=1)
        db_session.add(status)
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "offline", "last_seen": "never"}])
        device_monitoring.run_offline_check(db_session)

        assert emails == []
        assert slacks == []
        db_session.refresh(status)
        assert status.alert_count == 1  # unchanged -- cooldown suppressed it

    def test_cooldown_repeat_resends_after_interval(self, db_session, monkeypatch):
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = True
        link.offline_threshold_minutes = 15
        link.alert_cooldown_mode = "repeat"
        link.alert_cooldown_repeat_minutes = 10
        db_session.commit()

        status = VpnDeviceStatus(vpn_client_name=link.vpn_client_name, check_type="connectivity",
                                  current_status="offline", offline_since=datetime.now(timezone.utc) - timedelta(minutes=40),
                                  last_alert_sent_at=datetime.now(timezone.utc) - timedelta(minutes=15), alert_count=1)
        db_session.add(status)
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "offline", "last_seen": "never"}])
        device_monitoring.run_offline_check(db_session)

        assert len(emails) == 1
        db_session.refresh(status)
        assert status.alert_count == 2

    def test_maintenance_mode_suppresses_alert(self, db_session, monkeypatch):
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = True
        link.offline_threshold_minutes = 15
        link.maintenance_mode = True
        db_session.commit()

        status = VpnDeviceStatus(vpn_client_name=link.vpn_client_name, check_type="connectivity",
                                  current_status="offline", offline_since=datetime.now(timezone.utc) - timedelta(minutes=20))
        db_session.add(status)
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "offline", "last_seen": "never"}])
        device_monitoring.run_offline_check(db_session)

        assert emails == []
        assert slacks == []

    def test_recovery_notification_sent_after_alerted_outage(self, db_session, monkeypatch):
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = True
        link.offline_threshold_minutes = 15
        db_session.commit()

        status = VpnDeviceStatus(vpn_client_name=link.vpn_client_name, check_type="connectivity",
                                  current_status="offline", offline_since=datetime.now(timezone.utc) - timedelta(minutes=30),
                                  last_alert_sent_at=datetime.now(timezone.utc) - timedelta(minutes=25), alert_count=1)
        db_session.add(status)
        db_session.add(VpnDeviceOutage(vpn_client_name=link.vpn_client_name, started_at=status.offline_since))
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "online", "last_seen": "now (connected)"}])
        device_monitoring.run_offline_check(db_session)

        assert len(emails) == 1
        assert "Reconnected" in emails[0].text_body
        assert slacks[0][0] == "vpn_device_online"

        db_session.refresh(status)
        assert status.current_status == "online"
        assert status.offline_since is None
        assert status.alert_count == 0

        outage = db_session.query(VpnDeviceOutage).filter_by(vpn_client_name=link.vpn_client_name).first()
        assert outage.ended_at is not None
        assert outage.duration_seconds is not None

    def test_recovery_without_prior_alert_stays_silent(self, db_session, monkeypatch):
        """A blip that reconnected before ever crossing the alert
        threshold shouldn't generate a "device reconnected" notification --
        nobody was told it went offline in the first place."""
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = True
        link.offline_threshold_minutes = 15
        db_session.commit()

        status = VpnDeviceStatus(vpn_client_name=link.vpn_client_name, check_type="connectivity",
                                  current_status="offline", offline_since=datetime.now(timezone.utc) - timedelta(minutes=2))
        db_session.add(status)
        db_session.add(VpnDeviceOutage(vpn_client_name=link.vpn_client_name, started_at=status.offline_since))
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "online", "last_seen": "now (connected)"}])
        device_monitoring.run_offline_check(db_session)

        assert emails == []
        assert slacks == []

    def test_disabled_monitoring_is_skipped_entirely(self, db_session, monkeypatch):
        emails, slacks = _mock_channels(monkeypatch)
        user, link = _make_link(db_session)
        link.monitoring_enabled = False
        db_session.commit()

        _mock_status(monkeypatch, [{"name": link.vpn_client_name, "status": "offline", "last_seen": "never"}])
        processed = device_monitoring.run_offline_check(db_session)

        assert processed == 0
        assert emails == []
        assert db_session.query(VpnDeviceStatus).filter_by(vpn_client_name=link.vpn_client_name).first() is None


class TestMaintenanceModeToggleEndpoint:
    def test_admin_can_enable_maintenance_mode(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        _make_link(db_session, username="gina", client_name="gina-pc")
        resp = app_client.post("/api/clients/gina-pc/monitoring/maintenance", json={"enabled": True, "note": "Planned firmware upgrade"})
        assert resp.status_code == 200
        assert resp.json()["config"]["maintenance_mode"] is True
        assert resp.json()["config"]["maintenance_mode_note"] == "Planned firmware upgrade"

        resp2 = app_client.post("/api/clients/gina-pc/monitoring/maintenance", json={"enabled": False})
        assert resp2.status_code == 200
        assert resp2.json()["config"]["maintenance_mode"] is False


class TestAvailabilityReport:
    def test_uptime_and_outage_aggregation(self, db_session):
        user, link = _make_link(db_session, username="hank", client_name="hank-pc")
        link.monitoring_enabled = True
        db_session.commit()

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=1)
        # One 2-hour outage entirely inside the window.
        db_session.add(VpnDeviceOutage(
            vpn_client_name="hank-pc", started_at=start + timedelta(hours=1),
            ended_at=start + timedelta(hours=3), duration_seconds=7200,
        ))
        db_session.commit()

        report = device_monitoring.availability_report(db_session, start, end)
        row = next(r for r in report if r["vpn_client_name"] == "hank-pc")
        assert row["total_outages"] == 1
        assert 91.0 < row["uptime_pct"] < 92.0  # 2h downtime out of 24h ~= 91.67%
