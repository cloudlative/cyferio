"""Tests for the bandwidth Reports page's three endpoints
(routes/reports.py) -- pure aggregation over policy_store's JSON files
joined against User/Group/VpnProfileLink, no new data collection to test
beyond the aggregation math itself."""
import subprocess

import pytest

from vpnadmin import cli_wrapper as cw
from vpnadmin import policy_store
from vpnadmin.config import settings
from vpnadmin.models import Group, User, VpnProfileLink

from .conftest import login


@pytest.fixture(autouse=True)
def _tmp_policy_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
    monkeypatch.setattr(settings, "CLIENT_USAGE_FILE", str(tmp_path / "client_usage.json"))


def _seed(db_session):
    group = Group(name="Engineering", slug="engineering")
    db_session.add(group)
    db_session.commit()

    alice = User(username="alice", password_hash="x", first_name="Alice", group_id=group.id)
    bob = User(username="bob", password_hash="x", first_name="Bob")  # no group -- "Unassigned"
    db_session.add_all([alice, bob])
    db_session.commit()

    db_session.add_all([
        VpnProfileLink(user_id=alice.id, vpn_client_name="alice", link_source="created_with_profile"),
        VpnProfileLink(user_id=bob.id, vpn_client_name="bob", link_source="created_with_profile"),
    ])
    db_session.commit()

    # alice: 1GB quota, 900MB used (90% -- "exceeding" bucket lands at
    # >=100%, so this is "approaching"). bob: no quota at all (unlimited).
    policy_store.set_policy("alice", bandwidth_monthly_gb=1.0)
    # Directly write client_usage.json rather than going through a real
    # session -- get_usage()'s current-month rollover only matters for
    # policy_lib.py's own lazy-reset logic on the host side; the app-side
    # get_all_usage() this report reads just needs a plausible current-
    # month row.
    import json
    usage_path = settings.CLIENT_USAGE_FILE
    from datetime import date
    period_start = date.today().replace(day=1).isoformat()
    with open(usage_path, "w") as f:
        json.dump({"alice": {"period_start": period_start, "bytes_used": int(0.9 * 1024 ** 3)}}, f)


class TestUserReport:
    def test_user_report_shape(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/reports/users")
        assert r.status_code == 200
        rows = {row["username"]: row for row in r.json()}
        assert rows["alice"]["quota_gb"] == 1.0
        assert rows["alice"]["used_gb"] == pytest.approx(0.9, abs=0.01)
        assert rows["alice"]["pct_used"] == pytest.approx(90.0, abs=0.5)
        assert rows["alice"]["group_names"] == ["Engineering"]
        assert rows["bob"]["quota_gb"] is None
        assert rows["bob"]["pct_used"] is None

    def test_viewer_can_view(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "viewer", "viewerpass123")
        assert app_client.get("/api/reports/users").status_code == 200


class TestGroupReport:
    def test_group_and_unassigned_buckets(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/reports/groups")
        assert r.status_code == 200
        groups = {t["group"]: t for t in r.json()}
        assert groups["Engineering"]["member_count"] == 1
        assert groups["Engineering"]["total_quota_gb"] == 1.0
        assert groups["Unassigned"]["member_count"] == 1
        assert groups["Unassigned"]["total_quota_gb"] is None  # bob has no quota


class TestGlobalReport:
    def test_thresholds(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/reports/global")
        assert r.status_code == 200
        data = r.json()
        assert data["total_users_reported"] == 2
        assert len(data["approaching_threshold"]) == 1
        assert data["approaching_threshold"][0]["username"] == "alice"
        assert len(data["exceeding_threshold"]) == 0
        assert data["top_consumers"][0]["username"] == "alice"


def _fake_run(session_rows="[]", rejected_rows="[]"):
    def run(args, **kwargs):
        if "--session-history" in args:
            return subprocess.CompletedProcess(args, 0, stdout=session_rows, stderr="")
        if "--rejected-connections" in args:
            return subprocess.CompletedProcess(args, 0, stdout=rejected_rows, stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="[]", stderr="")
    return run


class TestUserOptions:
    def test_only_linked_users_returned(self, app_client, db_session):
        _seed(db_session)
        # carol has no linked VPN profile -- must not appear.
        db_session.add(User(username="carol", password_hash="x", first_name="Carol"))
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/reports/user-options")
        assert r.status_code == 200
        usernames = {row["username"] for row in r.json()}
        assert usernames == {"alice", "bob"}
        row = next(row for row in r.json() if row["username"] == "alice")
        assert row["vpn_client_name"] == "alice"

    def test_viewer_can_view(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "viewer", "viewerpass123")
        assert app_client.get("/api/reports/user-options").status_code == 200


class TestUserAnalyticsDetail:
    def test_found_user_with_profile(self, app_client, db_session, monkeypatch):
        _seed(db_session)
        alice = db_session.query(User).filter_by(username="alice").one()
        monkeypatch.setattr(subprocess, "run", _fake_run(
            session_rows='[{"client": "alice", "connected_at": "2026-08-01T10:00:00", '
                         '"disconnected_at": "2026-08-01T11:00:00", "duration_seconds": 3600, '
                         '"source_ip": "203.0.113.5", "bytes_received": 100, "bytes_sent": 200}]',
            rejected_rows='[{"claimed_name": "alice", "timestamp": "2026-08-02T00:00:00", "reason": "mac_mismatch"}, '
                          '{"claimed_name": "someone_else", "timestamp": "2026-08-02T00:00:00", "reason": "mac_mismatch"}]',
        ))
        login(app_client, "admin", "adminpass123")
        r = app_client.get(f"/api/reports/users/{alice.id}")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "alice"
        assert data["quota_gb"] == 1.0  # _per_client_row summary reused verbatim
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["bytes_received"] == 100
        # Only alice's own rejected attempt, not "someone_else"'s.
        assert len(data["rejected"]) == 1
        assert data["rejected"][0]["claimed_name"] == "alice"
        assert data["source_ip_summary"]["top_ips"] == [{"ip": "203.0.113.5", "count": 1}]

    def test_user_without_linked_profile_404s(self, app_client, db_session):
        _seed(db_session)
        carol = User(username="carol", password_hash="x", first_name="Carol")
        db_session.add(carol)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        assert app_client.get(f"/api/reports/users/{carol.id}").status_code == 404

    def test_nonexistent_user_404s(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "admin", "adminpass123")
        assert app_client.get("/api/reports/users/999999").status_code == 404

    def test_requires_reports_view_permission(self, app_client, db_session):
        _seed(db_session)
        alice = db_session.query(User).filter_by(username="alice").one()
        # No login at all -- unauthenticated.
        r = app_client.get(f"/api/reports/users/{alice.id}")
        assert r.status_code == 401


class TestLoginActivityLogging:
    def test_successful_login_writes_audit_entry(self, app_client, db_session):
        from vpnadmin.models import AuditLog
        login(app_client, "admin", "adminpass123")
        entries = db_session.query(AuditLog).filter_by(action="login_success").all()
        assert len(entries) == 1
        assert entries[0].username == "admin"
        assert entries[0].success is True

    def test_failed_login_does_not_write_login_success(self, app_client, db_session):
        from vpnadmin.models import AuditLog
        login(app_client, "admin", "wrong-password")
        entries = db_session.query(AuditLog).filter_by(action="login_success").all()
        assert entries == []

    def test_login_activity_endpoint_returns_entry(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")  # writes one login_success entry
        r = app_client.get("/api/reports/login-activity?days=30")
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["username"] == "admin"
