"""Tests for the bandwidth Reports page's three endpoints
(routes/reports.py) -- pure aggregation over policy_store's JSON files
joined against User/Team/VpnProfileLink, no new data collection to test
beyond the aggregation math itself."""
import pytest

from vpnadmin import policy_store
from vpnadmin.config import settings
from vpnadmin.models import Team, User, VpnProfileLink

from .conftest import login


@pytest.fixture(autouse=True)
def _tmp_policy_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
    monkeypatch.setattr(settings, "CLIENT_USAGE_FILE", str(tmp_path / "client_usage.json"))


def _seed(db_session):
    team = Team(name="Engineering", slug="engineering")
    db_session.add(team)
    db_session.commit()

    alice = User(username="alice", password_hash="x", first_name="Alice", teams=[team])
    bob = User(username="bob", password_hash="x", first_name="Bob")  # no team -- "Unassigned"
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
        assert rows["alice"]["team_names"] == ["Engineering"]
        assert rows["bob"]["quota_gb"] is None
        assert rows["bob"]["pct_used"] is None

    def test_viewer_can_view(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "viewer", "viewerpass123")
        assert app_client.get("/api/reports/users").status_code == 200


class TestTeamReport:
    def test_team_and_unassigned_buckets(self, app_client, db_session):
        _seed(db_session)
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/reports/teams")
        assert r.status_code == 200
        teams = {t["team"]: t for t in r.json()}
        assert teams["Engineering"]["member_count"] == 1
        assert teams["Engineering"]["total_quota_gb"] == 1.0
        assert teams["Unassigned"]["member_count"] == 1
        assert teams["Unassigned"]["total_quota_gb"] is None  # bob has no quota


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
