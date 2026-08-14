"""Tests for the self-service "My Reports" endpoint (routes/me_vpn.py's
GET /api/me/vpn-profile/report, Phase 4 of the Reporting Module Expansion).
The endpoint always resolves to request.user's own VpnProfileLink -- no
user_id param exists to mis-scope -- so the main things worth verifying are
the permission gate, the 404-when-unlinked behavior (mirroring
get_user_analytics()'s equivalent 404 in test_reports.py), and that the
response only ever contains the calling user's own data even when another
user's data also exists in the same DB."""

import subprocess

import pytest

from vpnadmin.auth import hash_password
from vpnadmin.config import settings
from vpnadmin.models import RoleDef, User, VpnProfileLink

from .conftest import login


@pytest.fixture(autouse=True)
def _tmp_policy_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
    monkeypatch.setattr(settings, "CLIENT_USAGE_FILE", str(tmp_path / "client_usage.json"))


def _make_self_service_user(db_session, username, *, vpn_client_name=None, password="somepass123"):
    """A "User"-role (self-service) account -- this role isn't in the
    legacy Role enum (see models.py's Role docstring), so it has to be
    looked up by slug and assigned via role_id directly, same pattern
    test_openvpn_install_access.py's _make_admin() uses for the admin
    role."""
    role = db_session.query(RoleDef).filter_by(slug="user").first()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id)
    db_session.add(user)
    db_session.commit()
    if vpn_client_name:
        db_session.add(VpnProfileLink(user_id=user.id, vpn_client_name=vpn_client_name, link_source="created_with_profile"))
        db_session.commit()
    return user


def _fake_run(session_rows="[]", rejected_rows="[]"):
    def run(args, **kwargs):
        if "--session-history" in args:
            return subprocess.CompletedProcess(args, 0, stdout=session_rows, stderr="")
        if "--rejected-connections" in args:
            return subprocess.CompletedProcess(args, 0, stdout=rejected_rows, stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="[]", stderr="")

    return run


class TestMyVpnReport:
    def test_requires_authentication(self, app_client):
        assert app_client.get("/api/me/vpn-profile/report").status_code == 401

    def test_no_linked_profile_404s(self, app_client, db_session):
        _make_self_service_user(db_session, "carol")
        login(app_client, "carol", "somepass123")
        r = app_client.get("/api/me/vpn-profile/report")
        assert r.status_code == 404

    def test_returns_own_data_only(self, app_client, db_session, monkeypatch):
        # Two linked self-service users -- alice's session/rejected rows
        # must never leak into bob's report.
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _make_self_service_user(db_session, "bob", vpn_client_name="bob", password="bobpass123")
        monkeypatch.setattr(
            subprocess,
            "run",
            _fake_run(
                session_rows='[{"client": "alice", "connected_at": "2026-08-01T10:00:00", '
                '"disconnected_at": "2026-08-01T11:00:00", "duration_seconds": 3600, '
                '"source_ip": "203.0.113.5", "bytes_received": 100, "bytes_sent": 200}]',
                rejected_rows='[{"claimed_name": "alice", "timestamp": "2026-08-02T00:00:00", "reason": "mac_mismatch"}, '
                '{"claimed_name": "bob", "timestamp": "2026-08-02T00:00:00", "reason": "mac_mismatch"}]',
            ),
        )
        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/me/vpn-profile/report")
        assert r.status_code == 200
        data = r.json()
        assert data["vpn_client_name"] == "alice"
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["bytes_received"] == 100
        # Only alice's own rejected attempt, not bob's.
        assert len(data["rejected"]) == 1
        assert data["rejected"][0]["claimed_name"] == "alice"
        assert data["source_ip_summary"]["top_ips"] == [{"ip": "203.0.113.5", "count": 1}]

    def test_quota_and_usage_scoped_to_own_client(self, app_client, db_session, monkeypatch):
        from vpnadmin import policy_store

        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        policy_store.set_policy("alice", bandwidth_monthly_gb=2.0)
        monkeypatch.setattr(subprocess, "run", _fake_run())
        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/me/vpn-profile/report")
        assert r.status_code == 200
        assert r.json()["policy"]["bandwidth_monthly_gb"] == 2.0

    def test_admin_role_cannot_use_this_as_a_lookup_for_others(self, app_client, db_session):
        # The admin account seeded by app_client has vpn_profiles:view (via
        # its blanket manage=True sweep) but no linked profile of its own --
        # confirms this endpoint never accepts/derives any other identity,
        # even for a role with far broader permissions elsewhere.
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/me/vpn-profile/report")
        assert r.status_code == 404


class TestMyReportsPage:
    def test_requires_authentication(self, app_client):
        r = app_client.get("/my-reports", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_renders_for_linked_self_service_user(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        r = app_client.get("/my-reports")
        assert r.status_code == 200
        assert "My Reports" in r.text

    def test_unlinked_user_redirected_to_my_vpn_profile(self, app_client, db_session):
        _make_self_service_user(db_session, "carol")
        login(app_client, "carol", "somepass123")
        r = app_client.get("/my-reports", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/my-vpn-profile"
