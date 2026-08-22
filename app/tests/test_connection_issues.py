"""Tests for "My Connection Issues" -- the host-ingestion endpoint
(routes/host_ingest.py's POST /internal/connection-rejections), the
self-service API (routes/me_connection_issues.py's GET/POST
/api/me/connection-issues), retention pruning (app_settings.py's
prune_connection_rejections), and the page route."""
from datetime import datetime, timedelta, timezone

import pytest

from vpnadmin.app_settings import prune_connection_rejections, runtime
from vpnadmin.auth import hash_password
from vpnadmin.config import settings
from vpnadmin.models import AuditLog, ConnectionRejectionLog, Group, RoleDef, User, VpnProfileLink

from .conftest import login


def _make_self_service_user(db_session, username, *, vpn_client_name=None, password="somepass123"):
    # Group-only permissions: a role only grants anything via group
    # membership now (see permissions.py's effective_role_ids).
    role = db_session.query(RoleDef).filter_by(slug="user").first()
    group = Group(name=f"{username}-user-group", role_id=role.id)
    db_session.add(group)
    db_session.flush()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id, group_id=group.id)
    db_session.add(user)
    db_session.commit()
    if vpn_client_name:
        db_session.add(VpnProfileLink(user_id=user.id, vpn_client_name=vpn_client_name, link_source="created_with_profile"))
        db_session.commit()
    return user


def _add_rejection(db_session, vpn_client_name, reason, **kw):
    row = ConnectionRejectionLog(vpn_client_name=vpn_client_name, reason=reason, **kw)
    db_session.add(row)
    db_session.commit()
    return row


class TestHostIngestEndpoint:
    def test_missing_token_configured_rejects(self, app_client, monkeypatch):
        monkeypatch.setattr(settings, "HOST_INGEST_TOKEN", None)
        r = app_client.post("/internal/connection-rejections", json={"vpn_client_name": "alice", "reason": "mac_mismatch"},
                             headers={"Authorization": "Bearer whatever"})
        assert r.status_code == 401

    def test_wrong_token_rejects(self, app_client, monkeypatch):
        monkeypatch.setattr(settings, "HOST_INGEST_TOKEN", "correct-token")
        r = app_client.post("/internal/connection-rejections", json={"vpn_client_name": "alice", "reason": "mac_mismatch"},
                             headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401

    def test_no_auth_header_rejects(self, app_client, monkeypatch):
        monkeypatch.setattr(settings, "HOST_INGEST_TOKEN", "correct-token")
        r = app_client.post("/internal/connection-rejections", json={"vpn_client_name": "alice", "reason": "mac_mismatch"})
        assert r.status_code == 401

    def test_valid_token_writes_row(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(settings, "HOST_INGEST_TOKEN", "correct-token")
        r = app_client.post(
            "/internal/connection-rejections",
            json={
                "vpn_client_name": "alice",
                "reason": "mac_mismatch",
                "message": "MAC not found",
                "source_ip": "203.0.113.5",
                "detected_mac": "AA:BB:CC:DD:EE:FF",
            },
            headers={"Authorization": "Bearer correct-token"},
        )
        assert r.status_code == 201
        rows = db_session.query(ConnectionRejectionLog).all()
        assert len(rows) == 1
        assert rows[0].vpn_client_name == "alice"
        assert rows[0].reason == "mac_mismatch"
        assert rows[0].detected_mac == "AA:BB:CC:DD:EE:FF"
        assert rows[0].source_ip == "203.0.113.5"

    def test_no_session_cookie_required(self, app_client, monkeypatch):
        # This endpoint is authenticated by bearer token only -- it must
        # never require a logged-in portal session (there isn't one; the
        # caller is a host-side script, not a browser).
        monkeypatch.setattr(settings, "HOST_INGEST_TOKEN", "correct-token")
        r = app_client.post("/internal/connection-rejections", json={"vpn_client_name": "bob", "reason": "ip_not_allowed"},
                             headers={"Authorization": "Bearer correct-token"})
        assert r.status_code == 201


class TestMyConnectionIssuesApi:
    def test_requires_authentication(self, app_client):
        assert app_client.get("/api/me/connection-issues").status_code == 401

    def test_no_linked_profile_404s(self, app_client, db_session):
        _make_self_service_user(db_session, "carol")
        login(app_client, "carol", "somepass123")
        r = app_client.get("/api/me/connection-issues")
        assert r.status_code == 404

    def test_returns_own_data_only(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _make_self_service_user(db_session, "bob", vpn_client_name="bob", password="bobpass123")
        _add_rejection(db_session, "alice", "mac_mismatch", detected_mac="AA:BB:CC:DD:EE:FF")
        _add_rejection(db_session, "bob", "mac_mismatch", detected_mac="11:22:33:44:55:66")

        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/me/connection-issues")
        assert r.status_code == 200
        data = r.json()
        assert data["vpn_client_name"] == "alice"
        assert len(data["history"]) == 1
        assert data["history"][0]["detected_mac"] == "AA:BB:CC:DD:EE:FF"

    def test_detected_os_included_for_os_not_allowed(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _add_rejection(db_session, "alice", "os_not_allowed", detected_os="ios")
        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/me/connection-issues")
        assert r.status_code == 200
        assert r.json()["history"][0]["detected_os"] == "ios"

    def test_allowed_os_reflects_configured_policy(self, app_client, db_session, tmp_path, monkeypatch):
        from vpnadmin import policy_store
        from vpnadmin.config import settings as env_settings

        monkeypatch.setattr(env_settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        monkeypatch.setattr(env_settings, "CLIENT_USAGE_FILE", str(tmp_path / "client_usage.json"))
        policy_store.set_policy("alice", allowed_os=["windows", "linux"])

        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _add_rejection(db_session, "alice", "os_not_allowed", detected_os="ios")
        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/me/connection-issues")
        assert r.status_code == 200
        assert sorted(r.json()["allowed_os"]) == ["linux", "windows"]

    def test_recommended_action_mapping(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _add_rejection(db_session, "alice", "mac_mismatch")
        _add_rejection(db_session, "alice", "country_not_allowed", detected_country="DE")
        _add_rejection(db_session, "alice", "city_not_allowed", detected_city="Berlin")
        _add_rejection(db_session, "alice", "asn_not_allowed", detected_asn="AS12345")
        _add_rejection(db_session, "alice", "bandwidth_exceeded")

        login(app_client, "alice", "somepass123")
        data = app_client.get("/api/me/connection-issues").json()
        by_reason = {row["reason"]: row for row in data["history"]}
        assert by_reason["mac_mismatch"]["recommended_action"] == "whitelist_mac"
        assert by_reason["country_not_allowed"]["recommended_action"] == "update_country"
        assert by_reason["city_not_allowed"]["recommended_action"] == "contact_admin"
        assert by_reason["asn_not_allowed"]["recommended_action"] == "contact_admin"
        assert by_reason["bandwidth_exceeded"]["recommended_action"] == "upgrade_quota"

    def test_summary_cards_aggregate_by_category(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _add_rejection(db_session, "alice", "mac_mismatch")
        _add_rejection(db_session, "alice", "mac_mismatch")
        _add_rejection(db_session, "alice", "city_not_allowed", detected_city="Berlin")

        login(app_client, "alice", "somepass123")
        data = app_client.get("/api/me/connection-issues").json()
        cards = {c["category"]: c for c in data["cards"]}
        assert cards["mac"]["count"] == 2
        assert cards["city"]["count"] == 1
        assert cards["country"]["count"] == 0
        assert cards["asn"]["count"] == 0

    def test_city_and_asn_never_leak_admin_allowlist(self, app_client, db_session):
        # The response for a city/ASN rejection must only ever contain the
        # DETECTED value for that one rejection -- never any admin-
        # configured allowed_cities/allowed_asns list (those aren't even
        # queried by this endpoint at all).
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _add_rejection(db_session, "alice", "city_not_allowed", detected_city="Berlin")
        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/me/connection-issues")
        raw = r.text
        assert "allowed_cities" not in raw
        assert "allowed_asns" not in raw

    def test_mac_self_service_enabled_reflects_permission(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        data = app_client.get("/api/me/connection-issues").json()
        # Default self-service "user" role has vpn_profiles:update.
        assert data["mac_self_service_enabled"] is True

    def test_view_is_audited(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        app_client.get("/api/me/connection-issues")
        entries = db_session.query(AuditLog).filter_by(action="self_view_connection_issues").all()
        assert len(entries) == 1
        assert entries[0].username == "alice"


class TestMyConnectionIssuesAudit:
    def test_requires_authentication(self, app_client):
        r = app_client.post("/api/me/connection-issues/audit", json={"action": "copy_mac"})
        assert r.status_code == 401

    def test_unknown_action_rejected(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/connection-issues/audit", json={"action": "delete_everything"})
        assert r.status_code == 400

    @pytest.mark.parametrize("action", ["copy_mac", "view_details"])
    def test_allowed_actions_write_audit_row(self, app_client, db_session, action):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/connection-issues/audit", json={"action": action, "target": "AA:BB:CC:DD:EE:FF"})
        assert r.status_code == 200
        entry = db_session.query(AuditLog).filter_by(action=f"self_{action}").first()
        assert entry is not None
        assert entry.target == "AA:BB:CC:DD:EE:FF"

    def test_request_access_review_no_longer_a_valid_audit_action(self, app_client, db_session):
        # "request_access_review" moved to its own endpoint (POST
        # .../request-review, see TestRequestAccessReview below) that
        # creates a real ticket and notifies admins -- this asserts it
        # stays rejected here rather than silently regressing back to a
        # pure, unnotified audit-log write.
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/connection-issues/audit", json={"action": "request_access_review"})
        assert r.status_code == 400


class TestRequestAccessReview:
    def test_creates_ticket_with_reason_matched_category(self, app_client, db_session):
        from vpnadmin.models import SupportTicket

        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        row = _add_rejection(db_session, "alice", "os_not_allowed", detected_os="ios", source_ip="203.0.113.9")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/connection-issues/request-review", json={"timestamp": row.timestamp.isoformat()})
        assert r.status_code == 201
        ticket = db_session.query(SupportTicket).filter_by(id=r.json()["ticket_id"]).one()
        assert ticket.category == "vpn_os_restriction"
        assert ticket.created_by_user_id == db_session.query(User).filter_by(username="alice").one().id
        assert "Device OS Restriction" in ticket.subject
        assert ticket.messages[0].body.count("203.0.113.9") == 1

    def test_creates_ticket_and_notifies_admin(self, app_client, db_session):
        from vpnadmin.models import TicketNotification

        admin = db_session.query(User).filter_by(username="admin").one()
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        row = _add_rejection(db_session, "alice", "mac_mismatch", detected_mac="AA:BB:CC:DD:EE:FF")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/connection-issues/request-review", json={"timestamp": row.timestamp.isoformat()})
        assert r.status_code == 201
        ticket_id = r.json()["ticket_id"]
        assert db_session.query(TicketNotification).filter_by(user_id=admin.id, ticket_id=ticket_id).count() >= 1

    def test_reason_with_no_mapping_falls_back_to_general_inquiry(self, app_client, db_session):
        from vpnadmin.models import SupportTicket

        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        row = _add_rejection(db_session, "alice", "some_future_reason_not_yet_mapped")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/connection-issues/request-review", json={"timestamp": row.timestamp.isoformat()})
        assert r.status_code == 201
        ticket = db_session.query(SupportTicket).filter_by(id=r.json()["ticket_id"]).one()
        assert ticket.category == "other_general_inquiry"

    def test_unknown_timestamp_404s(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        r = app_client.post(
            "/api/me/connection-issues/request-review",
            json={"timestamp": datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()},
        )
        assert r.status_code == 404

    def test_cannot_request_review_for_someone_elses_rejection(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        _make_self_service_user(db_session, "bob", vpn_client_name="bob")
        row = _add_rejection(db_session, "bob", "mac_mismatch")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/connection-issues/request-review", json={"timestamp": row.timestamp.isoformat()})
        assert r.status_code == 404

    def test_resubmitting_the_same_rejection_returns_the_existing_ticket(self, app_client, db_session):
        """A second request-review call against the SAME rejection row
        (double click, or a request racing a refresh) must not file a
        second ticket -- it returns the ticket already on file, matching
        GET ""'s existing_ticket_id (see next test)."""
        from vpnadmin.models import SupportTicket

        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        row = _add_rejection(db_session, "alice", "mac_mismatch", detected_mac="AA:BB:CC:DD:EE:FF")
        login(app_client, "alice", "somepass123")
        r1 = app_client.post("/api/me/connection-issues/request-review", json={"timestamp": row.timestamp.isoformat()})
        assert r1.status_code == 201
        r2 = app_client.post("/api/me/connection-issues/request-review", json={"timestamp": row.timestamp.isoformat()})
        assert r2.status_code == 201
        assert r2.json()["ticket_id"] == r1.json()["ticket_id"]
        assert db_session.query(SupportTicket).count() == 1

    def test_existing_ticket_id_survives_in_the_list_response(self, app_client, db_session):
        """The whole point of review_ticket_id -- GET "" (what the frontend
        refreshes on) must keep reporting the ticket id for this rejection
        after it's been filed, so a page reload shows "View Ticket #N"
        instead of reverting to "Request Access Review"."""
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        row = _add_rejection(db_session, "alice", "os_not_allowed", detected_os="ios")
        login(app_client, "alice", "somepass123")

        before = app_client.get("/api/me/connection-issues").json()["history"][0]
        assert before["existing_ticket_id"] is None

        review = app_client.post("/api/me/connection-issues/request-review", json={"timestamp": row.timestamp.isoformat()})
        ticket_id = review.json()["ticket_id"]

        after = app_client.get("/api/me/connection-issues").json()["history"][0]
        assert after["existing_ticket_id"] == ticket_id


class TestMyConnectionIssuesPage:
    def test_requires_authentication(self, app_client):
        r = app_client.get("/my-connection-issues", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_renders_for_linked_self_service_user(self, app_client, db_session):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        login(app_client, "alice", "somepass123")
        r = app_client.get("/my-connection-issues")
        assert r.status_code == 200
        assert "My Connection Issues" in r.text

    def test_unlinked_user_redirected_to_my_vpn_profile(self, app_client, db_session):
        _make_self_service_user(db_session, "carol")
        login(app_client, "carol", "somepass123")
        r = app_client.get("/my-connection-issues", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/my-vpn-profile"


class TestPruneConnectionRejections:
    def test_disabled_when_zero_or_none(self, db_session, monkeypatch):
        _add_rejection(db_session, "alice", "mac_mismatch")
        monkeypatch.setattr(runtime, "connection_issue_retention_days", 0)
        assert prune_connection_rejections(db_session) == 0
        assert db_session.query(ConnectionRejectionLog).count() == 1

    def test_deletes_rows_older_than_cutoff(self, db_session, monkeypatch):
        monkeypatch.setattr(runtime, "connection_issue_retention_days", 30)
        old_row = _add_rejection(db_session, "alice", "mac_mismatch")
        old_row.timestamp = datetime.now(timezone.utc) - timedelta(days=45)
        db_session.commit()
        _add_rejection(db_session, "alice", "mac_mismatch")  # recent, kept

        deleted = prune_connection_rejections(db_session)
        assert deleted == 1
        assert db_session.query(ConnectionRejectionLog).count() == 1
