"""Tests for GET /api/audit -- the admin-only recent-activity feed backing
the Dashboard's Recent Activity section (see routes/status.py)."""

from vpnadmin.audit import log_action
from vpnadmin.models import User

from .conftest import login


class TestAuditEndpoint:
    def test_admin_can_view_audit_log(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        user = db_session.query(User).filter_by(username="admin").first()
        log_action(db_session, user, "add_client", target="alice", detail="alice added.", success=True)
        log_action(db_session, user, "revoke_client", target="bob", detail="Failed to revoke", success=False)

        r = app_client.get("/api/audit")
        assert r.status_code == 200
        body = r.json()
        assert len(body) >= 2
        # Newest first.
        assert body[0]["action"] == "revoke_client"
        assert body[0]["success"] is False
        assert body[1]["action"] == "add_client"
        assert body[1]["target"] == "alice"

    def test_limit_is_respected(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        user = db_session.query(User).filter_by(username="admin").first()
        for i in range(5):
            log_action(db_session, user, "add_client", target=f"client{i}", detail="ok", success=True)

        r = app_client.get("/api/audit?limit=2")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_viewer_cannot_view_audit_log(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/audit")
        assert r.status_code == 403

    def test_unauthenticated_cannot_view_audit_log(self, app_client):
        r = app_client.get("/api/audit")
        assert r.status_code == 401
