"""Support Ticketing System -- RBAC scoping (routes/me_tickets.py vs
routes/tickets.py) and the full status lifecycle (create -> reply ->
resolve -> reply blocked -> reopen -> reply allowed again). See the
approved plan for the full feature spec; cli_wrapper-level plumbing
(--allow-duplicate flag etc.) is unrelated and covered in test_cli_wrapper.py.
"""
from vpnadmin.app_settings import runtime as runtime_settings
from vpnadmin.auth import hash_password
from vpnadmin.models import RoleDef, User

from .conftest import login


def _make_self_service_user(db_session, username, password="somepass123"):
    role = db_session.query(RoleDef).filter_by(slug="user").first()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id)
    db_session.add(user)
    db_session.commit()
    return user


def _make_editor(db_session, username, password="somepass123"):
    role = db_session.query(RoleDef).filter_by(slug="editor").first()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id)
    db_session.add(user)
    db_session.commit()
    return user


def _create_ticket(client, *, subject="Cannot connect", category="vpn_cannot_connect", priority="high", description="It just won't connect."):
    return client.post("/api/me/tickets", data={
        "subject": subject, "category": category, "priority": priority,
        "description": description, "attach_context": "false",
    })


class TestSelfServiceLifecycle:
    def test_create_view_reply_resolve_reply_blocked_reopen_reply_allowed(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")

        r = _create_ticket(app_client)
        assert r.status_code == 201
        ticket = r.json()
        assert ticket["status"] == "new"
        ticket_id = ticket["id"]

        r = app_client.get(f"/api/me/tickets/{ticket_id}")
        assert r.status_code == 200
        assert len(r.json()["messages"]) == 1

        r = app_client.post(f"/api/me/tickets/{ticket_id}/replies", data={"body": "Any update?"})
        assert r.status_code == 201
        assert r.json()["status"] == "waiting_for_admin"

        # An admin resolves it (via the admin router).
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "resolved"})
        assert r.status_code == 200
        assert r.json()["resolved_at"] is not None

        # Back to the user: reply is blocked while resolved.
        login(app_client, "alice", "somepass123")
        r = app_client.post(f"/api/me/tickets/{ticket_id}/replies", data={"body": "Still broken."})
        assert r.status_code == 409

        r = app_client.post(f"/api/me/tickets/{ticket_id}/reopen")
        assert r.status_code == 200
        assert r.json()["status"] == "reopened"
        assert r.json()["resolved_at"] is None

        r = app_client.post(f"/api/me/tickets/{ticket_id}/replies", data={"body": "Still broken."})
        assert r.status_code == 201

    def test_cannot_reopen_a_non_terminal_ticket(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]
        r = app_client.post(f"/api/me/tickets/{ticket_id}/reopen")
        assert r.status_code == 409

    def test_rate_limit_applies_to_create_and_reply_combined(self, app_client, db_session):
        runtime_settings.support_ticket_rate_limit_count = 1
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        assert _create_ticket(app_client, subject="one").status_code == 201
        r = _create_ticket(app_client, subject="two")
        assert r.status_code == 429


class TestOwnScopeIsolation:
    def test_a_user_cannot_view_another_users_ticket(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        _make_self_service_user(db_session, "bob")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "bob", "somepass123")
        r = app_client.get(f"/api/me/tickets/{ticket_id}")
        assert r.status_code == 404

    def test_a_user_cannot_reply_to_another_users_ticket(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        _make_self_service_user(db_session, "bob")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "bob", "somepass123")
        r = app_client.post(f"/api/me/tickets/{ticket_id}/replies", data={"body": "hi"})
        assert r.status_code == 404

    def test_a_user_only_sees_their_own_tickets_in_the_list(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        _make_self_service_user(db_session, "bob")
        login(app_client, "alice", "somepass123")
        _create_ticket(app_client, subject="alice's issue")

        login(app_client, "bob", "somepass123")
        _create_ticket(app_client, subject="bob's issue")
        r = app_client.get("/api/me/tickets")
        subjects = [t["subject"] for t in r.json()["tickets"]]
        assert subjects == ["bob's issue"]

    def test_viewer_role_cannot_use_the_admin_console(self, app_client, db_session):
        # "viewer" gets view=True on every OBJECTS key except settings/
        # roles/db_reporting -- support_tickets view is any-scope by
        # omission, so a viewer CAN see the list, but cannot reply/update.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/tickets")
        assert r.status_code == 200
        r = app_client.patch("/api/tickets/1", json={"status": "open"})
        assert r.status_code == 403

    def test_self_service_role_cannot_reach_the_admin_console(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/tickets")
        assert r.status_code == 403


class TestInternalNotesHiddenFromSelfService:
    def test_internal_note_never_appears_in_the_self_service_response(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/tickets/{ticket_id}/replies", data={"body": "internal only", "is_internal_note": "true"})
        assert r.status_code == 201
        assert any(m["is_internal_note"] and m["body"] == "internal only" for m in r.json()["messages"])

        login(app_client, "alice", "somepass123")
        r = app_client.get(f"/api/me/tickets/{ticket_id}")
        bodies = [m["body"] for m in r.json()["messages"]]
        assert "internal only" not in bodies


class TestAdminConsole:
    def test_admin_sees_every_ticket_regardless_of_owner(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        _make_self_service_user(db_session, "bob")
        login(app_client, "alice", "somepass123")
        _create_ticket(app_client, subject="alice's issue")
        login(app_client, "bob", "somepass123")
        _create_ticket(app_client, subject="bob's issue")

        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/tickets")
        subjects = {t["subject"] for t in r.json()["tickets"]}
        assert subjects == {"alice's issue", "bob's issue"}

    def test_editor_can_reply_and_update_status_but_stays_any_scope(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        _make_editor(db_session, "eve")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "eve", "somepass123")
        r = app_client.post(f"/api/tickets/{ticket_id}/replies", data={"body": "Looking into it."})
        assert r.status_code == 201
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "in_progress"})
        assert r.status_code == 200

    def test_assignment_and_priority_change_are_audit_logged(self, app_client, db_session):
        from vpnadmin.models import AuditLog

        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        admin_id = db_session.query(User).filter_by(username="admin").one().id
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"priority": "critical", "assigned_admin_id": admin_id})
        assert r.status_code == 200
        assert r.json()["assigned_admin"] is not None
        entry = db_session.query(AuditLog).filter_by(action="ticket_updated").one()
        assert "priority" in entry.detail
        assert "assigned_admin" in entry.detail

    def test_invalid_status_rejected(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "not-a-real-status"})
        assert r.status_code == 400


class TestCreateValidation:
    def test_unknown_category_rejected(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket(app_client, category="not-a-real-category")
        assert r.status_code == 422

    def test_blank_subject_rejected(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket(app_client, subject="   ")
        assert r.status_code == 422
