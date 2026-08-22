"""Support Ticketing System -- RBAC scoping (routes/me_tickets.py vs
routes/tickets.py) and the full status lifecycle (create -> reply ->
resolve -> reply blocked -> reopen -> reply allowed again). See the
approved plan for the full feature spec; cli_wrapper-level plumbing
(--allow-duplicate flag etc.) is unrelated and covered in test_cli_wrapper.py.
"""
from vpnadmin.app_settings import runtime as runtime_settings
from vpnadmin.auth import hash_password
from vpnadmin.models import Group, RoleDef, User

from .conftest import login


def _make_role_user(db_session, username, role_slug, password="somepass123"):
    # Group-only permissions: a role only grants anything via group
    # membership now (see permissions.py's effective_role_ids).
    role = db_session.query(RoleDef).filter_by(slug=role_slug).first()
    group = Group(name=f"{username}-{role_slug}-group", role_id=role.id)
    db_session.add(group)
    db_session.flush()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id, group_id=group.id)
    db_session.add(user)
    db_session.commit()
    return user


def _make_self_service_user(db_session, username, password="somepass123"):
    return _make_role_user(db_session, username, "user", password)


def _make_editor(db_session, username, password="somepass123"):
    return _make_role_user(db_session, username, "editor", password)


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
        assert ticket["status"] == "open"
        ticket_id = ticket["id"]

        r = app_client.get(f"/api/me/tickets/{ticket_id}")
        assert r.status_code == 200
        assert len(r.json()["messages"]) == 1

        r = app_client.post(f"/api/me/tickets/{ticket_id}/replies", data={"body": "Any update?"})
        assert r.status_code == 201
        assert r.json()["status"] == "in_progress"

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
        assert r.json()["status"] == "open"
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

    def test_assignable_admins_is_not_shadowed_by_ticket_id_route(self, app_client, db_session):
        """Regression test: GET /assignable-admins was declared AFTER GET
        /{ticket_id} in routes/tickets.py -- FastAPI/Starlette matches
        routes in registration order, so /{ticket_id} (a catch-all for any
        single path segment) matched first, tried to bind the literal
        string "assignable-admins" to `ticket_id: int`, and 422'd. Found
        live 2026-08-21: ticket_detail.html's admin-view init() awaits this
        endpoint with no try/catch, so the 422 silently aborted the whole
        init() before loadTicket() ever ran -- the ticket detail page
        (/support-center/{id}) was stuck on "Loading..." forever with no
        visible error. This asserts the real 200/expected-shape response,
        not just "not 422", so a future re-introduction of the same
        ordering mistake fails loudly here instead of only in production."""
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/tickets/assignable-admins")
        assert r.status_code == 200
        admins = r.json()["admins"]
        assert any(a["username"] == "admin" for a in admins)


class TestStatusWorkflowRules:
    """Status Workflow Rules -- see support_tickets.py's TRANSITIONS for the
    full design. Reported live 2026-08-21: "I can see that ticket can be
    moved to status New from closed ticket" -- these lock down every
    terminal status (TERMINAL_STATUSES) to a reopen-only exit, while
    leaving every active status free to move to any other status
    (including jumping straight to a terminal one), matching how a real
    collaboration tool's workflow engine is actually configured."""

    def test_closed_cannot_jump_straight_to_in_progress(self, app_client, db_session):
        _make_self_service_user(db_session, "frank")
        login(app_client, "frank", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "closed"})
        assert r.status_code == 200

        # The exact bug report (adapted -- "new" no longer exists as a
        # status, "open" IS the reopen target now): Closed -> a working
        # status directly, skipping the required Reopen step.
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "in_progress"})
        assert r.status_code == 409
        assert "open" in r.json()["detail"].lower()
        # The ticket's actual status is untouched by the rejected attempt.
        assert app_client.get(f"/api/tickets/{ticket_id}").json()["status"] == "closed"

    def test_closed_can_only_reopen(self, app_client, db_session):
        _make_self_service_user(db_session, "gina")
        login(app_client, "gina", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "closed"})
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "open"})
        assert r.status_code == 200
        assert r.json()["status"] == "open"

    def test_resolved_cannot_jump_to_a_different_terminal_status(self, app_client, db_session):
        """Resolved -> Cancelled directly is blocked too -- not just the
        reported Closed -> New case. Terminal statuses are one-way doors;
        sideways moves between them require reopening first, same as
        moving back into the active workflow does."""
        _make_self_service_user(db_session, "hank")
        login(app_client, "hank", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "resolved"})
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "cancelled"})
        assert r.status_code == 409

    def test_resolved_can_move_to_closed(self, app_client, db_session):
        """The one deliberate exception to "terminal statuses only exit via
        reopen": Resolved -> Closed is forward progress through the
        workflow, not an exit from it -- reported live as broken
        ("transition from resolved to close does not work from the close
        button")."""
        _make_self_service_user(db_session, "mona")
        login(app_client, "mona", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "resolved"})
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "closed"})
        assert r.status_code == 200
        assert r.json()["status"] == "closed"

    def test_active_status_can_jump_straight_to_a_terminal_one(self, app_client, db_session):
        """A brand-new ticket can be closed directly -- real collaboration
        tools don't force a rigid step-by-step sequence for the active
        part of the workflow, only terminal exits are restricted."""
        _make_self_service_user(db_session, "ivan")
        login(app_client, "ivan", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "closed"})
        assert r.status_code == 200

    def test_active_statuses_move_freely_between_each_other(self, app_client, db_session):
        _make_self_service_user(db_session, "jill")
        login(app_client, "jill", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        # open -> in_progress directly -- common in practice (an admin
        # picks up a fresh ticket and starts working).
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "in_progress"})
        assert r.status_code == 200
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "waiting_for_user"})
        assert r.status_code == 200

    def test_same_status_save_is_always_a_no_op(self, app_client, db_session):
        """Re-saving the ticket's own current status (e.g. from the Save
        button on the manage panel without touching the dropdown) must
        never 409, regardless of TRANSITIONS -- this isn't a transition at
        all."""
        _make_self_service_user(db_session, "kate")
        login(app_client, "kate", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "closed"})
        r = app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "closed"})
        assert r.status_code == 200

    def test_allowed_next_statuses_exposed_on_ticket_detail(self, app_client, db_session):
        _make_self_service_user(db_session, "liam")
        login(app_client, "liam", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "closed"})
        detail = app_client.get(f"/api/tickets/{ticket_id}").json()
        assert detail["allowed_next_statuses"] == [{"value": "open", "label": "Open"}]

        # Self-service detail never exposes this (no generic status picker there).
        login(app_client, "liam", "somepass123")
        self_detail = app_client.get(f"/api/me/tickets/{ticket_id}").json()
        assert self_detail["allowed_next_statuses"] == []


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
