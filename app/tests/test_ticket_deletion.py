"""Individual + bulk ticket deletion (spec section 2/3) -- soft delete,
audit logging, permission gating, and exclusion from every normal list/
detail query. See routes/tickets.py's delete_ticket/bulk_delete_tickets."""
from vpnadmin.auth import hash_password
from vpnadmin.models import AuditLog, Group, RoleDef, User

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


def _make_editor(db_session, username, password="somepass123"):
    return _make_role_user(db_session, username, "editor", password)


def _make_self_service_user(db_session, username, password="somepass123"):
    return _make_role_user(db_session, username, "user", password)


def _create_ticket(client, *, subject="Cannot connect"):
    r = client.post("/api/me/tickets", data={
        "subject": subject, "category": "vpn_cannot_connect", "priority": "high",
        "description": "It just won't connect.", "attach_context": "false",
    })
    assert r.status_code == 201
    return r.json()["id"]


class TestSingleDelete:
    def test_admin_can_soft_delete_and_it_is_excluded_from_lists(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client)

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/tickets/{ticket_id}")
        assert r.status_code == 204

        # Excluded from the default admin list.
        r = app_client.get("/api/tickets")
        assert ticket_id not in [t["id"] for t in r.json()["tickets"]]

        # But still fetchable with include_deleted=true (delete-visibility caller).
        r = app_client.get("/api/tickets?include_deleted=true")
        assert ticket_id in [t["id"] for t in r.json()["tickets"]]
        row = next(t for t in r.json()["tickets"] if t["id"] == ticket_id)
        assert row["deleted"] is True

        # Excluded from self-service too.
        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/me/tickets")
        assert ticket_id not in [t["id"] for t in r.json()["tickets"]]
        r = app_client.get(f"/api/me/tickets/{ticket_id}")
        assert r.status_code == 404

        # Audited.
        row = db_session.query(AuditLog).filter_by(action="ticket_deleted", target=f"TCK-{ticket_id}").first()
        assert row is not None
        assert row.username == "admin"

    def test_restore_undoes_delete(self, app_client, db_session):
        _make_self_service_user(db_session, "bob")
        login(app_client, "bob", "somepass123")
        ticket_id = _create_ticket(app_client)

        login(app_client, "admin", "adminpass123")
        assert app_client.delete(f"/api/tickets/{ticket_id}").status_code == 204
        r = app_client.post(f"/api/tickets/{ticket_id}/restore")
        assert r.status_code == 200
        assert r.json()["deleted"] is False

        r = app_client.get("/api/tickets")
        assert ticket_id in [t["id"] for t in r.json()["tickets"]]

    def test_editor_role_lacks_delete_permission(self, app_client, db_session):
        _make_self_service_user(db_session, "carol")
        login(app_client, "carol", "somepass123")
        ticket_id = _create_ticket(app_client)

        _make_editor(db_session, "eddie")
        login(app_client, "eddie", "somepass123")
        r = app_client.delete(f"/api/tickets/{ticket_id}")
        assert r.status_code == 403

    def test_deleted_ticket_not_found_for_non_deleter(self, app_client, db_session):
        _make_self_service_user(db_session, "dana")
        login(app_client, "dana", "somepass123")
        ticket_id = _create_ticket(app_client)

        login(app_client, "admin", "adminpass123")
        app_client.delete(f"/api/tickets/{ticket_id}")

        _make_editor(db_session, "frank")
        login(app_client, "frank", "somepass123")
        r = app_client.get(f"/api/tickets/{ticket_id}")
        assert r.status_code == 404


class TestBulkActions:
    def test_bulk_delete_audits_per_ticket_and_excludes_from_lists(self, app_client, db_session):
        _make_self_service_user(db_session, "greg")
        login(app_client, "greg", "somepass123")
        ids = [_create_ticket(app_client, subject=f"Issue {i}") for i in range(3)]

        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/tickets/bulk/delete", json={"ticket_ids": ids})
        assert r.status_code == 200
        assert set(r.json()["deleted"]) == set(ids)

        r = app_client.get("/api/tickets")
        remaining = {t["id"] for t in r.json()["tickets"]}
        assert not remaining.intersection(ids)

        for tid in ids:
            row = db_session.query(AuditLog).filter_by(action="ticket_deleted", target=f"TCK-{tid}").first()
            assert row is not None

    def test_bulk_delete_requires_delete_permission(self, app_client, db_session):
        _make_self_service_user(db_session, "hank")
        login(app_client, "hank", "somepass123")
        ids = [_create_ticket(app_client)]

        _make_editor(db_session, "iris")
        login(app_client, "iris", "somepass123")
        r = app_client.post("/api/tickets/bulk/delete", json={"ticket_ids": ids})
        assert r.status_code == 403

    def test_bulk_close_and_resolve(self, app_client, db_session):
        _make_self_service_user(db_session, "jill")
        login(app_client, "jill", "somepass123")
        ids = [_create_ticket(app_client, subject=f"T{i}") for i in range(2)]

        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/tickets/bulk/close", json={"ticket_ids": ids})
        assert r.status_code == 200
        assert set(r.json()["closed"]) == set(ids)
        for tid in ids:
            r = app_client.get(f"/api/tickets/{tid}")
            assert r.json()["status"] == "closed"

    def test_bulk_resolve_skips_an_already_closed_ticket(self, app_client, db_session):
        """A closed ticket can't jump straight to resolved without being
        reopened first -- same Status Workflow Rules the single-ticket
        PATCH endpoint and bulk_close_tickets already enforce. Bulk
        resolve is expected to silently skip it (not error the whole
        batch), same "skip, don't fail" posture as every other guard in
        these bulk endpoints."""
        _make_self_service_user(db_session, "liam")
        login(app_client, "liam", "somepass123")
        ids = [_create_ticket(app_client, subject=f"U{i}") for i in range(2)]

        login(app_client, "admin", "adminpass123")
        app_client.post("/api/tickets/bulk/close", json={"ticket_ids": [ids[0]]})

        r = app_client.post("/api/tickets/bulk/resolve", json={"ticket_ids": ids})
        assert r.status_code == 200
        assert r.json()["resolved"] == [ids[1]]
        assert ids[0] in r.json()["skipped"]
        assert app_client.get(f"/api/tickets/{ids[0]}").json()["status"] == "closed"
        assert app_client.get(f"/api/tickets/{ids[1]}").json()["status"] == "resolved"

    def test_bulk_assign(self, app_client, db_session):
        _make_self_service_user(db_session, "kim")
        login(app_client, "kim", "somepass123")
        ids = [_create_ticket(app_client)]

        login(app_client, "admin", "adminpass123")
        admin_user = db_session.query(User).filter_by(username="admin").first()
        r = app_client.post("/api/tickets/bulk/assign", json={"ticket_ids": ids, "assigned_admin_id": admin_user.id})
        assert r.status_code == 200
        assert ids[0] in r.json()["assigned"]
        r = app_client.get(f"/api/tickets/{ids[0]}")
        assert r.json()["assigned_admin"] == admin_user.display_name

    def test_bulk_export_csv_shape(self, app_client, db_session):
        _make_self_service_user(db_session, "liam")
        login(app_client, "liam", "somepass123")
        ids = [_create_ticket(app_client, subject="Export Me")]

        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/tickets/bulk/export", json={"ticket_ids": ids})
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        lines = body["csv"].strip().splitlines()
        header = lines[0]
        assert header == "Subject,Category,Priority,Status,Assigned To,Created,Updated"
        assert "Export Me" in lines[1]
