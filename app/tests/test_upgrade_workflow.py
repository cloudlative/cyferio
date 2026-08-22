"""Upgrade Assignment Workflow -- claiming (self-assignment) and
reassigning a System Maintenance ticket via the EXISTING routes/tickets.py
PATCH endpoint (no parallel claim/ownership mechanism), the auto-advance
to "assigned" status on claim, the audit trail, and that assignment fires
an in-app notification following the existing merged-bell id-prefix
contract (routes/notifications.py)."""
from vpnadmin.auth import hash_password
from vpnadmin.models import AuditLog, Group, RoleDef, Role, SupportTicket, TicketNotification, User

from .conftest import login


def _make_second_admin(db_session, username="admin2", password="somepass123"):
    # Group-only permissions: a role only grants anything via group
    # membership now (see permissions.py's effective_role_ids).
    admin_role = db_session.query(RoleDef).filter_by(slug="admin").one()
    group = Group(name=f"{username}-admin-group", role_id=admin_role.id)
    db_session.add(group)
    db_session.flush()
    user = User(username=username, password_hash=hash_password(password), role=Role.admin, role_id=admin_role.id, group_id=group.id)
    db_session.add(user)
    db_session.commit()
    return user


def _make_sysmaint_ticket(db_session, admin, *, category="sysmaint_application_upgrade", status="open"):
    ticket = SupportTicket(
        created_by_user_id=admin.id, subject="Upgrade Cyferio from v1.0.0 to v1.1.0",
        category=category, priority="medium", status=status,
    )
    db_session.add(ticket)
    db_session.commit()
    return ticket


class TestClaim:
    def test_assigning_to_self_advances_status_to_assigned(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin)
        login(app_client, "admin", "adminpass123")

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin.id})
        assert r.status_code == 200
        body = r.json()
        assert body["assigned_admin"] == admin.display_name
        assert body["status"] == "assigned"

    def test_claim_does_not_override_an_explicit_status(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin)
        login(app_client, "admin", "adminpass123")

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin.id, "status": "in_progress"})
        assert r.status_code == 200
        assert r.json()["status"] == "in_progress"

    def test_claim_does_not_advance_a_ticket_already_past_open(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin, status="in_progress")
        login(app_client, "admin", "adminpass123")

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin.id})
        assert r.status_code == 200
        assert r.json()["status"] == "in_progress"

    def test_assignment_creates_in_app_notification_with_ticket_prefix(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin)
        login(app_client, "admin", "adminpass123")

        app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin.id})
        notif = db_session.query(TicketNotification).filter_by(user_id=admin.id, ticket_id=ticket.id, kind="ticket_assigned").one_or_none()
        assert notif is not None

        r = app_client.get("/api/notifications")
        assert r.status_code == 200
        ids = [n["id"] for n in r.json()["notifications"]]
        assert f"ticket:{notif.id}" in ids


class TestReassignment:
    def test_manage_permission_admin_can_reassign_a_ticket_someone_else_claimed(self, app_client, db_session):
        admin1 = db_session.query(User).filter_by(username="admin").one()
        admin2 = _make_second_admin(db_session)
        ticket = _make_sysmaint_ticket(db_session, admin1)
        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin1.id})

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin2.id})
        assert r.status_code == 200
        assert r.json()["assigned_admin"] == admin2.display_name

    def test_reassignment_is_audited_with_old_and_new_admin(self, app_client, db_session):
        admin1 = db_session.query(User).filter_by(username="admin").one()
        admin2 = _make_second_admin(db_session)
        ticket = _make_sysmaint_ticket(db_session, admin1)
        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin1.id})

        app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin2.id})
        log = (
            db_session.query(AuditLog)
            .filter(AuditLog.target == f"TCK-{ticket.id}", AuditLog.action == "ticket_updated")
            .order_by(AuditLog.id.desc()).first()
        )
        assert log is not None
        assert "admin" in log.detail and "admin2" in log.detail

    def test_clearing_assignment_is_audited(self, app_client, db_session):
        admin1 = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin1)
        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin1.id})

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"clear_assignment": True})
        assert r.status_code == 200
        assert r.json()["assigned_admin"] is None

    def test_viewer_cannot_assign_tickets(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin)
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"assigned_admin_id": admin.id})
        assert r.status_code == 403


class TestStatusTransitions:
    def test_completed_is_a_terminal_status(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin, status="in_progress")
        login(app_client, "admin", "adminpass123")

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"status": "completed"})
        assert r.status_code == 200
        assert r.json()["status"] == "completed"

    def test_failed_status_accepted(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin, status="in_progress")
        login(app_client, "admin", "adminpass123")

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"status": "failed"})
        assert r.status_code == 200
        assert r.json()["status"] == "failed"

    def test_cancelled_status_accepted(self, app_client, db_session):
        admin = db_session.query(User).filter_by(username="admin").one()
        ticket = _make_sysmaint_ticket(db_session, admin, status="open")
        login(app_client, "admin", "adminpass123")

        r = app_client.patch(f"/api/tickets/{ticket.id}", json={"status": "cancelled"})
        assert r.status_code == 200
        assert r.json()["status"] == "cancelled"
