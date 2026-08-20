"""Support Ticketing System, phase 3 -- in-app notification fan-out
(app/vpnadmin/ticket_notifications.py, routes/notifications.py's merged
bell feed). Email sends aren't mocked -- no EmailProvider is configured
in the test DB, so mailer.send_admin_notification/
send_ticket_notification_email both fail soft (return False) exactly as
they're designed to; these tests only assert on the TicketNotification
rows and the merged /api/notifications contract."""
from vpnadmin.models import TicketNotification, User

from .test_support_tickets import _create_ticket, _make_self_service_user

from .conftest import login


class TestAdminSideNotifications:
    def test_new_ticket_notifies_every_admin_capable_account(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        admin = db_session.query(User).filter_by(username="admin").one()
        n = db_session.query(TicketNotification).filter_by(user_id=admin.id, ticket_id=ticket_id, kind="ticket_created").one_or_none()
        assert n is not None

    def test_critical_priority_at_creation_also_raises_a_critical_notification(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client, priority="critical").json()["id"]

        admin = db_session.query(User).filter_by(username="admin").one()
        n = db_session.query(TicketNotification).filter_by(user_id=admin.id, ticket_id=ticket_id, kind="ticket_critical").one_or_none()
        assert n is not None

    def test_user_reply_notifies_the_assigned_admin_only_when_assigned(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        _make_self_service_user(db_session, "carol")  # unrelated user, never assigned
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        admin = db_session.query(User).filter_by(username="admin").one()
        app_client.patch(f"/api/tickets/{ticket_id}", json={"assigned_admin_id": admin.id})

        login(app_client, "alice", "somepass123")
        app_client.post(f"/api/me/tickets/{ticket_id}/replies", data={"body": "any update?"})

        n = db_session.query(TicketNotification).filter_by(user_id=admin.id, ticket_id=ticket_id, kind="ticket_reply").one_or_none()
        assert n is not None

    def test_reopen_notifies_admins(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "resolved"})

        login(app_client, "alice", "somepass123")
        app_client.post(f"/api/me/tickets/{ticket_id}/reopen")

        admin = db_session.query(User).filter_by(username="admin").one()
        n = db_session.query(TicketNotification).filter_by(user_id=admin.id, ticket_id=ticket_id, kind="ticket_reopened").one_or_none()
        assert n is not None


class TestUserSideNotifications:
    def test_admin_reply_notifies_the_ticket_creator(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.post(f"/api/tickets/{ticket_id}/replies", data={"body": "Looking into it."})

        alice = db_session.query(User).filter_by(username="alice").one()
        n = db_session.query(TicketNotification).filter_by(user_id=alice.id, ticket_id=ticket_id, kind="ticket_reply").one_or_none()
        assert n is not None

    def test_internal_note_does_not_notify_the_ticket_creator(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.post(f"/api/tickets/{ticket_id}/replies", data={"body": "internal only", "is_internal_note": "true"})

        alice = db_session.query(User).filter_by(username="alice").one()
        assert db_session.query(TicketNotification).filter_by(user_id=alice.id, ticket_id=ticket_id).count() == 0

    def test_status_change_notifies_the_ticket_creator(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.patch(f"/api/tickets/{ticket_id}", json={"status": "resolved"})

        alice = db_session.query(User).filter_by(username="alice").one()
        n = db_session.query(TicketNotification).filter_by(user_id=alice.id, ticket_id=ticket_id, kind="ticket_status_changed").one_or_none()
        assert n is not None
        assert "Resolved" in n.message


class TestMergedNotificationBell:
    def test_ticket_notification_appears_in_the_merged_feed_and_can_be_marked_read(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/notifications")
        assert r.status_code == 200
        matches = [n for n in r.json()["notifications"] if n["link_url"] == f"/support/{ticket_id}"]
        assert len(matches) == 1
        notif_id = matches[0]["id"]
        assert notif_id.startswith("ticket:")

        r = app_client.post(f"/api/notifications/{notif_id}/read")
        assert r.status_code == 200
        assert r.json()["read_at"] is not None

    def test_unknown_prefixed_id_404s_cleanly(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/notifications/bogus:1/read")
        assert r.status_code == 404
        r = app_client.post("/api/notifications/ticket:999999/read")
        assert r.status_code == 404
