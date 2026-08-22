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
        # The admin is not this ticket's creator, so their own copy of the
        # notification must link to the admin console page -- see
        # routes/notifications.py's _ticket_link_url(). Landing an admin on
        # /support/<id> (the self-service page) 404s "Ticket not found"
        # there, since GET /api/me/tickets/<id> only ever resolves the
        # caller's own tickets.
        matches = [n for n in r.json()["notifications"] if n["link_url"] == f"/support-center/{ticket_id}"]
        assert len(matches) == 1
        notif_id = matches[0]["id"]
        assert notif_id.startswith("ticket:")

        r = app_client.post(f"/api/notifications/{notif_id}/read")
        assert r.status_code == 200
        assert r.json()["read_at"] is not None

    def test_ticket_creators_own_notification_links_to_the_self_service_page(self, app_client, db_session):
        """The flip side of the admin-routing test above: when the
        notified user IS the ticket's own creator (e.g. an admin-side reply
        notifying the creator back), the link must stay on the self-service
        page, not the admin console one -- see _ticket_link_url()."""
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        login(app_client, "admin", "adminpass123")
        app_client.post(f"/api/tickets/{ticket_id}/replies", data={"body": "Looking into it."})

        login(app_client, "alice", "somepass123")
        r = app_client.get("/api/notifications")
        assert r.status_code == 200
        matches = [n for n in r.json()["notifications"] if n["link_url"] == f"/support/{ticket_id}"]
        assert len(matches) == 1

    def test_unknown_prefixed_id_404s_cleanly(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/notifications/bogus:1/read")
        assert r.status_code == 404
        r = app_client.post("/api/notifications/ticket:999999/read")
        assert r.status_code == 404


class TestNotificationPreferences:
    """notification_prefs.py's per-event Ticket Email / Bell settings
    (Settings -> Support Ticketing / Notifications sections) -- see that
    module's own docstring for why the two channels are gated completely
    independently, and why bell filtering happens at READ time (routes/
    notifications.py) rather than by skipping the TicketNotification
    write itself."""

    def test_bell_disabled_hides_row_but_email_stays_on(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={
            "bell_notify_types": {"ticket_created": False},
            "ticket_email_notify_types": {"ticket_created": True},
        })
        assert r.status_code == 200

        from vpnadmin import ticket_notifications
        sent = {}
        orig = ticket_notifications.mailer.send_admin_notification
        ticket_notifications.mailer.send_admin_notification = lambda **kw: sent.update(kw)
        try:
            login(app_client, "alice", "somepass123")
            ticket_id = _create_ticket(app_client).json()["id"]
        finally:
            ticket_notifications.mailer.send_admin_notification = orig
        assert sent, "ticket_email_notify_types has ticket_created on -- email must still send"

        admin = db_session.query(User).filter_by(username="admin").one()
        row = db_session.query(TicketNotification).filter_by(user_id=admin.id, ticket_id=ticket_id, kind="ticket_created").one_or_none()
        assert row is not None, "the row is still WRITTEN regardless of the bell preference (read-time filter only)"

        login(app_client, "admin", "adminpass123")
        r2 = app_client.get("/api/notifications")
        kinds = [n["kind"] for n in r2.json()["notifications"]]
        assert "ticket_created" not in kinds, "but it must not be SURFACED once bell_notify_types disables it"

    def test_email_disabled_stops_admin_email_but_bell_row_still_appears(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"ticket_email_notify_types": {"ticket_created": False}})
        assert r.status_code == 200

        from vpnadmin import ticket_notifications
        sent = {}
        orig = ticket_notifications.mailer.send_admin_notification
        ticket_notifications.mailer.send_admin_notification = lambda **kw: sent.update(kw)
        try:
            login(app_client, "alice", "somepass123")
            _create_ticket(app_client)
        finally:
            ticket_notifications.mailer.send_admin_notification = orig
        assert not sent, "ticket_email_notify_types has ticket_created off -- no admin email"

        login(app_client, "admin", "adminpass123")
        r2 = app_client.get("/api/notifications")
        kinds = [n["kind"] for n in r2.json()["notifications"]]
        assert "ticket_created" in kinds, "bell is untouched by the email-only preference"

    def test_unread_count_respects_bell_preference(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "admin", "adminpass123")
        # Clean slate -- other tests in this class/session may have left
        # admin with unread notifications of their own; a bare delta
        # comparison below would otherwise be sensitive to whatever ran
        # before this test.
        app_client.post("/api/notifications/read-all")
        before = app_client.get("/api/notifications").json()["unread_count"]

        login(app_client, "alice", "somepass123")
        _create_ticket(app_client)

        login(app_client, "admin", "adminpass123")
        after = app_client.get("/api/notifications").json()["unread_count"]
        assert after == before + 1

        # Muting ticket_created is a READ-TIME filter (see routes/
        # notifications.py's module docstring) -- it applies to every
        # currently-unread row of that kind, not just ones written after
        # the mute. The first ticket's still-unread notification is
        # ALREADY kind="ticket_created", so it drops out of the count too,
        # the same as a second (also muted) ticket created afterwards
        # would never have been counted at all -- both land back at
        # `before`, not at `after`.
        app_client.patch("/api/settings", json={"bell_notify_types": {"ticket_created": False}})
        after_mute = app_client.get("/api/notifications").json()["unread_count"]
        assert after_mute == before

        login(app_client, "alice", "somepass123")
        _create_ticket(app_client)
        login(app_client, "admin", "adminpass123")
        after2 = app_client.get("/api/notifications").json()["unread_count"]
        assert after2 == before, "a new ticket_created row must not count either while muted"

    def test_user_email_disabled_stops_creator_email_but_bell_row_still_appears(self, app_client, db_session):
        """user_email_notify_types gates ticket_notifications._notify_user's
        email send to the ticket's own CREATOR -- entirely independent of
        ticket_email_notify_types (the admin side of the same events, see
        the two tests above)."""
        alice = _make_self_service_user(db_session, "alice")
        alice.email = "alice@example.com"
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"user_email_notify_types": {"ticket_reply": False}})
        assert r.status_code == 200

        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        from vpnadmin import ticket_notifications
        sent = {}
        orig = ticket_notifications.mailer.send_ticket_notification_email
        ticket_notifications.mailer.send_ticket_notification_email = lambda **kw: sent.update(kw)
        try:
            login(app_client, "admin", "adminpass123")
            r2 = app_client.post(f"/api/tickets/{ticket_id}/replies", data={"body": "we're looking into it"})
            assert r2.status_code == 201
        finally:
            ticket_notifications.mailer.send_ticket_notification_email = orig
        assert not sent, "user_email_notify_types has ticket_reply off -- no email to the creator"

        login(app_client, "alice", "somepass123")
        kinds = [n["kind"] for n in app_client.get("/api/notifications").json()["notifications"]]
        assert "ticket_reply" in kinds, "the bell row is untouched by the user-email-only preference"

    def test_user_email_enabled_by_default(self, app_client, db_session):
        """No settings.py PATCH at all -- effective_user_email_types must
        default every key to True (this subdivides behavior that was
        previously unconditional, see notification_prefs.py's own
        docstring), so an upgraded deployment keeps emailing ticket
        creators exactly as before until an admin opts something out."""
        alice = _make_self_service_user(db_session, "alice")
        alice.email = "alice@example.com"
        db_session.commit()
        login(app_client, "alice", "somepass123")
        ticket_id = _create_ticket(app_client).json()["id"]

        from vpnadmin import ticket_notifications
        sent = {}
        orig = ticket_notifications.mailer.send_ticket_notification_email
        ticket_notifications.mailer.send_ticket_notification_email = lambda **kw: sent.update(kw)
        try:
            login(app_client, "admin", "adminpass123")
            app_client.post(f"/api/tickets/{ticket_id}/replies", data={"body": "we're looking into it"})
        finally:
            ticket_notifications.mailer.send_ticket_notification_email = orig
        assert sent, "an unconfigured user_email_notify_types must default to on"


class TestMigrateTicketEmailNotifyTypes:
    def test_seeds_every_key_from_the_legacy_toggle(self, db_session):
        from vpnadmin.app_settings import get_settings_row, migrate_ticket_email_notify_types
        from vpnadmin.notification_prefs import TICKET_EMAIL_KEYS, effective_ticket_email_types

        row = get_settings_row(db_session)
        row.notify_admin_on_ticket_created = True
        db_session.commit()

        migrate_ticket_email_notify_types(db_session)
        db_session.refresh(row)
        effective = effective_ticket_email_types(row.ticket_email_notify_types)
        assert effective == {key: True for key in TICKET_EMAIL_KEYS}

    def test_fresh_install_seeds_every_key_false(self, db_session):
        from vpnadmin.app_settings import get_settings_row, migrate_ticket_email_notify_types
        from vpnadmin.notification_prefs import TICKET_EMAIL_KEYS, effective_ticket_email_types

        row = get_settings_row(db_session)
        assert row.notify_admin_on_ticket_created is None
        assert row.ticket_email_notify_types is None

        migrate_ticket_email_notify_types(db_session)
        db_session.refresh(row)
        effective = effective_ticket_email_types(row.ticket_email_notify_types)
        assert effective == {key: False for key in TICKET_EMAIL_KEYS}

    def test_idempotent_a_later_legacy_toggle_flip_is_ignored(self, db_session):
        from vpnadmin.app_settings import get_settings_row, migrate_ticket_email_notify_types
        from vpnadmin.notification_prefs import effective_ticket_email_types

        row = get_settings_row(db_session)
        row.notify_admin_on_ticket_created = True
        db_session.commit()
        migrate_ticket_email_notify_types(db_session)
        db_session.refresh(row)
        first_pass = row.ticket_email_notify_types

        row.notify_admin_on_ticket_created = False
        db_session.commit()
        migrate_ticket_email_notify_types(db_session)
        db_session.refresh(row)
        assert row.ticket_email_notify_types == first_pass
        assert all(effective_ticket_email_types(row.ticket_email_notify_types).values())
