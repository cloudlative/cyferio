"""Support Ticketing System, phase 3 -- fan-out for both notification
channels (the in-app bell's TicketNotification rows, see routes/
notifications.py, and outbound email) at the events the feature spec
calls out: ticket created, a reply on either side, reopened, marked
critical, and status changed (covers resolved/closed).

Admin-side recipients are computed live from role grants (every account
with any-scope support_tickets update/manage) rather than a stored
subscription list, same reasoning as routes/tickets.py's
list_assignable_admins. Admin EMAIL alerts go to the single configured
admin_notification_email (app_settings.runtime), same as every other
notify_admin_on_* toggle in this app -- there's no per-admin-address
infra to fan an email out to each individually; the in-app bell is what
gives every admin account its own notification regardless.

Admin email is gated per-event via notification_prefs.py (see
_notify_admins below) rather than the one all-or-nothing
notify_admin_on_ticket_created toggle this replaced (that column is now
inert legacy data, read exactly once by app_settings.
migrate_ticket_email_notify_types to seed the new per-event settings on
upgrade). The TicketNotification row itself is ALWAYS written regardless
of this or any bell preference -- notification_prefs' bell_notify_types
setting is enforced at READ time instead (routes/notifications.py's GET
filters what's actually surfaced/counted), not by skipping the write --
see _notify_admins' own comment for why (a producer with its own
"already notified this" dedup-by-row-existence check, like main.py's
quota loop, would otherwise re-fire on every tick while muted).

User-side email is never gated by an admin toggle (see mailer.
send_ticket_notification_email's own docstring) -- these are
transactional to the ticket's own creator.

Every function here is best-effort: a failed email send or a notification
insert failing for the wrong reason must never turn an otherwise-
successful ticket action into a 500. Called from routes/me_tickets.py/
routes/tickets.py AFTER the triggering db.commit(), each managing its own
follow-up commit for the TicketNotification row(s) it adds."""
from sqlalchemy.orm import Session

from . import app_settings, mailer, notification_prefs, slack_notifications
from .models import SupportTicket, TicketNotification, User
from .permissions import has_permission_any_scope
from .support_tickets import status_label


def _admin_recipients(db: Session) -> list[User]:
    return [
        u for u in db.query(User).filter(User.is_active.is_(True), User.deleted.is_(False)).all()
        if has_permission_any_scope(db, u, "support_tickets", "update")
    ]


def _notify_admins(db: Session, ticket: SupportTicket, kind: str, message: str) -> None:
    recipients = [ticket.assigned_admin] if ticket.assigned_admin_id else _admin_recipients(db)
    # The TicketNotification row itself is ALWAYS written, regardless of
    # bell_notify_types -- that setting controls what routes/notifications.
    # py's GET surfaces to the user, not what gets recorded (see that
    # router's own filtering, added alongside notification_prefs.py).
    # Writing it unconditionally here keeps this module simple and, more
    # importantly, matches main.py's quota loop: THAT producer's own
    # "already notified this threshold" dedup check queries for a prior
    # QuotaNotification row's existence, so gating the write itself (an
    # earlier draft of this change did exactly that) would have made a
    # muted bell category re-fire its email every single loop tick
    # instead of just once per threshold-crossing -- read-time filtering
    # avoids that class of bug entirely, uniformly, for every producer.
    for admin in recipients:
        if admin is None:
            continue
        db.add(TicketNotification(user_id=admin.id, ticket_id=ticket.id, kind=kind, message=message))
    db.commit()
    if notification_prefs.ticket_email_enabled(app_settings.runtime.ticket_email_notify_types, kind):
        mailer.send_admin_notification(db=db, subject=f"{message}", body=f"Ticket #{ticket.id}: {ticket.subject}\nCategory: {ticket.category}\nPriority: {ticket.priority}")


def _notify_user(db: Session, ticket: SupportTicket, kind: str, message: str, *, email_headline: str, email_body: str | None = None) -> None:
    # Always written -- see _notify_admins' comment above on why bell
    # filtering happens at read time (routes/notifications.py), not here.
    db.add(TicketNotification(user_id=ticket.created_by_user_id, ticket_id=ticket.id, kind=kind, message=message))
    db.commit()
    creator = ticket.created_by
    if creator and creator.email:
        mailer.send_ticket_notification_email(
            db=db, to_address=creator.email, ticket_id=ticket.id, subject=ticket.subject,
            headline=email_headline, body_text=email_body,
        )


def ticket_created(db: Session, ticket: SupportTicket) -> None:
    _notify_admins(db, ticket, "ticket_created", f"New ticket #{ticket.id}: {ticket.subject}")
    slack_notifications.notify(db, "ticket_created", f":ticket: New ticket #{ticket.id}: {ticket.subject} (category: {ticket.category}, priority: {ticket.priority})")
    if ticket.priority == "critical":
        ticket_marked_critical(db, ticket)


def ticket_marked_critical(db: Session, ticket: SupportTicket) -> None:
    _notify_admins(db, ticket, "ticket_critical", f"Critical priority ticket #{ticket.id}: {ticket.subject}")


def ticket_assigned(db: Session, ticket: SupportTicket) -> None:
    """New event -- fired when routes/tickets.py's PATCH endpoint sets/
    changes assigned_admin_id (the existing "claim"/reassignment
    mechanism, see that router's own docstring). Notifies the newly-
    assigned admin specifically (not every admin, unlike ticket_created)
    since they're the one who now owns follow-up. Bell-only, no email --
    unchanged from before notification_prefs.py existed; "ticket_assigned"
    is a real bell event key but was never one of the 4 events
    TICKET_EMAIL_EVENTS covers, so there's no email toggle for it. Always
    written -- see _notify_admins' comment on why bell filtering happens
    at read time, not here."""
    if ticket.assigned_admin is None:
        return
    admin = ticket.assigned_admin
    db.add(TicketNotification(user_id=admin.id, ticket_id=ticket.id, kind="ticket_assigned",
                               message=f"Ticket #{ticket.id} assigned to you: {ticket.subject}"))
    db.commit()
    slack_notifications.notify(db, "ticket_assigned", f":inbox_tray: Ticket #{ticket.id} assigned to {admin.username}: {ticket.subject}")


def user_replied(db: Session, ticket: SupportTicket) -> None:
    _notify_admins(db, ticket, "ticket_reply", f"New reply on ticket #{ticket.id}: {ticket.subject}")


def ticket_reopened(db: Session, ticket: SupportTicket) -> None:
    _notify_admins(db, ticket, "ticket_reopened", f"Ticket #{ticket.id} reopened: {ticket.subject}")
    slack_notifications.notify(db, "ticket_reopened", f":repeat: Ticket #{ticket.id} reopened: {ticket.subject}")


def admin_replied(db: Session, ticket: SupportTicket) -> None:
    _notify_user(
        db, ticket, "ticket_reply", f"New reply on your ticket #{ticket.id}",
        email_headline="An administrator replied to your ticket",
    )


def ticket_marked_duplicate(db: Session, ticket: SupportTicket) -> None:
    """New event -- fired when routes/tickets.py's mark-duplicate endpoint
    sets duplicate_of_ticket_id. Notifies the ticket's own creator (not
    every admin -- this isn't an admin-actionable event the way
    ticket_created/user_replied are); the parent ticket's owner is not
    separately notified since nothing about THEIR ticket changed."""
    _notify_user(
        db, ticket, "ticket_status_changed",
        f"Ticket #{ticket.id} was marked as a duplicate of Ticket #{ticket.duplicate_of_ticket_id}",
        email_headline="Your ticket was marked as a duplicate",
        email_body=f"Please see Ticket #{ticket.duplicate_of_ticket_id} for the ongoing conversation.",
    )


def status_changed(db: Session, ticket: SupportTicket, old_status: str, new_status: str) -> None:
    _notify_user(
        db, ticket, "ticket_status_changed",
        f"Ticket #{ticket.id} status changed to {status_label(new_status)}",
        email_headline=f"Your ticket status changed to {status_label(new_status)}",
        email_body=f"Previous status: {status_label(old_status)}",
    )
    if new_status in ("resolved", "completed"):
        slack_notifications.notify(db, "ticket_resolved", f":white_check_mark: Ticket #{ticket.id} resolved: {ticket.subject}")
        if new_status == "completed":
            slack_notifications.notify(db, "upgrade_completed", f":white_check_mark: Upgrade ticket #{ticket.id} completed: {ticket.subject}")
    elif new_status == "failed":
        slack_notifications.notify(db, "upgrade_failed", f":x: Upgrade ticket #{ticket.id} failed: {ticket.subject}")
    else:
        slack_notifications.notify(db, "ticket_updated", f":memo: Ticket #{ticket.id} status changed to {status_label(new_status)}: {ticket.subject}")
