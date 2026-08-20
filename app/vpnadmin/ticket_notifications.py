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

User-side email is never gated by an admin toggle (see mailer.
send_ticket_notification_email's own docstring) -- these are
transactional to the ticket's own creator.

Every function here is best-effort: a failed email send or a notification
insert failing for the wrong reason must never turn an otherwise-
successful ticket action into a 500. Called from routes/me_tickets.py/
routes/tickets.py AFTER the triggering db.commit(), each managing its own
follow-up commit for the TicketNotification row(s) it adds."""
from sqlalchemy.orm import Session

from . import app_settings, mailer
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
    for admin in recipients:
        if admin is None:
            continue
        db.add(TicketNotification(user_id=admin.id, ticket_id=ticket.id, kind=kind, message=message))
    db.commit()
    if app_settings.runtime.notify_admin_on_ticket_created:
        mailer.send_admin_notification(db=db, subject=f"{message}", body=f"Ticket #{ticket.id}: {ticket.subject}\nCategory: {ticket.category}\nPriority: {ticket.priority}")


def _notify_user(db: Session, ticket: SupportTicket, kind: str, message: str, *, email_headline: str, email_body: str | None = None) -> None:
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
    if ticket.priority == "critical":
        ticket_marked_critical(db, ticket)


def ticket_marked_critical(db: Session, ticket: SupportTicket) -> None:
    _notify_admins(db, ticket, "ticket_critical", f"Critical priority ticket #{ticket.id}: {ticket.subject}")


def user_replied(db: Session, ticket: SupportTicket) -> None:
    _notify_admins(db, ticket, "ticket_reply", f"New reply on ticket #{ticket.id}: {ticket.subject}")


def ticket_reopened(db: Session, ticket: SupportTicket) -> None:
    _notify_admins(db, ticket, "ticket_reopened", f"Ticket #{ticket.id} reopened: {ticket.subject}")


def admin_replied(db: Session, ticket: SupportTicket) -> None:
    _notify_user(
        db, ticket, "ticket_reply", f"New reply on your ticket #{ticket.id}",
        email_headline="An administrator replied to your ticket",
    )


def status_changed(db: Session, ticket: SupportTicket, old_status: str, new_status: str) -> None:
    _notify_user(
        db, ticket, "ticket_status_changed",
        f"Ticket #{ticket.id} status changed to {status_label(new_status)}",
        email_headline=f"Your ticket status changed to {status_label(new_status)}",
        email_body=f"Previous status: {status_label(old_status)}",
    )
