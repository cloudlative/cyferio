"""In-app notifications -- QuotaNotification (bandwidth quota threshold
crossings, written by main.py's _quota_notification_loop) and
TicketNotification (Support Ticketing System events, written by routes/
me_tickets.py/routes/tickets.py at the moment each event happens, not by
a background loop) are merged into one read/read-all contract here.
Deliberately two separate tables, not one shared/polymorphic table: the
two have genuinely different shapes (QuotaNotification's pct_used/
vpn_client_name/period_start-based unique constraint don't apply to a
ticket event, and vice versa a ticket_id FK doesn't belong on a quota
row) -- this router is what presents them as one list to the frontend.

Deliberately always operates on request.user's own rows, never an id/
username taken from the request -- same "own by construction, no separate
scope check needed" reasoning as me_vpn.py's own module docstring. Any
authenticated account (any role) can see its own notifications; there's
no permission object for this because "my own notifications" isn't a
module an admin would ever need to grant/revoke access to.

Each source table's own numeric id isn't unique ACROSS the two tables, so
every notification's `id` in this router's responses is prefixed
("quota:<id>" / "ticket:<id>") -- mark_read/mark_all_read parse that
prefix to know which table to update."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import require_user
from ..db import get_db
from ..models import QuotaNotification, TicketNotification, User

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


def _serialize_quota(n: QuotaNotification) -> dict:
    return {
        "id": f"quota:{n.id}",
        "kind": f"quota_{n.level}",
        "level": n.level,  # "warning" | "critical" -- drives .notif-item-level's existing color classes
        "message": n.message,
        "link_url": None,
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "read_at": n.read_at.isoformat() if n.read_at else None,
    }


def _ticket_link_url(n: TicketNotification) -> str | None:
    """Which page this notification's ticket actually opens in.

    Used to hardcode "/support/<id>" (the self-service page) unconditionally
    -- fine for a ticket's own creator, but wrong for every admin recipient
    of a ticket someone else filed: /support/<id> talks to GET /api/me/
    tickets/<id>, which 404s "Ticket not found" for anyone but the ticket's
    creator (routes/me_tickets.py's _require_own_ticket is deliberately
    "own tickets only" -- see that module's docstring), so an admin clicking
    their own "New ticket" bell notification landed on a page stuck showing
    that 404 with no way forward. Route each recipient to the page whose API
    will actually resolve their ticket: the notified user's own ticket goes
    to the self-service page, everyone else (i.e. every admin recipient --
    see ticket_notifications._notify_admins, the only caller that ever
    writes a TicketNotification for someone other than the ticket's
    creator) goes to the admin console page instead.

    n.ticket can be None if the row survived a ticket delete somehow (it
    shouldn't -- ticket_id has ondelete=CASCADE -- but a notification row
    must never crash the whole notifications list over one bad reference);
    the frontend already renders a missing link_url as a plain unclickable
    row (see app.js's notif-bell rendering), same as a quota notification's
    permanent link_url=None."""
    if n.ticket is None:
        return None
    if n.user_id == n.ticket.created_by_user_id:
        return f"/support/{n.ticket_id}"
    return f"/support-center/{n.ticket_id}"


def _serialize_ticket(n: TicketNotification) -> dict:
    return {
        "id": f"ticket:{n.id}",
        "kind": n.kind,
        "level": "info",  # neutral styling -- ticket events aren't a warning/critical severity scale
        "message": n.message,
        "link_url": _ticket_link_url(n),
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "read_at": n.read_at.isoformat() if n.read_at else None,
    }


@router.get("")
def list_my_notifications(user: User = Depends(require_user), db: Session = Depends(get_db)):
    quota_rows = (
        db.query(QuotaNotification).filter(QuotaNotification.user_id == user.id)
        .order_by(QuotaNotification.created_at.desc()).limit(30).all()
    )
    ticket_rows = (
        db.query(TicketNotification).filter(TicketNotification.user_id == user.id)
        .order_by(TicketNotification.created_at.desc()).limit(30).all()
    )
    merged = sorted(
        [_serialize_quota(n) for n in quota_rows] + [_serialize_ticket(n) for n in ticket_rows],
        key=lambda n: n["created_at"] or "", reverse=True,
    )[:30]
    unread_count = (
        db.query(QuotaNotification).filter(QuotaNotification.user_id == user.id, QuotaNotification.read_at.is_(None)).count()
        + db.query(TicketNotification).filter(TicketNotification.user_id == user.id, TicketNotification.read_at.is_(None)).count()
    )
    return {"notifications": merged, "unread_count": unread_count}


def _split_prefixed_id(notification_id: str) -> tuple[str, int]:
    if ":" not in notification_id:
        raise HTTPException(status_code=404, detail="Notification not found.")
    source, _, raw_id = notification_id.partition(":")
    try:
        return source, int(raw_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Notification not found.")


@router.post("/{notification_id}/read")
def mark_read(notification_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    source, raw_id = _split_prefixed_id(notification_id)
    model = {"quota": QuotaNotification, "ticket": TicketNotification}.get(source)
    if model is None:
        raise HTTPException(status_code=404, detail="Notification not found.")
    n = db.query(model).filter_by(id=raw_id, user_id=user.id).one_or_none()
    if n is None:
        # Never trust a path id blindly -- 404 whether it doesn't exist at
        # all or belongs to someone else, same shape either way so this
        # can't be used to probe for valid ids.
        raise HTTPException(status_code=404, detail="Notification not found.")
    if n.read_at is None:
        n.read_at = datetime.now(timezone.utc)
        db.commit()
    return _serialize_quota(n) if source == "quota" else _serialize_ticket(n)


@router.post("/read-all")
def mark_all_read(user: User = Depends(require_user), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    updated = (
        db.query(QuotaNotification).filter(QuotaNotification.user_id == user.id, QuotaNotification.read_at.is_(None))
        .update({"read_at": now}, synchronize_session=False)
    )
    updated += (
        db.query(TicketNotification).filter(TicketNotification.user_id == user.id, TicketNotification.read_at.is_(None))
        .update({"read_at": now}, synchronize_session=False)
    )
    db.commit()
    return {"marked_read": updated}
