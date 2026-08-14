"""In-app notifications -- currently just QuotaNotification (bandwidth
quota threshold crossings, written by main.py's _quota_notification_loop),
but deliberately shaped as its own small router/table rather than folded
into me_vpn.py, since a notification concept naturally grows to cover
event types beyond VPN self-service (e.g. a future account/security
notice) that shouldn't have to live under the vpn-profile prefix.

Deliberately always operates on request.user's own rows, never an id/
username taken from the request -- same "own by construction, no separate
scope check needed" reasoning as me_vpn.py's own module docstring. Any
authenticated account (any role) can see its own notifications; there's
no permission object for this because "my own notifications" isn't a
module an admin would ever need to grant/revoke access to."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import require_user
from ..db import get_db
from ..models import QuotaNotification, User

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


def _serialize(n: QuotaNotification) -> dict:
    return {
        "id": n.id,
        "level": n.level,
        "message": n.message,
        "pct_used": n.pct_used,
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "read_at": n.read_at.isoformat() if n.read_at else None,
    }


@router.get("")
def list_my_notifications(user: User = Depends(require_user), db: Session = Depends(get_db)):
    rows = db.query(QuotaNotification).filter(QuotaNotification.user_id == user.id).order_by(QuotaNotification.created_at.desc()).limit(30).all()
    unread_count = db.query(QuotaNotification).filter(QuotaNotification.user_id == user.id, QuotaNotification.read_at.is_(None)).count()
    return {"notifications": [_serialize(n) for n in rows], "unread_count": unread_count}


@router.post("/{notification_id}/read")
def mark_read(notification_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    n = db.query(QuotaNotification).filter_by(id=notification_id, user_id=user.id).one_or_none()
    if n is None:
        # Never trust a path id blindly -- 404 whether it doesn't exist at
        # all or belongs to someone else, same shape either way so this
        # can't be used to probe for valid ids.
        raise HTTPException(status_code=404, detail="Notification not found.")
    if n.read_at is None:
        n.read_at = datetime.now(UTC)
        db.commit()
    return _serialize(n)


@router.post("/read-all")
def mark_all_read(user: User = Depends(require_user), db: Session = Depends(get_db)):
    now = datetime.now(UTC)
    updated = (
        db.query(QuotaNotification)
        .filter(QuotaNotification.user_id == user.id, QuotaNotification.read_at.is_(None))
        .update({"read_at": now}, synchronize_session=False)
    )
    db.commit()
    return {"marked_read": updated}
