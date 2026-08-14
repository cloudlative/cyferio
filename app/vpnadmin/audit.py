from sqlalchemy.orm import Session

from .models import AuditLog, User


def log_action(db: Session, user: User, action: str, *, target: str | None = None, detail: str | None = None, success: bool = True) -> None:
    """Records a state-changing action. Deliberately not used for read-only
    endpoints (list/status/check) -- see AuditLog's docstring for why."""
    entry = AuditLog(
        username=user.username,
        action=action,
        target=target,
        detail=(detail or "")[:2000],  # guard against an unexpectedly huge stderr blob
        success=success,
    )
    db.add(entry)
    db.commit()
