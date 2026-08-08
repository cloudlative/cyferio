from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import require_user
from ..db import get_db
from ..models import User

router = APIRouter(prefix="/api/teams", tags=["teams"])

UNASSIGNED = "Unassigned"


@router.get("")
def list_teams(_: User = Depends(require_user), db: Session = Depends(get_db)):
    """Groups active, non-deleted portal users by their free-text `team`
    field -- there's no separate Team table (team is just a profile field on
    User), so this is a read-only view built by grouping, not a distinct
    resource with its own CRUD. Deliberately open to any logged-in user
    (viewer or admin), unlike /api/users, since only non-sensitive fields
    are exposed here (no password/email/etc.)."""
    users = (
        db.query(User)
        .filter(User.deleted.is_(False))
        .order_by(User.username)
        .all()
    )
    groups: dict[str, list[dict]] = {}
    for u in users:
        team_name = (u.team or "").strip() or UNASSIGNED
        groups.setdefault(team_name, []).append({
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
            "role": u.role.value,
            "is_active": u.is_active,
        })

    def _sort_key(name: str):
        return (name == UNASSIGNED, name.lower())

    return [
        {"team": name, "count": len(members), "members": members}
        for name, members in sorted(groups.items(), key=lambda kv: _sort_key(kv[0]))
    ]
