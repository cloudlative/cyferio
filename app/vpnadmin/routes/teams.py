from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..audit import log_action
from ..auth import require_admin, require_user
from ..db import get_db
from ..models import Team, User

router = APIRouter(prefix="/api/teams", tags=["teams"])

UNASSIGNED = "Unassigned"


class CreateTeamRequest(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("Team name must be 1-64 characters.")
        if v == UNASSIGNED:
            raise ValueError(f"'{UNASSIGNED}' is reserved and can't be used as a team name.")
        return v


@router.get("")
def list_teams(_: User = Depends(require_user), db: Session = Depends(get_db)):
    """Groups active, non-deleted portal users by team. Built from the Team
    table so a team with zero members still shows up (with count 0), not
    just teams that happen to already have someone assigned. Deliberately
    open to any logged-in user (viewer or admin), unlike /api/users, since
    only non-sensitive fields are exposed here (no password/email/etc.)."""
    teams = db.query(Team).order_by(Team.name).all()
    users = db.query(User).filter(User.deleted.is_(False)).order_by(User.username).all()

    def _member(u: User) -> dict:
        return {
            "id": u.id,
            "username": u.username,
            "display_name": u.display_name,
            "role": u.role.value,
            "is_active": u.is_active,
        }

    groups: list[dict] = []
    for t in teams:
        members = [_member(u) for u in users if u.team_id == t.id]
        groups.append({"id": t.id, "team": t.name, "count": len(members), "members": members})

    unassigned_members = [_member(u) for u in users if u.team_id is None]
    groups.append({"id": None, "team": UNASSIGNED, "count": len(unassigned_members), "members": unassigned_members})

    return groups


@router.post("", status_code=201)
def create_team(body: CreateTeamRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(Team).filter(Team.name == body.name).first() is not None:
        raise HTTPException(status_code=409, detail=f"Team '{body.name}' already exists.")
    team = Team(name=body.name)
    db.add(team)
    db.commit()
    log_action(db, admin, "create_team", target=team.name)
    return {"id": team.id, "team": team.name, "count": 0, "members": []}


@router.delete("/{team_id}")
def delete_team(team_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Deletes the team itself; members are NOT cascade-deleted -- they're
    simply unassigned (team_id set to NULL, falling back to "Unassigned")."""
    team = db.get(Team, team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found.")
    member_count = db.query(User).filter(User.team_id == team.id).update({"team_id": None})
    db.delete(team)
    db.commit()
    log_action(db, admin, "delete_team", target=team.name, detail=f"{member_count} member(s) unassigned")
    return {"message": f"Team '{team.name}' deleted. {member_count} member(s) moved to Unassigned."}
