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


def _member(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "role": u.role.value,
        "is_active": u.is_active,
    }


@router.get("")
def list_teams(_: User = Depends(require_user), db: Session = Depends(get_db)):
    """Groups active, non-deleted portal users by team -- a user can now
    belong to several teams at once (see User.teams / the user_teams
    association table), so a user may appear under more than one group
    here, unlike a traditional single-owner grouping. Built from the Team
    table so a team with zero members still shows up (with count 0), not
    just teams that happen to already have someone assigned. Deliberately
    open to any logged-in user (viewer or admin), unlike /api/users, since
    only non-sensitive fields are exposed here (no password/email/etc.)."""
    teams = db.query(Team).order_by(Team.name).all()
    users = db.query(User).filter(User.deleted.is_(False)).order_by(User.username).all()

    groups: list[dict] = []
    for t in teams:
        members = [_member(u) for u in users if t in u.teams]
        groups.append({"id": t.id, "team": t.name, "count": len(members), "members": members})

    unassigned_members = [_member(u) for u in users if len(u.teams) == 0]
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
    """Deletes a team, but only if it currently has no members -- unlike
    the previous behavior (auto-unassigning members then deleting), the
    caller must explicitly reassign/remove every member first. This avoids
    a team disappearing out from under people who are still on it."""
    team = db.get(Team, team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found.")
    active_members = [u for u in team.members if not u.deleted]
    if active_members:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete a team with members assigned ({len(active_members)}) -- "
                   f"reassign or remove its members first.",
        )
    name = team.name
    db.delete(team)
    db.commit()
    log_action(db, admin, "delete_team", target=name)
    return {"message": f"Team '{name}' deleted."}


class MembershipRequest(BaseModel):
    user_id: int


@router.post("/{team_id}/members", status_code=201)
def add_team_member(team_id: int, body: MembershipRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Adds one user to one team, without disturbing any of their other
    team memberships -- the per-team complement to PATCH /api/users/{id}
    with team_ids (which replaces a user's whole membership list at once)."""
    team = db.get(Team, team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found.")
    user = db.get(User, body.user_id)
    if user is None or user.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    if team not in user.teams:
        user.teams.append(team)
        db.commit()
        log_action(db, admin, "add_team_member", target=team.name, detail=user.username)
    return {"message": f"'{user.username}' added to '{team.name}'."}


@router.delete("/{team_id}/members/{user_id}")
def remove_team_member(team_id: int, user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    team = db.get(Team, team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if team in user.teams:
        user.teams.remove(team)
        db.commit()
        log_action(db, admin, "remove_team_member", target=team.name, detail=user.username)
    return {"message": f"'{user.username}' removed from '{team.name}'."}
