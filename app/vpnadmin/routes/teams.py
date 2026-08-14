import json
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session, selectinload

from ..audit import log_action
from ..auth import require_user
from ..db import get_db
from ..models import Team, User
from ..permissions import require_permission

router = APIRouter(prefix="/api/teams", tags=["teams"])

require_admin = require_permission("teams", "manage")  # former auth.require_admin, see permissions.py

UNASSIGNED = "Unassigned"

_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def _valid_slug(v: str) -> str:
    v = v.strip().lower()
    if not v or len(v) > 64 or not _SLUG_RE.match(v):
        raise ValueError("Slug must be lowercase letters/numbers/hyphens only, e.g. 'devops-team'.")
    return v


def _valid_tags(v: list[str] | None) -> list[str] | None:
    if v is None:
        return None
    tags = [t.strip() for t in v if t.strip()]
    if any(len(t) > 32 for t in tags):
        raise ValueError("Each tag must be 32 characters or fewer.")
    return tags


def _derive_unique_slug(db: Session, name: str) -> str:
    """Same slugify-then-dedupe logic as db.py's _backfill_team_slugs, used
    here for the create-time case (a caller that never supplied a slug at
    all) rather than the one-time startup backfill of pre-existing rows."""
    base = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-") or "team"
    existing = {t.slug for t in db.query(Team).filter(Team.slug.isnot(None)).all()}
    slug = base
    n = 2
    while slug in existing:
        slug = f"{base}-{n}"
        n += 1
    return slug


class CreateTeamRequest(BaseModel):
    name: str
    # Optional: create_team() below derives it from `name` (same slugify
    # logic as db.py's _backfill_team_slugs) when omitted, so existing
    # callers that only ever sent `name` (including every test written
    # before this field existed) keep working unchanged.
    slug: str | None = None
    description: str | None = None
    tags: list[str] | None = None

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("Team name must be 1-64 characters.")
        if v == UNASSIGNED:
            raise ValueError(f"'{UNASSIGNED}' is reserved and can't be used as a team name.")
        return v

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str | None) -> str | None:
        return _valid_slug(v) if v else None

    @field_validator("description")
    @classmethod
    def _description(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        return v or None

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str] | None) -> list[str] | None:
        return _valid_tags(v)


class UpdateTeamRequest(BaseModel):
    """All fields optional -- PATCH semantics, only supplied fields change.
    No `members` here; membership stays on its own dedicated endpoints
    below (add_team_member/remove_team_member), same separation of concerns
    already established for this resource."""

    name: str | None = None
    slug: str | None = None
    description: str | None = None
    tags: list[str] | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("Team name must be 1-64 characters.")
        if v == UNASSIGNED:
            raise ValueError(f"'{UNASSIGNED}' is reserved and can't be used as a team name.")
        return v

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str | None) -> str | None:
        return _valid_slug(v) if v is not None else v

    @field_validator("description")
    @classmethod
    def _description(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        return v or None

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str] | None) -> list[str] | None:
        return _valid_tags(v)


def _team_detail(t: Team) -> dict:
    return {
        "id": t.id,
        "team": t.name,
        "slug": t.slug,
        "description": t.description,
        "tags": json.loads(t.tags) if t.tags else [],
    }


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
    # selectinload(User.teams): without it, every `t in u.teams` check below
    # lazy-fires its own SELECT the first time each user's `.teams` is
    # touched -- one extra query per user (N+1), the actual cause of this
    # page's slow load on any deployment with more than a handful of users.
    # This batches it into a single extra query total, up front.
    users = db.query(User).options(selectinload(User.teams)).filter(User.deleted.is_(False)).order_by(User.username).all()

    groups: list[dict] = []
    for t in teams:
        members = [_member(u) for u in users if t in u.teams]
        groups.append({**_team_detail(t), "count": len(members), "members": members})

    unassigned_members = [_member(u) for u in users if len(u.teams) == 0]
    groups.append(
        {
            "id": None,
            "team": UNASSIGNED,
            "slug": None,
            "description": None,
            "tags": [],
            "count": len(unassigned_members),
            "members": unassigned_members,
        }
    )

    return groups


@router.post("", status_code=201)
def create_team(body: CreateTeamRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(Team).filter(Team.name == body.name).first() is not None:
        raise HTTPException(status_code=409, detail=f"Team '{body.name}' already exists.")
    slug = body.slug or _derive_unique_slug(db, body.name)
    if db.query(Team).filter(Team.slug == slug).first() is not None:
        raise HTTPException(status_code=409, detail=f"A team with slug '{slug}' already exists.")
    team = Team(
        name=body.name,
        slug=slug,
        description=body.description,
        tags=json.dumps(body.tags) if body.tags else None,
    )
    db.add(team)
    db.commit()
    log_action(db, admin, "create_team", target=team.name)
    return {**_team_detail(team), "count": 0, "members": []}


@router.patch("/{team_id}")
def update_team(team_id: int, body: UpdateTeamRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    team = db.get(Team, team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found.")
    changes = []
    if body.name is not None and body.name != team.name:
        if db.query(Team).filter(Team.name == body.name, Team.id != team_id).first() is not None:
            raise HTTPException(status_code=409, detail=f"Team '{body.name}' already exists.")
        team.name = body.name
        changes.append("name")
    if body.slug is not None and body.slug != team.slug:
        if db.query(Team).filter(Team.slug == body.slug, Team.id != team_id).first() is not None:
            raise HTTPException(status_code=409, detail=f"A team with slug '{body.slug}' already exists.")
        team.slug = body.slug
        changes.append("slug")
    if "description" in body.model_fields_set:
        team.description = body.description
        changes.append("description")
    if "tags" in body.model_fields_set:
        team.tags = json.dumps(body.tags) if body.tags else None
        changes.append("tags")
    if changes:
        db.commit()
        log_action(db, admin, "update_team", target=team.name, detail=", ".join(changes))
    return _team_detail(team)


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
            detail=f"Cannot delete a team with members assigned ({len(active_members)}) -- reassign or remove its members first.",
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
