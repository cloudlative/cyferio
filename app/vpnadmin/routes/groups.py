import json
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session, selectinload

from ..audit import log_action
from ..auth import require_user
from ..db import get_db
from ..models import RoleDef, Group, User
from ..permissions import require_permission

router = APIRouter(prefix="/api/groups", tags=["groups"])

require_admin = require_permission("groups", "manage")  # former auth.require_admin, see permissions.py

UNASSIGNED = "Unassigned"

_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def _valid_slug(v: str) -> str:
    v = v.strip().lower()
    if not v or len(v) > 64 or not _SLUG_RE.match(v):
        raise ValueError("Slug must be lowercase letters/numbers/hyphens only, e.g. 'devops-group'.")
    return v


def _valid_tags(v: list[str] | None) -> list[str] | None:
    if v is None:
        return None
    tags = [t.strip() for t in v if t.strip()]
    if any(len(t) > 32 for t in tags):
        raise ValueError("Each tag must be 32 characters or fewer.")
    return tags


def _derive_unique_slug(db: Session, name: str) -> str:
    """Same slugify-then-dedupe logic as db.py's _backfill_group_slugs, used
    here for the create-time case (a caller that never supplied a slug at
    all) rather than the one-time startup backfill of pre-existing rows."""
    base = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-") or "group"
    existing = {t.slug for t in db.query(Group).filter(Group.slug.isnot(None)).all()}
    slug = base
    n = 2
    while slug in existing:
        slug = f"{base}-{n}"
        n += 1
    return slug


class CreateGroupRequest(BaseModel):
    name: str
    # Optional: create_group() below derives it from `name` (same slugify
    # logic as db.py's _backfill_group_slugs) when omitted, so existing
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
            raise ValueError("Group name must be 1-64 characters.")
        if v == UNASSIGNED:
            raise ValueError(f"'{UNASSIGNED}' is reserved and can't be used as a group name.")
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


class UpdateGroupRequest(BaseModel):
    """All fields optional -- PATCH semantics, only supplied fields change.
    No `members` here; membership stays on its own dedicated endpoints
    below (add_group_member/remove_group_member), same separation of concerns
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
            raise ValueError("Group name must be 1-64 characters.")
        if v == UNASSIGNED:
            raise ValueError(f"'{UNASSIGNED}' is reserved and can't be used as a group name.")
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


def _role_brief(r: RoleDef) -> dict:
    return {"id": r.id, "slug": r.slug, "name": r.name}


def _group_detail(t: Group) -> dict:
    return {
        "id": t.id,
        "group": t.name,
        "slug": t.slug,
        "description": t.description,
        "tags": json.loads(t.tags) if t.tags else [],
        # Roles assigned to this group -- inherited by every current member.
        # Groups are the ONLY source of a user's effective permissions (see
        # permissions.py's effective_role_ids) -- a group with zero roles
        # assigned grants its members nothing.
        "roles": [_role_brief(r) for r in t.role_defs],
    }


def _member(u: User) -> dict:
    # Deliberately NOT u.role/u.role_id -- under the group-only permission
    # model neither one determines this user's actual access any more (see
    # permissions.py's effective_role_ids), so showing either here would be
    # stale/misleading. "effective_roles" instead: the union of every role
    # assigned to every group this user belongs to (not just the group this
    # member listing is nested under -- a user may be in several groups),
    # i.e. the same role set effective_role_ids() would compute --
    # including the super_admin hardcoded exemption (see
    # User.effective_role_names' own docstring): that account shows its
    # real role here even with zero group memberships, same as everywhere
    # else in this app that displays a role. Relies on the caller having
    # selectinload'd both User.groups and Group.role_defs (see list_groups
    # below) so this stays O(1) queries, not N+1.
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "effective_roles": u.effective_role_names,
        "is_active": u.is_active,
    }


@router.get("")
def list_groups(_: User = Depends(require_user), db: Session = Depends(get_db)):
    """Groups active, non-deleted portal users by group -- a user can now
    belong to several groups at once (see User.groups / the user_groups
    association table), so a user may appear under more than one group
    here, unlike a traditional single-owner grouping. Built from the Group
    table so a group with zero members still shows up (with count 0), not
    just groups that happen to already have someone assigned. Deliberately
    open to any logged-in user (viewer or admin), unlike /api/users, since
    only non-sensitive fields are exposed here (no password/email/etc.)."""
    # selectinload(Group.role_defs): same N+1 reasoning as selectinload(User.
    # groups) below, just for the roles-assigned-to-group list _group_detail
    # now includes -- one extra query total for every group's roles, instead
    # of one lazy SELECT per group the first time `.role_defs` is touched.
    group_rows = db.query(Group).options(selectinload(Group.role_defs)).order_by(Group.name).all()
    # selectinload(User.groups): without it, every `t in u.groups` check below
    # lazy-fires its own SELECT the first time each user's `.groups` is
    # touched -- one extra query per user (N+1), the actual cause of this
    # page's slow load on any deployment with more than a handful of users.
    # This batches it into a single extra query total, up front.
    users = (
        db.query(User)
        # .selectinload(Group.role_defs) chained on: _member() below reads
        # each member's effective_roles via u.groups[*].role_defs -- without
        # this, that's a lazy SELECT per group per user (N+1 on top of N+1).
        # selectinload(User.role_def): _member() -> User.effective_role_names'
        # super_admin exemption check needs it.
        .options(selectinload(User.groups).selectinload(Group.role_defs), selectinload(User.role_def))
        .filter(User.deleted.is_(False))
        .order_by(User.username)
        .all()
    )

    groups: list[dict] = []
    for t in group_rows:
        members = [_member(u) for u in users if t in u.groups]
        groups.append({**_group_detail(t), "count": len(members), "members": members})

    unassigned_members = [_member(u) for u in users if len(u.groups) == 0]
    groups.append({
        "id": None, "group": UNASSIGNED, "slug": None, "description": None, "tags": [], "roles": [],
        "count": len(unassigned_members), "members": unassigned_members,
    })

    return groups


@router.post("", status_code=201)
def create_group(body: CreateGroupRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(Group).filter(Group.name == body.name).first() is not None:
        raise HTTPException(status_code=409, detail=f"Group '{body.name}' already exists.")
    slug = body.slug or _derive_unique_slug(db, body.name)
    if db.query(Group).filter(Group.slug == slug).first() is not None:
        raise HTTPException(status_code=409, detail=f"A group with slug '{slug}' already exists.")
    group = Group(
        name=body.name, slug=slug, description=body.description,
        tags=json.dumps(body.tags) if body.tags else None,
    )
    db.add(group)
    db.commit()
    log_action(db, admin, "create_group", target=group.name)
    return {**_group_detail(group), "count": 0, "members": []}


@router.patch("/{group_id}")
def update_group(group_id: int, body: UpdateGroupRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    changes = []
    if body.name is not None and body.name != group.name:
        if db.query(Group).filter(Group.name == body.name, Group.id != group_id).first() is not None:
            raise HTTPException(status_code=409, detail=f"Group '{body.name}' already exists.")
        group.name = body.name
        changes.append("name")
    if body.slug is not None and body.slug != group.slug:
        if db.query(Group).filter(Group.slug == body.slug, Group.id != group_id).first() is not None:
            raise HTTPException(status_code=409, detail=f"A group with slug '{body.slug}' already exists.")
        group.slug = body.slug
        changes.append("slug")
    if "description" in body.model_fields_set:
        group.description = body.description
        changes.append("description")
    if "tags" in body.model_fields_set:
        group.tags = json.dumps(body.tags) if body.tags else None
        changes.append("tags")
    if changes:
        db.commit()
        log_action(db, admin, "update_group", target=group.name, detail=", ".join(changes))
    return _group_detail(group)


@router.delete("/{group_id}")
def delete_group(group_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Deletes a group, but only if it currently has no members -- unlike
    the previous behavior (auto-unassigning members then deleting), the
    caller must explicitly reassign/remove every member first. This avoids
    a group disappearing out from under people who are still on it."""
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    active_members = [u for u in group.members if not u.deleted]
    if active_members:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete a group with members assigned ({len(active_members)}) -- "
                   f"reassign or remove its members first.",
        )
    name = group.name
    db.delete(group)
    db.commit()
    log_action(db, admin, "delete_group", target=name)
    return {"message": f"Group '{name}' deleted."}


class MembershipRequest(BaseModel):
    user_id: int


@router.post("/{group_id}/members", status_code=201)
def add_group_member(group_id: int, body: MembershipRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Adds one user to one group, without disturbing any of their other
    group memberships -- the per-group complement to PATCH /api/users/{id}
    with group_ids (which replaces a user's whole membership list at once)."""
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    user = db.get(User, body.user_id)
    if user is None or user.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    if group not in user.groups:
        user.groups.append(group)
        db.commit()
        log_action(db, admin, "add_group_member", target=group.name, detail=user.username)
    return {"message": f"'{user.username}' added to '{group.name}'."}


@router.delete("/{group_id}/members/{user_id}")
def remove_group_member(group_id: int, user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if group in user.groups:
        user.groups.remove(group)
        db.commit()
        log_action(db, admin, "remove_group_member", target=group.name, detail=user.username)
    return {"message": f"'{user.username}' removed from '{group.name}'."}


# --- Group-Based Permissions Phase 1: role assignment -----------------------
# A group can be assigned zero or more roles; every current member inherits
# every assigned role's permissions on top of their own direct role_id (see
# permissions.py's effective_role_ids). Deliberately its own pair of
# endpoints, same "membership stays on its own dedicated endpoints" split
# UpdateGroupRequest's docstring already establishes for members -- role
# assignment is a distinct concern from group metadata and from membership.
# Gated on the same groups:manage permission (require_admin above) as every
# other Groups write.

@router.get("/available-roles")
def list_available_roles(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Every RoleDef, for the "Assign Roles" picker on the Groups page --
    deliberately its own minimal endpoint (id/slug/name only, no
    permission matrix) rather than reusing GET /api/roles, which is gated
    on roles:manage: an admin granted groups:manage but not roles:manage
    must still be able to assign an existing role to a group without also
    needing Roles Management access."""
    roles = db.query(RoleDef).order_by(RoleDef.name).all()
    return [_role_brief(r) for r in roles]


class GroupRoleRequest(BaseModel):
    role_id: int


@router.post("/{group_id}/roles", status_code=201)
def assign_group_role(group_id: int, body: GroupRoleRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    role = db.get(RoleDef, body.role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    if role not in group.role_defs:
        group.role_defs.append(role)
        db.commit()
        log_action(db, admin, "group_role_assigned", target=group.name, detail=role.slug)
    return {**_group_detail(group), "count": len([u for u in group.members if not u.deleted]), "members": [_member(u) for u in group.members if not u.deleted]}


@router.delete("/{group_id}/roles/{role_id}")
def remove_group_role(group_id: int, role_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    role = db.get(RoleDef, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    if role in group.role_defs:
        group.role_defs.remove(role)
        db.commit()
        log_action(db, admin, "group_role_removed", target=group.name, detail=role.slug)
    return {"message": f"Role '{role.slug}' removed from '{group.name}'."}
