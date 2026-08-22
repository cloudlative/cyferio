import json
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session, selectinload

from .. import app_settings
from ..app_settings import get_settings_row, refresh_runtime_cache
from ..audit import log_action
from ..auth import require_user
from ..db import get_db
from ..models import SUPER_ADMIN_GROUP_NAME, RoleDef, Group, User
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


def _is_super_admin_group(group: Group) -> bool:
    return group.name == SUPER_ADMIN_GROUP_NAME


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
        if v == SUPER_ADMIN_GROUP_NAME:
            raise ValueError(f"'{SUPER_ADMIN_GROUP_NAME}' is reserved for the built-in, system-managed group and can't be used as a group name.")
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
    already established for this resource. Rejected outright (see
    update_group below) for the immutable "SuperAdmin" group, regardless of
    which fields are supplied."""
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
        # Single-group/single-role permissions: a group has AT MOST one
        # role -- null means this group currently grants its members
        # nothing (see permissions.py's effective_role_ids).
        "role": _role_brief(t.role) if t.role is not None else None,
        # Settings -> User Management's "Default Group for New Users" --
        # surfaced here (rather than a separate /api/settings round-trip)
        # since users.html already fetches /api/groups to populate the Add
        # User form's own Group picker. See AppSettings.default_group_id's
        # own docstring for the full design.
        "is_default": t.id == app_settings.runtime.default_group_id,
        # Drives the client-side immutability guards mirrored in
        # groups.html (Edit/Delete/role-change/member-management all
        # disabled or hidden for this one group) -- the actual enforcement
        # is server-side, in update_group/delete_group/set_group_role/
        # add_group_member/remove_group_member below; this flag is
        # defense-in-depth/UX only.
        "is_super_admin_group": _is_super_admin_group(t),
    }


def _member(u: User) -> dict:
    # Deliberately NOT u.role/u.role_id -- under the single-group/single-
    # role permission model neither one determines this user's actual
    # access any more (see permissions.py's effective_role_ids), so
    # showing either here would be stale/misleading. "effective_roles"
    # instead: the role this user's ONE group grants (empty if none), i.e.
    # the same role set effective_role_ids() would compute -- including
    # the super_admin hardcoded exemption (see User.effective_role_names'
    # own docstring): that account shows its real role here even though
    # its own group's role assignment is purely cosmetic. Relies on the
    # caller having selectinload'd both User.group and Group.role (see
    # list_groups below) so this stays O(1) queries, not N+1.
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "effective_roles": u.effective_role_names,
        "is_active": u.is_active,
    }


@router.get("")
def list_groups(_: User = Depends(require_user), db: Session = Depends(get_db)):
    """Active, non-deleted portal users grouped by their ONE group -- see
    models.py's Group/User docstrings for the single-group/single-role
    model. Built from the Group table so a group with zero members still
    shows up (with count 0), not just groups that happen to already have
    someone assigned. Deliberately open to any logged-in user (viewer or
    admin), unlike /api/users, since only non-sensitive fields are exposed
    here (no password/email/etc.)."""
    # selectinload(Group.role): same N+1 reasoning as selectinload(User.
    # group) below, just for the role-assigned-to-group field _group_detail
    # now includes -- one extra query total for every group's role, instead
    # of one lazy SELECT per group the first time `.role` is touched.
    group_rows = db.query(Group).options(selectinload(Group.role)).order_by(Group.name).all()
    # selectinload(User.group): without it, every `u.group_id == t.id` check
    # below is still cheap (a plain column compare), but _member() reads
    # each member's effective_roles via u.group.role -- without eager-
    # loading both hops, that's a lazy SELECT per user (N+1). This batches
    # it into a single extra query total, up front. selectinload(User.
    # role_def): _member() -> User.effective_role_names' super_admin
    # exemption check needs it.
    users = (
        db.query(User)
        .options(selectinload(User.group).selectinload(Group.role), selectinload(User.role_def))
        .filter(User.deleted.is_(False))
        .order_by(User.username)
        .all()
    )

    groups: list[dict] = []
    for t in group_rows:
        members = [_member(u) for u in users if u.group_id == t.id]
        groups.append({**_group_detail(t), "count": len(members), "members": members})

    unassigned_members = [_member(u) for u in users if u.group_id is None]
    groups.append({
        "id": None, "group": UNASSIGNED, "slug": None, "description": None, "tags": [], "role": None,
        "is_super_admin_group": False, "count": len(unassigned_members), "members": unassigned_members,
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
    if _is_super_admin_group(group):
        raise HTTPException(
            status_code=400,
            detail=f"'{SUPER_ADMIN_GROUP_NAME}' is a built-in, system-managed group -- its name, slug, "
                   f"description, and tags can't be changed.",
        )
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
    a group disappearing out from under people who are still on it. The
    immutable "SuperAdmin" group is rejected explicitly, with its own clear
    message, even though it would also always fail the "has members" guard
    below in practice (it permanently holds exactly the bootstrap admin) --
    an explicit check makes the REASON unambiguous rather than looking like
    an ordinary "reassign members first" case."""
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    if _is_super_admin_group(group):
        raise HTTPException(
            status_code=400,
            detail=f"'{SUPER_ADMIN_GROUP_NAME}' is a built-in, system-managed group and can't be deleted.",
        )
    active_members = [u for u in group.members if not u.deleted]
    if active_members:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete a group with members assigned ({len(active_members)}) -- "
                   f"reassign or remove its members first.",
        )
    name = group.name
    # Settings -> User Management's "Default Group for New Users" (see
    # AppSettings.default_group_id's own docstring) has no FK constraint on
    # purpose, but leaving it pointing at an id that no longer exists would
    # mean it just silently stops matching anything in the Add User picker
    # forever -- clearing it here instead keeps the setting meaningful
    # ("no default" is explicit, not an accidental side effect of some
    # unrelated group having been deleted a year ago).
    settings_row = get_settings_row(db)
    if settings_row.default_group_id == group.id:
        settings_row.default_group_id = None
        refresh_runtime_cache(db)
    db.delete(group)
    db.commit()
    log_action(db, admin, "delete_group", target=name)
    return {"message": f"Group '{name}' deleted."}


class MembershipRequest(BaseModel):
    user_id: int


@router.post("/{group_id}/members", status_code=201)
def add_group_member(group_id: int, body: MembershipRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Moves one user into this group -- since a user can only ever belong
    to ONE group at a time now, this REPLACES whatever group (if any) they
    were previously in, it doesn't add a second membership. The immutable
    "SuperAdmin" group rejects being the target of a move entirely (its
    one member, the bootstrap admin, is fixed) -- see also update_user's
    own is_bootstrap_admin guard in routes/users.py, which is the other
    place group membership could otherwise be changed."""
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    if _is_super_admin_group(group):
        raise HTTPException(
            status_code=400,
            detail=f"'{SUPER_ADMIN_GROUP_NAME}' is a built-in, system-managed group -- its membership is "
                   f"fixed to the bootstrap admin account and can't be changed.",
        )
    user = db.get(User, body.user_id)
    if user is None or user.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.is_bootstrap_admin:
        raise HTTPException(status_code=400, detail="The bootstrap admin account's group can't be changed.")
    previous_group = user.group
    if user.group_id != group.id:
        user.group_id = group.id
        db.commit()
        detail = user.username if previous_group is None else f"{user.username} (moved from '{previous_group.name}')"
        log_action(db, admin, "add_group_member", target=group.name, detail=detail)
    verb = "moved to" if previous_group is not None else "added to"
    return {"message": f"'{user.username}' {verb} '{group.name}'."}


@router.delete("/{group_id}/members/{user_id}")
def remove_group_member(group_id: int, user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if _is_super_admin_group(group):
        raise HTTPException(
            status_code=400,
            detail=f"'{SUPER_ADMIN_GROUP_NAME}' is a built-in, system-managed group -- its membership is "
                   f"fixed to the bootstrap admin account and can't be changed.",
        )
    if user.group_id == group.id:
        user.group_id = None
        db.commit()
        log_action(db, admin, "remove_group_member", target=group.name, detail=user.username)
    return {"message": f"'{user.username}' removed from '{group.name}'."}


# --- Single-group/single-role permissions: role assignment ------------------
# A group is assigned AT MOST one role; every current member inherits it.
# Deliberately its own endpoint, same "membership stays on its own
# dedicated endpoints" split UpdateGroupRequest's docstring already
# establishes for members -- role assignment is a distinct concern from
# group metadata and from membership. Gated on the same groups:manage
# permission (require_admin above) as every other Groups write.

@router.get("/available-roles")
def list_available_roles(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Every RoleDef, for the Groups page's "Role" picker -- deliberately
    its own minimal endpoint (id/slug/name only, no permission matrix)
    rather than reusing GET /api/roles, which is gated on roles:manage: an
    admin granted groups:manage but not roles:manage must still be able to
    assign an existing role to a group without also needing Roles
    Management access."""
    # Excludes "super_admin" -- reserved exclusively for the bootstrap
    # admin account (see permissions.py's effective_role_ids hardcoded
    # exemption and db.py's promote_bootstrap_admin_to_super_admin). That
    # account's actual access never depends on group membership, so
    # assigning this role to an ordinary group would be misleading at
    # best -- it's already permanently assigned (cosmetically) to the
    # SuperAdmin group instead, which isn't offered here as a group to
    # edit in the first place. Server-side backstop for this same rule
    # lives in set_group_role below.
    roles = db.query(RoleDef).filter(RoleDef.slug != "super_admin").order_by(RoleDef.name).all()
    return [_role_brief(r) for r in roles]


class GroupRoleRequest(BaseModel):
    role_id: int | None = None  # None = clear this group's role (grants nothing)


@router.put("/{group_id}/role")
def set_group_role(group_id: int, body: GroupRoleRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Sets (or clears) this group's ONE role -- REPLACES whatever role it
    had before, unlike the earlier Group-Only Permissions model's additive
    "assign a role" endpoint. Rejected outright for the immutable
    "SuperAdmin" group, which is permanently pinned to the super_admin
    role."""
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    if _is_super_admin_group(group):
        raise HTTPException(
            status_code=400,
            detail=f"'{SUPER_ADMIN_GROUP_NAME}' is a built-in, system-managed group -- its role is fixed "
                   f"to Super Admin and can't be changed.",
        )
    if body.role_id is None:
        if group.role_id is not None:
            old_slug = group.role.slug if group.role is not None else str(group.role_id)
            group.role_id = None
            db.commit()
            log_action(db, admin, "group_role_removed", target=group.name, detail=old_slug)
        return _group_detail(group)
    role = db.get(RoleDef, body.role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    if role.slug == "super_admin":
        raise HTTPException(status_code=400, detail="The Super Admin role can't be assigned to a group -- it's reserved for the bootstrap admin account and is never sourced from group membership.")
    if group.role_id != role.id:
        group.role_id = role.id
        db.commit()
        log_action(db, admin, "group_role_assigned", target=group.name, detail=role.slug)
    return _group_detail(group)
