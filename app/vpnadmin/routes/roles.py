"""
Phase 5 of the dynamic-RBAC rollout: Roles Management CRUD + the
permission-matrix editor's API -- see docs/rbac_identity_design.md §6 and
the joyful-sauteeing-cookie plan.
"""
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..audit import log_action
from ..db import get_db
from ..models import ApiScope, ObjectPermission, RoleApiScope, RoleDef, RoleKind, User, group_role_defs, user_groups
from ..permissions import ACTIONS, OBJECTS, require_permission

router = APIRouter(prefix="/api/roles", tags=["roles"])

require_roles_admin = require_permission("roles", "manage")

SLUG_RE = re.compile(r"^[a-z0-9_]{2,64}$")


def _matrix_for(db: Session, role_id: int) -> dict:
    perms = {p.object_key: p for p in db.query(ObjectPermission).filter_by(role_id=role_id).all()}
    scopes = {s.object_key: s.scope for s in db.query(RoleApiScope).filter_by(role_id=role_id).all()}
    out = {}
    for object_key in OBJECTS:
        p = perms.get(object_key)
        out[object_key] = {
            **{a: (getattr(p, f"can_{a}") if p is not None else False) for a in ACTIONS},
            "scope": (scopes[object_key].value if object_key in scopes else ApiScope.any.value),
        }
    return out


def _serialize(db: Session, role: RoleDef, *, with_matrix: bool = False) -> dict:
    # Group-only permissions: "how many users actually have this role" is
    # no longer a User.role_id count (that column is legacy/inert for
    # permission purposes -- see permissions.py's effective_role_ids). The
    # real answer is "how many distinct, non-deleted users belong to a
    # group this role is assigned to" -- surfacing the old role_id count
    # here instead would show stale data as if it were current, real
    # usage (e.g. 0 for a role that's actually granted to 50 people
    # through a group, or a non-zero count for a role nobody currently
    # has effective access through any more).
    user_count = (
        db.query(User.id)
        .join(user_groups, user_groups.c.user_id == User.id)
        .join(group_role_defs, group_role_defs.c.group_id == user_groups.c.group_id)
        .filter(group_role_defs.c.role_id == role.id, User.deleted.is_(False))
        .distinct()
        .count()
    )
    out = {
        "id": role.id,
        "slug": role.slug,
        "name": role.name,
        "description": role.description,
        "kind": role.kind.value,
        "is_system": role.is_system,
        "user_count": user_count,
    }
    if with_matrix:
        out["objects"] = OBJECTS  # {object_key: display_name}, so the UI never hardcodes the module list
        out["matrix"] = _matrix_for(db, role.id)
    return out


# Fixed display order for the 5 system roles (task feedback: "Roles
# sorting - order: 1. Super Admin ... 2. admin 3. Editor 4. Viewer 5. User
# 6. Any other Custom role"). Every slug not listed here (i.e. every custom
# role) sorts after all of these, alphabetically by name -- see
# _role_sort_key below.
_SYSTEM_ROLE_ORDER = {"super_admin": 0, "admin": 1, "editor": 2, "viewer": 3, "user": 4}


def _role_sort_key(role: RoleDef):
    return (_SYSTEM_ROLE_ORDER.get(role.slug, len(_SYSTEM_ROLE_ORDER)), role.name)


@router.get("")
def list_roles(_: User = Depends(require_roles_admin), db: Session = Depends(get_db)):
    return [_serialize(db, r) for r in sorted(db.query(RoleDef).all(), key=_role_sort_key)]


class CreateRoleRequest(BaseModel):
    slug: str
    name: str
    description: str | None = None

    @field_validator("slug")
    @classmethod
    def _valid_slug(cls, v: str) -> str:
        v = v.strip().lower()
        if not SLUG_RE.match(v):
            raise ValueError("Slug must be 2-64 characters: lowercase letters, numbers, underscore only.")
        return v

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("Name must be 1-128 characters.")
        return v


@router.post("", status_code=201)
def create_role(body: CreateRoleRequest, admin: User = Depends(require_roles_admin), db: Session = Depends(get_db)):
    if db.query(RoleDef).filter(RoleDef.slug == body.slug).first() is not None:
        raise HTTPException(status_code=409, detail=f"A role with slug '{body.slug}' already exists.")
    role = RoleDef(
        slug=body.slug, name=body.name, description=body.description,
        kind=RoleKind.custom, is_system=False, created_by=admin.username,
    )
    db.add(role)
    db.commit()
    log_action(db, admin, "create_role", target=role.slug)
    return _serialize(db, role, with_matrix=True)


@router.get("/{role_id}")
def get_role(role_id: int, _: User = Depends(require_roles_admin), db: Session = Depends(get_db)):
    role = db.get(RoleDef, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    return _serialize(db, role, with_matrix=True)


class UpdateRoleRequest(BaseModel):
    """Slug is deliberately not editable here, for either system or custom
    roles -- it's the stable identity routes/users.py's _resolve_role and
    every audit-log entry reference by string, and nothing in this app
    needs to rename it after creation."""
    name: str | None = None
    description: str | None = None


def _block_super_admin_edit(role: RoleDef) -> None:
    """Super Admin (task feedback: "not modifiable") is the one system role
    that can't even be renamed/re-described/re-permissioned -- unlike
    admin/editor/viewer/user, which stay editable (just not deletable, see
    delete_role's own is_system check) same as before this role existed."""
    if role.slug == "super_admin":
        raise HTTPException(status_code=409, detail="'Super Admin' is a protected system role and cannot be modified.")


@router.patch("/{role_id}")
def update_role(role_id: int, body: UpdateRoleRequest, admin: User = Depends(require_roles_admin), db: Session = Depends(get_db)):
    role = db.get(RoleDef, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    _block_super_admin_edit(role)
    changes = []
    if body.name is not None and body.name.strip() and body.name != role.name:
        role.name = body.name.strip()
        changes.append("name")
    if body.description is not None and body.description != role.description:
        role.description = body.description
        changes.append("description")
    if changes:
        db.commit()
        log_action(db, admin, "update_role", target=role.slug, detail=", ".join(changes))
    return _serialize(db, role, with_matrix=True)


@router.delete("/{role_id}")
def delete_role(role_id: int, admin: User = Depends(require_roles_admin), db: Session = Depends(get_db)):
    role = db.get(RoleDef, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    if role.is_system:
        raise HTTPException(status_code=409, detail=f"'{role.name}' is a built-in system role and can't be deleted.")
    # Group-only permissions: the ONLY thing that actually grants this
    # role to anyone any more is a group assignment (see permissions.py's
    # effective_role_ids) -- User.role_id is legacy/inert, so a "still in
    # use" check against it would be checking data nobody's access is
    # actually determined by (and could false-negative on a role that
    # genuinely has zero effective holders, or false-positive-block on a
    # role only a stale role_id references). This is the real guard.
    group_assignments = db.query(group_role_defs.c.group_id).filter(group_role_defs.c.role_id == role.id).count()
    if group_assignments:
        raise HTTPException(
            status_code=409,
            detail=f"Can't delete '{role.name}' -- {group_assignments} group(s) still have this role assigned. "
                   f"Unassign it from those groups first.",
        )
    slug = role.slug
    db.delete(role)  # cascades to ObjectPermission/RoleApiScope rows -- see RoleDef's relationship cascade
    db.commit()
    log_action(db, admin, "delete_role", target=slug)
    return {"message": f"Role '{slug}' deleted."}


class ObjectPermissionEntry(BaseModel):
    view: bool = False
    create: bool = False
    update: bool = False
    delete: bool = False
    execute: bool = False
    manage: bool = False


class UpdateObjectPermissionsRequest(BaseModel):
    permissions: dict[str, ObjectPermissionEntry]

    @field_validator("permissions")
    @classmethod
    def _known_objects(cls, v: dict) -> dict:
        unknown = set(v) - set(OBJECTS)
        if unknown:
            raise ValueError(f"Unknown object(s): {sorted(unknown)}")
        return v


@router.put("/{role_id}/object-permissions")
def update_object_permissions(
    role_id: int, body: UpdateObjectPermissionsRequest,
    admin: User = Depends(require_roles_admin), db: Session = Depends(get_db),
):
    role = db.get(RoleDef, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    _block_super_admin_edit(role)
    existing = {p.object_key: p for p in db.query(ObjectPermission).filter_by(role_id=role.id).all()}
    for object_key, entry in body.permissions.items():
        row = existing.get(object_key)
        if row is None:
            row = ObjectPermission(role_id=role.id, object_key=object_key)
            db.add(row)
        for action in ACTIONS:
            setattr(row, f"can_{action}", getattr(entry, action))
    db.commit()
    log_action(db, admin, "update_role_permissions", target=role.slug,
               detail=f"{len(body.permissions)} object(s) updated")
    return _serialize(db, role, with_matrix=True)


class UpdateApiScopesRequest(BaseModel):
    scopes: dict[str, ApiScope]

    @field_validator("scopes")
    @classmethod
    def _known_objects(cls, v: dict) -> dict:
        unknown = set(v) - set(OBJECTS)
        if unknown:
            raise ValueError(f"Unknown object(s): {sorted(unknown)}")
        return v


@router.put("/{role_id}/api-scopes")
def update_api_scopes(
    role_id: int, body: UpdateApiScopesRequest,
    admin: User = Depends(require_roles_admin), db: Session = Depends(get_db),
):
    role = db.get(RoleDef, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found.")
    _block_super_admin_edit(role)
    existing = {s.object_key: s for s in db.query(RoleApiScope).filter_by(role_id=role.id).all()}
    for object_key, scope in body.scopes.items():
        row = existing.get(object_key)
        if row is None:
            db.add(RoleApiScope(role_id=role.id, object_key=object_key, scope=scope))
        else:
            row.scope = scope
    db.commit()
    log_action(db, admin, "update_role_api_scopes", target=role.slug,
               detail=f"{len(body.scopes)} object(s) updated")
    return _serialize(db, role, with_matrix=True)
