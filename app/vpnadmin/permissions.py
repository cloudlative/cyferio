"""
Dynamic RBAC: the object-permission registry, system-role seeding, and the
FastAPI dependencies routes use to enforce it. Replaces auth.py's old
require_admin/require_client_manager (that migration happens in Phase 2 --
see the joyful-sauteeing-cookie plan and docs/rbac_identity_design.md).

Design recap (full detail in docs/rbac_identity_design.md §1-3):
  - A "role" is a RoleDef row plus a bag of ObjectPermission/RoleApiScope
    rows -- no enum, admin-creatable via Roles Management (Phase 5).
  - `OBJECTS` below is the registry of what can be permissioned -- adding a
    future module is one line here, not a migration.
  - Enforcement is fail-closed: no ObjectPermission row for a (role, object)
    pair means no access, including for objects added after a role was
    created.
"""
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .auth import require_user
from .db import get_db
from .models import ApiScope, ObjectPermission, RoleApiScope, RoleDef, RoleKind, User

# object_key -> display name, shown in the Roles Management permission-
# matrix UI (Phase 5) and used nowhere else structurally -- this dict is the
# single source of truth for "what modules exist" from an RBAC standpoint.
OBJECTS: dict[str, str] = {
    "dashboard": "Dashboard",
    "health": "Health Screen",
    "vpn_profiles": "VPN Profiles",
    "users": "User Management",
    "roles": "Role Management",
    "teams": "Teams",
    "audit_log": "Audit Logs",
    "settings": "Settings",
    "reports": "Reports",
    # Phase 1 Python service layer's web-triggered install/uninstall (see
    # routes/openvpn_install.py) -- deliberately its own object, not folded
    # into "vpn_profiles", since it's a host-namespace action (SSH-executed,
    # see host_executor.py) with much higher blast radius than a normal
    # client add/revoke and should be grantable independently.
    "openvpn_install": "OpenVPN Install/Uninstall",
}

ACTIONS = ("view", "create", "update", "delete", "execute", "manage")

# slug -> {object_key: {action: bool}}, only actions that differ from the
# all-False default need listing. This is the seed data for the 4 system
# roles -- see docs/rbac_identity_design.md §3. Every object not mentioned
# for a role defaults to no access at all (fail-closed).
_SYSTEM_ROLES: dict[str, dict] = {
    "admin": {
        "name": "Admin",
        "description": "Full control of every module.",
        "permissions": {obj: {"manage": True} for obj in OBJECTS},
        "scopes": {},  # "any" scope everywhere (the default) -- admin never restricted to "own"
    },
    "editor": {
        "name": "Editor",
        "description": "Can add/revoke/edit VPN clients and manage their MAC addresses. "
        "No user management, teams, or settings access -- matches the pre-RBAC "
        "'editor' role exactly.",
        "permissions": {
            "dashboard": {"view": True},
            "health": {"view": True},
            "vpn_profiles": {"view": True, "update": True, "execute": True},
        },
        "scopes": {},
    },
    "viewer": {
        "name": "Viewer",
        "description": "Read-only: status/list/check, no add/revoke/user-management. "
        "Matches the pre-RBAC 'viewer' role exactly.",
        "permissions": {
            obj: {"view": True} for obj in OBJECTS
            if obj not in ("settings", "roles", "openvpn_install")
        },
        "scopes": {},
    },
    "user": {
        "name": "User",
        "description": "Access to only their own VPN profile and account -- no visibility "
        "into other users, teams, audit logs, or settings.",
        "permissions": {
            "vpn_profiles": {"view": True, "update": True},
            "users": {"view": True, "update": True},  # scoped "own" below -- their own account/password only
        },
        "scopes": {
            "vpn_profiles": ApiScope.own,
            "users": ApiScope.own,
        },
    },
}


def rename_legacy_vpn_self_service_role(db: Session) -> None:
    """One-time, idempotent fixup for deployments seeded before this role was
    renamed from "VPN Self-Service User" (slug vpn_self_service) to "User"
    (slug user) -- same self-healing-migration style as db.py's
    _sync_missing_columns/_sync_enum_values, just for a data value instead
    of a schema/enum change. seed_system_roles() below only ever CREATES a
    missing RoleDef row, it never edits an existing one (by design -- an
    admin may have since changed a system role's name), so shipping the
    slug rename in _SYSTEM_ROLES alone would make seed_system_roles() seed
    a brand-new "user" row on next startup while the old vpn_self_service
    row (still referenced by every existing self-service User.role_id) sits
    around orphaned -- two roles doing the same job. This renames that row
    in place instead, preserving its id (so every existing role_id foreign
    key keeps resolving) -- must run BEFORE seed_system_roles() (see
    db.py's _seed_rbac) so it wins the race instead of a fresh seed. A
    no-op once already renamed, or on a deployment that never had the old
    slug (a genuinely fresh install seeds "user" directly) -- safe to leave
    in permanently."""
    if db.query(RoleDef).filter_by(slug="user").first() is not None:
        return  # already renamed (or a fresh install that seeded "user" directly)
    legacy = db.query(RoleDef).filter_by(slug="vpn_self_service").first()
    if legacy is None:
        return  # nothing to migrate
    legacy.slug = "user"
    legacy.name = "User"
    db.commit()


def seed_system_roles(db: Session) -> None:
    """Idempotent -- safe to call on every startup (same pattern as
    auth.bootstrap_admin/ensure_bootstrap_admin_flag). Creates the 4 system
    RoleDef rows + their permission/scope rows if missing; never touches an
    already-existing row's permissions (an admin may have deliberately
    edited a system role's grants since -- this only fills in what's
    missing at creation time, it doesn't re-assert defaults every boot)."""
    for slug, spec in _SYSTEM_ROLES.items():
        role = db.query(RoleDef).filter(RoleDef.slug == slug).first()
        if role is not None:
            continue
        role = RoleDef(
            slug=slug,
            name=spec["name"],
            description=spec["description"],
            kind=RoleKind.system,
            is_system=True,
        )
        db.add(role)
        db.flush()  # get role.id without a full commit yet
        for object_key, actions in spec["permissions"].items():
            db.add(ObjectPermission(role_id=role.id, object_key=object_key, **{
                f"can_{a}": actions.get(a, False) for a in ACTIONS
            }))
        for object_key, scope in spec["scopes"].items():
            db.add(RoleApiScope(role_id=role.id, object_key=object_key, scope=scope))
    db.commit()


def migrate_user_roles(db: Session) -> None:
    """Phase 2 backfill: for every User whose role_id is still unset, derive
    it from the legacy `role` enum column and the now-seeded system roles.
    Idempotent (only touches role_id IS NULL rows) -- safe on every startup,
    same as seed_system_roles above. Never touches `role` itself; that
    column, and the Role enum backing it, are removed in a later cleanup
    once every deployment has run this at least once and every route is
    confirmed migrated onto require_permission (see the joyful-sauteeing-
    cookie plan's Phase 2 note)."""
    role_ids_by_slug = {r.slug: r.id for r in db.query(RoleDef).all()}
    changed = False
    for user in db.query(User).filter(User.role_id.is_(None)).all():
        slug = user.role.value if user.role is not None else "viewer"
        role_id = role_ids_by_slug.get(slug)
        if role_id is not None:
            user.role_id = role_id
            changed = True
    if changed:
        db.commit()


def has_permission(db: Session, user: User, object_key: str, action: str) -> bool:
    """Non-raising counterpart to require_permission, for callers that need
    a plain bool rather than a 403 -- e.g. routes/pages.py's server-rendered
    nav/redirect guards, which can't use a Depends()-raised HTTPException
    the way API routes do."""
    return _has_permission(db, user.role_id, object_key, action)


def _scope_for(db: Session, role_id: int, object_key: str) -> ApiScope:
    row = db.query(RoleApiScope).filter_by(role_id=role_id, object_key=object_key).first()
    return row.scope if row is not None else ApiScope.any


def _has_permission(db: Session, role_id: int | None, object_key: str, action: str) -> bool:
    if role_id is None:
        return False
    perm = db.query(ObjectPermission).filter_by(role_id=role_id, object_key=object_key).first()
    if perm is None:
        return False
    if perm.can_manage:  # superset: full control, unlocks every action -- see ObjectPermission's docstring
        return True
    return getattr(perm, f"can_{action}", False)


def require_permission(object_key: str, action: str) -> Callable[..., User]:
    """For any route needing 'this role can {action} on {object_key}'.
    Fail-closed: no row, or role_id unset (still-mid-Phase-2 accounts), means
    403. `object_key` must be a key in OBJECTS; `action` one of ACTIONS.

    Does NOT check scope -- a role scoped "own" for this object (e.g.
    the "User" self-service role on "vpn_profiles") still passes here, since it does
    have the boolean permission, just restricted to its own record
    elsewhere (routes/me_vpn.py). Any endpoint that returns/acts on
    *every* record of a type (a bulk list, not a single "my own" lookup)
    must use require_permission_any_scope below instead, or an "own"-scoped
    role would see every other user's records too."""
    def _dep(user: User = Depends(require_user), db: Session = Depends(get_db)) -> User:
        if not _has_permission(db, user.role_id, object_key, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing '{action}' permission on '{object_key}'.",
            )
        return user
    return _dep


def has_permission_any_scope(db: Session, user: User, object_key: str, action: str) -> bool:
    """Non-raising counterpart to require_permission_any_scope, for
    routes/pages.py's redirect-style guards -- same reasoning as
    has_permission above."""
    if not _has_permission(db, user.role_id, object_key, action):
        return False
    if user.role_id is not None and _scope_for(db, user.role_id, object_key) == ApiScope.own:
        return False
    return True


def require_permission_any_scope(object_key: str, action: str) -> Callable[..., User]:
    """Like require_permission, but additionally rejects a role scoped
    "own" for this object -- for bulk/list endpoints and "System
    Administration" pages that expose every record (or every user's
    activity) rather than just the caller's own. This is what keeps the
    "User" self-service role off /api/clients, /api/status/*, /diagnostics,
    /health, etc: it has view=True on "vpn_profiles" (for its own linked
    profile via routes/me_vpn.py) but its scope for that object is "own",
    so it's blocked here even though require_permission alone would let it
    through."""
    def _dep(user: User = Depends(require_user), db: Session = Depends(get_db)) -> User:
        if not has_permission_any_scope(db, user, object_key, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing '{action}' permission on '{object_key}' (or this role is limited to its own records).",
            )
        return user
    return _dep


def require_own_or_permission(
    object_key: str, action: str, owner_username: Callable[[Request], str | None]
) -> Callable[..., User]:
    """Like require_permission, but if the caller's role is scoped "own" for
    this object, additionally requires owner_username(request) == the
    caller's own username. owner_username typically pulls a path param or
    resolves the record being acted on (e.g. the username on a
    VpnProfileLink) -- return None if the target record doesn't exist, which
    this treats as "not the caller's own" (403, not 404 -- existing routes
    still do their own 404 handling after this dependency passes)."""
    def _dep(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)) -> User:
        if not _has_permission(db, user.role_id, object_key, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing '{action}' permission on '{object_key}'.",
            )
        if user.role_id is not None and _scope_for(db, user.role_id, object_key) == ApiScope.own:
            target_username = owner_username(request)
            if target_username is None or target_username != user.username:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="This role can only access its own records.",
                )
        return user
    return _dep
