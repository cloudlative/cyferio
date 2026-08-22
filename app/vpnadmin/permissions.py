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
from .models import ApiScope, Group, ObjectPermission, RoleApiScope, RoleDef, RoleKind, User, group_role_defs, user_groups

# object_key -> display name, shown in the Roles Management permission-
# matrix UI (Phase 5) and used nowhere else structurally -- this dict is the
# single source of truth for "what modules exist" from an RBAC standpoint.
OBJECTS: dict[str, str] = {
    "dashboard": "Dashboard",
    "health": "Health Screen",
    "vpn_profiles": "VPN Profiles",
    "users": "User Management",
    "roles": "Role Management",
    "groups": "Groups",
    "audit_log": "Audit Logs",
    "settings": "Settings",
    "reports": "Reports",
    # Deliberately its OWN object, not folded into "reports" -- per-table
    # sizes (reveal schema/data-volume), live lock/long-running-query
    # counts, and connection details are more operationally sensitive than
    # anything else "reports" exposes today. Excluded from the "viewer"
    # role's blanket grant below (unlike "reports"/"health", which viewer
    # already has) -- admin/super_admin only, by default.
    "db_reporting": "Database Reporting",
    "support_tickets": "Support Tickets",
    # Server-level security/hardening posture (SSH config, firewall state,
    # OS/package/filesystem findings) -- excluded from viewer's blanket
    # grant below, same reasoning as db_reporting: a finding's evidence
    # (raw sshd_config lines, file permission bits, listening ports) is
    # more operationally sensitive than anything else "viewer" currently
    # sees, admin/super_admin only by default.
    "system_audit": "System Audit",
    # Split out of "users" (previously the three admin MFA actions --
    # reset/disable/force-enroll -- used require_permission("users",
    # "manage") like every other user-management route) so a role can be
    # granted "administer MFA for other accounts" without also getting
    # rename/delete/role-change/restriction-editing power over every user.
    # Same "generalize a broad object into a narrower one" move as
    # "db_reporting" was split out of "reports". Deliberately does NOT
    # cover `mfa_policy_override` (the per-user MFA policy exemption field
    # on the general PATCH /users/{id} endpoint) -- that field is set in
    # the same single-Depends() PATCH handler as role changes,
    # deactivation, and login restrictions, all gated by one users:manage
    # check for the whole endpoint; splitting one field out of that into a
    # second in-handler permission check wouldn't match this app's
    # per-ROUTE permission model anywhere else, for the sake of one field,
    # so it stays under users:manage. See routes/users.py's
    # reset_user_mfa/disable_user_mfa/force_enroll_user_mfa for what moved.
    "mfa_admin": "MFA Administration",
}

ACTIONS = ("view", "create", "update", "delete", "execute", "manage")

# slug -> {object_key: {action: bool}}, only actions that differ from the
# all-False default need listing. This is the seed data for the 4 system
# roles -- see docs/rbac_identity_design.md §3. Every object not mentioned
# for a role defaults to no access at all (fail-closed).
_SYSTEM_ROLES: dict[str, dict] = {
    # Highest-privilege role, reserved exclusively for the bootstrap admin
    # account -- see db.py's _promote_bootstrap_admin_to_super_admin, which
    # moves the very first admin account onto this role_id right after it's
    # seeded (a fresh deployment's bootstrap_admin() itself still creates
    # that account on the plain "admin" role, same as ever; this is a
    # one-time promotion step, not a change to account creation). Distinct
    # from "admin" mainly by policy, not by permission bits (both currently
    # get manage=True on every object) -- what actually makes it "super" is
    # everything OUTSIDE the permission matrix: it's excluded from the Add
    # User role dropdown (nobody can create a second one), and both
    # update_role/update_object_permissions/update_api_scopes in routes/
    # roles.py hard-block any edit to it (unlike every other system role,
    # which admins CAN rename/re-describe/re-permission, just not delete).
    "super_admin": {
        "name": "Super Admin",
        "description": "Reserved for the bootstrap admin account only -- full control of every "
        "module, permanently un-modifiable and never offered when creating a new user.",
        "permissions": {obj: {"manage": True} for obj in OBJECTS},
        "scopes": {},
    },
    "admin": {
        "name": "Admin",
        "description": "Full control of every module.",
        "permissions": {obj: {"manage": True} for obj in OBJECTS},
        "scopes": {},  # "any" scope everywhere (the default) -- admin never restricted to "own"
    },
    "editor": {
        "name": "Editor",
        "description": "Can add/revoke/edit VPN clients and manage their MAC addresses. "
        "No user management, groups, or settings access -- matches the pre-RBAC "
        "'editor' role exactly.",
        "permissions": {
            "dashboard": {"view": True},
            "health": {"view": True},
            "vpn_profiles": {"view": True, "update": True, "execute": True},
            # Any-scope (no scopes entry below) -- lets editor-role staff
            # act as support agents (view every ticket, reply, change
            # status/assignment via "update") without the full "manage"
            # an admin/super_admin gets, consistent with editor's existing
            # "operational staff, no settings/user-management" character.
            "support_tickets": {"view": True, "update": True},
        },
        "scopes": {},
    },
    "viewer": {
        "name": "Viewer",
        "description": "Read-only: status/list/check, no add/revoke/user-management. "
        "Matches the pre-RBAC 'viewer' role exactly.",
        "permissions": {
            obj: {"view": True} for obj in OBJECTS
            # "mfa_admin" excluded same as db_reporting/system_audit: it
            # only has meaningful "manage"-level actions (reset/disable/
            # force-enroll another account's MFA), nothing a bare "view"
            # grant would do anything with, and viewer never had
            # users:manage (the object mfa_admin was split out of) to
            # begin with -- so this mirrors, not widens, viewer's existing
            # access.
            if obj not in ("settings", "roles", "db_reporting", "system_audit", "mfa_admin")
        },
        "scopes": {},
    },
    "user": {
        "name": "User",
        "description": "Access to only their own VPN profile and account -- no visibility "
        "into other users, groups, audit logs, or settings.",
        "permissions": {
            "vpn_profiles": {"view": True, "update": True},
            "users": {"view": True, "update": True},  # scoped "own" below -- their own account/password only
            # "view"+"create"+"update" is enough for the entire self-service
            # ticket lifecycle: create a ticket, view own tickets, reply to
            # (and reopen) an own ticket -- see routes/me_tickets.py. Scoped
            # "own" below, same as vpn_profiles/users.
            "support_tickets": {"view": True, "create": True, "update": True},
        },
        "scopes": {
            "vpn_profiles": ApiScope.own,
            "users": ApiScope.own,
            "support_tickets": ApiScope.own,
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
    RoleDef rows if missing, then backfills any (role, object) permission/
    scope row a system role's spec grants but doesn't yet have -- never
    touches a row that already exists (an admin may have deliberately
    edited a system role's grants since; a backfill only fills genuine
    gaps, it doesn't re-assert defaults every boot).

    The backfill (not just "create if the whole role is missing") matters
    because OBJECTS grows over time -- e.g. "db_reporting" was added in
    Phase 3, well after most deployments' admin/super_admin RoleDef rows
    were already seeded. The OLD version of this function (`if role is
    not None: continue`) skipped an existing role entirely, so those
    already-seeded roles never picked up the new object's permission row
    at all -- confirmed live: admin/super_admin accounts on an
    already-running deployment had zero ObjectPermission row for
    "db_reporting", so Database Reporting silently never appeared for
    anyone, despite the feature being fully shipped and deployed. Per
    OBJECTS' own module docstring, fail-closed-with-no-row is the CORRECT
    behavior for a custom, admin-edited role (an admin's own role
    shouldn't retroactively gain access to a module they never granted),
    but a stock SYSTEM role should still pick up new registry entries on
    next startup -- same self-healing-migration spirit as db.py's
    _sync_missing_columns for schema columns, just for permission rows."""
    for slug, spec in _SYSTEM_ROLES.items():
        role = db.query(RoleDef).filter(RoleDef.slug == slug).first()
        if role is None:
            role = RoleDef(
                slug=slug,
                name=spec["name"],
                description=spec["description"],
                kind=RoleKind.system,
                is_system=True,
            )
            db.add(role)
            db.flush()  # get role.id without a full commit yet

        existing_perm_objects = {p.object_key for p in db.query(ObjectPermission).filter_by(role_id=role.id).all()}
        for object_key, actions in spec["permissions"].items():
            if object_key in existing_perm_objects:
                continue
            db.add(ObjectPermission(role_id=role.id, object_key=object_key, **{
                f"can_{a}": actions.get(a, False) for a in ACTIONS
            }))

        existing_scope_objects = {s.object_key for s in db.query(RoleApiScope).filter_by(role_id=role.id).all()}
        for object_key, scope in spec["scopes"].items():
            if object_key in existing_scope_objects:
                continue
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


def effective_role_ids(db: Session, user: User) -> set[int]:
    """Group-Only Permissions: the full set of role_ids a user's access is
    evaluated against -- EXCLUSIVELY the union of every role_id assigned
    (via group_role_defs) to every group this user belongs to (via
    user_groups). `User.role_id` itself is NOT consulted here -- it is
    legacy/inert for permission purposes (kept on the model only so
    migrate_users_to_role_groups below has something to read the user's
    pre-migration role from; see that function's docstring). Permissions
    come exclusively from group membership now: a user in zero groups, or
    in group(s) with zero assigned roles, gets back the empty set and fails
    every permission check -- there is no fallback to a personal role and
    no implicit "Default" group.

    This replaces the earlier "Team-Based Permissions Phase 1" behavior,
    where a user's own direct role_id was UNIONed on top of whatever their
    teams granted. That union-with-a-personal-role model is gone: groups
    are now the ONLY source of permissions. Backward compatibility for
    existing deployments is instead provided at migration time --
    migrate_users_to_role_groups() (run once at startup, see its docstring)
    auto-creates a group per distinct previously-held role and places every
    holder of that role into it, so effective_role_ids() returns the exact
    same set of role_ids for every user immediately after that migration
    runs as effective_role_ids() would have returned under the OLD
    (role_id UNION teams) logic beforehand. See test_group_roles.py's
    TestGroupOnlyMigrationPreservesAccess for the explicit regression test
    proving this.

    HARDCODED EXEMPTION -- super_admin: reserved exclusively for the
    bootstrap admin account (see db.py's promote_bootstrap_admin_to_
    super_admin and _SYSTEM_ROLES["super_admin"] below), super_admin must
    keep full, unconditional access to everything and must NEVER depend on
    group membership -- not required to be in any group, not subject to
    the "zero groups = zero permissions" rule everyone else gets. Checked
    directly here, structurally, BEFORE any group resolution runs, via
    whether this user's own `role_id` resolves to the "super_admin"
    RoleDef -- the same signal that already made super_admin's
    ObjectPermission rows (manage=True on every object) apply to them
    under the OLD Phase 1 logic, back when `user.role_id` was still part
    of the union. Verified (not assumed) before writing this rewrite:
    pre-rewrite, effective_role_ids() routed super_admin through the
    exact same ObjectPermission-lookup path as every other role via their
    own role_id, with no separate bypass anywhere in has_permission/
    require_permission -- so removing role_id from the general union
    would otherwise have been the FIRST time super_admin's access could
    ever be affected by group membership at all. This short-circuit is
    what keeps that from happening. Deliberately NOT a group ("SuperAdmin"
    or similar) -- an explicit design decision to keep this exemption pure
    hardcoded logic, no group machinery involved."""
    if user.role_def is not None and user.role_def.slug == "super_admin":
        return {user.role_id}
    group_ids = [g.id for g in user.groups]
    if not group_ids:
        return set()
    rows = db.query(group_role_defs.c.role_id).filter(group_role_defs.c.group_id.in_(group_ids)).distinct().all()
    return {row[0] for row in rows}


def migrate_users_to_role_groups(db: Session) -> None:
    """One-time (idempotent, safe on every startup) data migration for the
    group-only permission model: since effective_role_ids() above no longer
    ever consults User.role_id, this backfills a Group for every distinct
    role_id currently held directly by at least one User, assigns that role
    to the group, and adds every current holder of that role_id as a
    member -- so nobody's effective permissions change the moment the
    group-only model ships. Mirrors migrate_user_roles()'s idempotency/
    startup-registration style above; must run AFTER seed_system_roles()
    (roles must exist to look up their names/ids) and AFTER migrate_user_roles()
    (so User.role_id is backfilled from the legacy `role` enum first, giving
    this function the most complete picture of "current role" to migrate
    from) -- see main.py's lifespan for the registration order.

    Algorithm, per distinct role_id found on >=1 User row:
      1. Find-or-create a Group whose assigned role (via group_role_defs)
         is exactly that role_id. Naming: the RoleDef's own `name` (e.g.
         RoleDef "Admin" -> Group "Admin"). Collision handling: if a Group
         with that exact name already exists but does NOT have this role_id
         assigned (e.g. an admin manually created a "Admin" group for an
         unrelated purpose before this migration ever ran), this appends
         " (auto)" to the name instead of reusing/renaming the existing
         group -- never silently repurposes a group an admin created,
         and never silently grants an existing group a role its owner
         didn't ask for. If a Group with the exact target name AND that
         exact role_id assigned already exists (e.g. this migration's own
         prior run, or an admin who set things up by hand identically),
         it's reused as-is -- this is what makes re-running idempotent.
      2. For every User currently holding that role_id, add them as a
         member of the group UNLESS they're already a member of ANY group
         that has this exact role_id assigned (covers both "this migration
         already ran for them" and "an admin already manually organized
         this user into a group with the equivalent role" -- avoids
         duplicate/pointless memberships either way).

    Never touches User.role_id itself (left in place as inert legacy data,
    per the group-only model's design -- see effective_role_ids' docstring).
    Never removes a group or membership -- purely additive, matching every
    other startup migration in this file.

    Deliberately EXCLUDES "super_admin" from the roles it migrates: that
    role is exempted from the group-only model entirely (see
    effective_role_ids' hardcoded exemption above) -- the bootstrap admin
    account's access already doesn't depend on group membership, so
    creating and populating an auto-migration group for it would just be
    pointless clutter on the Groups page, not a real backward-compatibility
    need."""
    role_by_id = {r.id: r for r in db.query(RoleDef).all()}

    # Every distinct role_id currently held directly by >=1 non-deleted
    # user, EXCLUDING super_admin (see docstring above -- that one's
    # exempted from groups entirely, not migrated into one). Deleted users
    # are also excluded -- no point creating/populating a migration group
    # for a role only a soft-deleted account still points at.
    distinct_role_ids = {
        row[0] for row in db.query(User.role_id).join(RoleDef, User.role_id == RoleDef.id).filter(
            User.role_id.isnot(None), User.deleted.is_(False), RoleDef.slug != "super_admin"
        ).distinct().all()
    }

    changed = False
    for role_id in distinct_role_ids:
        role = role_by_id.get(role_id)
        if role is None:
            continue  # orphaned role_id (role since deleted) -- nothing sensible to migrate onto

        # Users currently already covered (member of ANY group -- whether
        # auto-created by a prior run of this migration, or manually
        # assembled by an admin -- that has this exact role_id assigned)
        # -- skip them; only genuinely uncovered holders need a new
        # membership. Computed BEFORE find-or-create below so a role every
        # one of whose holders is already covered doesn't spawn a
        # pointless, empty auto-group -- see test_permissions.py's
        # TestMigrateUsersToRoleGroups.test_skips_a_user_already_in_a_
        # group_with_the_equivalent_role.
        already_covered_user_ids = {
            row[0] for row in db.query(user_groups.c.user_id)
            .join(group_role_defs, group_role_defs.c.group_id == user_groups.c.group_id)
            .filter(group_role_defs.c.role_id == role_id)
            .distinct().all()
        }
        holders = db.query(User).filter(User.role_id == role_id, User.deleted.is_(False)).all()
        uncovered = [u for u in holders if u.id not in already_covered_user_ids]
        if not uncovered:
            continue

        # Find-or-create the target group for this role_id -- only reached
        # when there's actually at least one holder needing a membership.
        group = (
            db.query(Group)
            .join(group_role_defs, group_role_defs.c.group_id == Group.id)
            .filter(Group.name == role.name, group_role_defs.c.role_id == role_id)
            .first()
        )
        if group is None:
            name = role.name
            if db.query(Group).filter(Group.name == name).first() is not None:
                # Name taken by an unrelated, manually-created group -- don't
                # repurpose it. See docstring's collision strategy.
                name = f"{role.name} (auto)"
                n = 2
                while db.query(Group).filter(Group.name == name).first() is not None:
                    name = f"{role.name} (auto {n})"
                    n += 1
            group = Group(name=name, slug=None, description=(
                f"Auto-created during the group-only permissions migration to preserve "
                f"every existing '{role.name}' user's access -- reorganize freely."
            ))
            db.add(group)
            db.flush()  # get group.id
            db.execute(group_role_defs.insert().values(group_id=group.id, role_id=role_id))
            changed = True

        for user in uncovered:
            db.execute(user_groups.insert().values(user_id=user.id, group_id=group.id))
            changed = True

    if changed:
        db.commit()


def has_permission(db: Session, user: User, object_key: str, action: str) -> bool:
    """Non-raising counterpart to require_permission, for callers that need
    a plain bool rather than a 403 -- e.g. routes/pages.py's server-rendered
    nav/redirect guards, which can't use a Depends()-raised HTTPException
    the way API routes do."""
    return _has_permission(db, effective_role_ids(db, user), object_key, action)


def _granting_role_ids(db: Session, role_ids: set[int], object_key: str, action: str) -> set[int]:
    """Which of `role_ids` individually grant {action} on {object_key} --
    the set-aware core of the old single-role _has_permission check, kept
    as its own helper because scope resolution (_effective_scope below)
    needs to know WHICH roles actually granted access, not just whether at
    least one did. Fail-closed per role (a role with no ObjectPermission
    row for this object grants nothing), fail-open across the set (only
    one granting role is needed) -- same posture require_permission has
    always had for a single role, just extended from 1 role to N."""
    if not role_ids:
        return set()
    perms = db.query(ObjectPermission).filter(
        ObjectPermission.role_id.in_(role_ids), ObjectPermission.object_key == object_key
    ).all()
    # can_manage is a superset: full control, unlocks every action -- see
    # ObjectPermission's docstring -- same rule the old single-role check applied.
    return {p.role_id for p in perms if p.can_manage or getattr(p, f"can_{action}", False)}


def _has_permission(db: Session, role_ids: set[int], object_key: str, action: str) -> bool:
    return bool(_granting_role_ids(db, role_ids, object_key, action))


def _effective_scope(db: Session, granting_role_ids: set[int], object_key: str) -> ApiScope:
    """Least-restrictive scope across `granting_role_ids` (roles already
    confirmed to grant the permission being checked, see
    _granting_role_ids) -- if ANY of them has "any" scope for this object
    (including the default: no RoleApiScope row at all), the union is
    "any"; only when EVERY granting role is explicitly scoped "own" does
    the union stay "own". Same fail-open-across-the-set posture as
    _has_permission above: a single role with unrestricted access already
    grants unrestricted access, regardless of how many other roles in the
    set are more restricted. Only ever called with a non-empty set (every
    caller checks _has_permission/_granting_role_ids first)."""
    scoped = {s.role_id: s.scope for s in db.query(RoleApiScope).filter(
        RoleApiScope.role_id.in_(granting_role_ids), RoleApiScope.object_key == object_key
    ).all()}
    for role_id in granting_role_ids:
        if scoped.get(role_id, ApiScope.any) == ApiScope.any:
            return ApiScope.any
    return ApiScope.own


def require_permission(object_key: str, action: str) -> Callable[..., User]:
    """For any route needing 'this role can {action} on {object_key}'.
    Fail-closed: no row, or the user is in zero groups (or in group(s) with
    no role granting this), means 403. `object_key` must be a key in
    OBJECTS; `action` one of ACTIONS.

    Checks the caller's full effective_role_ids (every role granted via
    group membership -- see effective_role_ids; permissions come EXCLUSIVELY
    from groups now, not from any personal role) -- ANY one of them granting
    the permission is enough, same union semantics a single role's own
    permissions have always had. A user in no group grants nothing here.

    Does NOT check scope -- a role scoped "own" for this object (e.g.
    the "User" self-service role on "vpn_profiles") still passes here, since it does
    have the boolean permission, just restricted to its own record
    elsewhere (routes/me_vpn.py). Any endpoint that returns/acts on
    *every* record of a type (a bulk list, not a single "my own" lookup)
    must use require_permission_any_scope below instead, or an "own"-scoped
    role would see every other user's records too."""
    def _dep(user: User = Depends(require_user), db: Session = Depends(get_db)) -> User:
        if not _has_permission(db, effective_role_ids(db, user), object_key, action):
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
    granting = _granting_role_ids(db, effective_role_ids(db, user), object_key, action)
    if not granting:
        return False
    return _effective_scope(db, granting, object_key) != ApiScope.own


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
    """Like require_permission, but if every one of the caller's granting
    roles is scoped "own" for this object, additionally requires
    owner_username(request) == the caller's own username. owner_username
    typically pulls a path param or resolves the record being acted on
    (e.g. the username on a VpnProfileLink) -- return None if the target
    record doesn't exist, which this treats as "not the caller's own" (403,
    not 404 -- existing routes still do their own 404 handling after this
    dependency passes)."""
    def _dep(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)) -> User:
        granting = _granting_role_ids(db, effective_role_ids(db, user), object_key, action)
        if not granting:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing '{action}' permission on '{object_key}'.",
            )
        if _effective_scope(db, granting, object_key) == ApiScope.own:
            target_username = owner_username(request)
            if target_username is None or target_username != user.username:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="This role can only access its own records.",
                )
        return user
    return _dep
