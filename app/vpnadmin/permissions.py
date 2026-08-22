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
import logging
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from .auth import require_user
from .db import get_db
from .models import (
    ApiScope,
    Group,
    ObjectPermission,
    RoleApiScope,
    RoleDef,
    RoleKind,
    SUPER_ADMIN_GROUP_NAME,
    User,
)

logger = logging.getLogger(__name__)

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
    """Single-Group, Single-Role Permissions: the full set of role_ids a
    user's access is evaluated against. As of this model there is AT MOST
    one: the role assigned to the ONE group this user belongs to
    (`user.group.role_id`). `User.role_id` itself is NOT consulted here --
    it is legacy/inert for permission purposes (kept on the model only for
    the same historical reasons documented on User.role_id's own column
    comment). A user with no group, or whose group has no role assigned,
    gets back the empty set and fails every permission check -- there is
    no fallback to a personal role.

    Still returns a `set[int]` (not a bare int/None) even though it now
    holds at most one element -- this deliberately minimizes blast radius:
    every downstream caller (has_permission, _granting_role_ids,
    _effective_scope, require_permission, ...) already consumes a set, and
    their "least-restrictive-wins across the set" logic degrades correctly
    and harmlessly to a 0-or-1-element set without needing to be rewritten.

    This replaces the earlier "Group-Only Permissions" model, where a
    user could belong to several groups and a group could be assigned
    several roles, with effective_role_ids() returning the UNION of every
    role_id reachable through every group membership. That union is gone:
    a user has one group, a group has one role, full stop. Backward
    compatibility for existing deployments is provided at migration time
    -- migrate_groups_and_users_to_single_assignment() (run once at
    startup, see its own docstring) collapses any pre-existing multi-
    group/multi-role data down to single assignments before this function
    is ever consulted for real traffic.

    HARDCODED EXEMPTION -- super_admin: reserved exclusively for the
    bootstrap admin account (see db.py's promote_bootstrap_admin_to_
    super_admin and _SYSTEM_ROLES["super_admin"] below), super_admin must
    keep full, unconditional access to everything and must NEVER depend on
    group membership. Checked directly here, structurally, BEFORE any
    group resolution runs, via whether this user's own `role_id` resolves
    to the "super_admin" RoleDef. UNCHANGED from the prior Group-Only
    model's version of this same check -- this rewrite touches only the
    non-super_admin path below it. The bootstrap admin account is ALSO a
    member of the immutable "SuperAdmin" group (see ensure_super_admin_
    group below) so it satisfies the "every user has exactly one group"
    UI/structural invariant like everyone else, but that group membership
    is purely cosmetic -- it is never consulted here, on purpose, so this
    hardcoded exemption remains the one and only source of super_admin's
    actual permissions (belt-and-suspenders, per explicit design
    decision: both mechanisms exist, only one of them is load-bearing)."""
    if user.role_def is not None and user.role_def.slug == "super_admin":
        return {user.role_id}
    if user.group_id is None or user.group is None or user.group.role_id is None:
        return set()
    return {user.group.role_id}


def ensure_super_admin_group(db: Session) -> None:
    """Idempotent creation/maintenance of the immutable "SuperAdmin" group
    (see models.SUPER_ADMIN_GROUP_NAME) -- exists purely so the bootstrap
    admin account satisfies the new "every user belongs to exactly one
    group" structural/UI invariant cleanly, without a special-cased "no
    group" carve-out in the Add/Edit User dialogs. Its role assignment is
    COSMETIC: super_admin's actual permissions come exclusively from the
    hardcoded exemption in effective_role_ids() above, never from this (or
    any) group -- see that function's own docstring for why both
    mechanisms deliberately coexist.

    Mirrors db.py's promote_bootstrap_admin_to_super_admin exactly:
    registered from BOTH db.py's _seed_rbac (covers every startup on an
    already-provisioned database) and main.py's lifespan (covers a
    genuinely fresh install, where the bootstrap account doesn't exist yet
    the first time _seed_rbac runs) -- same "fresh-install first call is
    necessarily a partial no-op" reasoning. Must run AFTER seed_system_
    roles() (the super_admin RoleDef must already exist) and AFTER
    promote_bootstrap_admin_to_super_admin() is registered to have already
    run for this startup (it doesn't strictly need the bootstrap account
    to already BE on the super_admin role_id -- only is_bootstrap_admin is
    checked below -- but see db.py/main.py's own comments for the actual
    call order, kept identical to that existing pair for consistency).
    Must run BEFORE migrate_groups_and_users_to_single_assignment() (see
    that function's own docstring): the bootstrap admin is excluded from
    that migration's "zero-group fallback" rule entirely, so its group
    membership must already be settled by the time that migration runs."""
    super_admin_role = db.query(RoleDef).filter_by(slug="super_admin").first()
    if super_admin_role is None:
        return  # seed_system_roles somehow didn't run -- nothing to anchor the group to yet
    group = db.query(Group).filter_by(name=SUPER_ADMIN_GROUP_NAME).first()
    if group is None:
        group = Group(
            name=SUPER_ADMIN_GROUP_NAME, slug="super-admin", role_id=super_admin_role.id,
            description=(
                "Immutable, system-managed -- exists only so the bootstrap admin account "
                "satisfies the 'every user belongs to exactly one group' rule. Its real "
                "permissions come from a hardcoded exemption, not from this group's role."
            ),
        )
        db.add(group)
        db.flush()  # get group.id
    elif group.role_id != super_admin_role.id:
        # Defensive: routes/groups.py's update_group/set_group_role both
        # reject changing this away from super_admin, so this should be
        # unreachable in practice -- kept as a self-healing backstop, same
        # spirit as seed_system_roles' own backfill-not-skip approach.
        group.role_id = super_admin_role.id
    bootstrap = db.query(User).filter_by(is_bootstrap_admin=True).first()
    if bootstrap is not None and bootstrap.group_id != group.id:
        bootstrap.group_id = group.id
    db.commit()


# Deterministic "widest access" precedence used by migrate_groups_and_
# users_to_single_assignment below when a User's pre-existing multi-group
# membership has to be collapsed to one group -- lower number = more
# permissive, wins the tie-break. Per explicit product decision: "admin"
# (this app's actual highest predefined privilege short of super_admin,
# which is never group-assignable to begin with) outranks everything;
# any CUSTOM role (not in this map at all) is treated as ranking between
# admin and editor -- more permissive than every other predefined role,
# since a custom role an admin deliberately created is more likely to be
# a deliberately elevated one than not, but never assumed to outrank the
# literal "admin" role itself.
_ROLE_RANK = {"admin": 0, "editor": 2, "user": 3, "viewer": 4}
_CUSTOM_ROLE_RANK = 1


def _role_rank(slug: str | None) -> int:
    if slug is None:
        return _CUSTOM_ROLE_RANK + 1  # no role at all -- least permissive of all, sorts last
    return _ROLE_RANK.get(slug, _CUSTOM_ROLE_RANK)


def migrate_groups_and_users_to_single_assignment(db: Session) -> None:
    """One-time (idempotent, safe on every startup) data migration for the
    single-group/single-role permissions model. Collapses any pre-existing
    "a group can have several roles" / "a user can belong to several
    groups" data (from the earlier Group-Only Permissions model -- shipped
    in v2.16.0/v2.16.1, so real multi-role/multi-group data is expected to
    be rare, but this handles it defensively per explicit spec) down to
    exactly one role per group and one group per user, then places any
    genuinely group-less user into a safe default. Must run AFTER
    seed_system_roles() (needs the "user" RoleDef to exist for step 3) and
    AFTER ensure_super_admin_group() (the bootstrap admin's group
    membership must already be settled -- this migration's step 3
    explicitly excludes it, on the assumption ensure_super_admin_group
    already handled it). Registered from the same two places as every
    other migration in this file (db.py's _seed_rbac + main.py's
    lifespan) -- see their own comments for the "fresh install vs.
    already-provisioned DB" reasoning.

    Reads the OLD group_role_defs/user_groups many-to-many join tables
    DIRECTLY via raw SQL (`text()` against the live connection) rather
    than through an ORM relationship -- models.py deliberately no longer
    maps either table (see Group's own docstring and the module-level
    comment right below it) now that neither is written to going forward,
    following the exact precedent this codebase already established for
    User.role/User.role_id when THAT model was superseded by groups (left
    in place as an inert relic, never dropped -- see db.py's module
    docstring for why this app's migration approach can only ever ADD
    schema, never drop/rename it). Both tables are guarded with
    `inspect(...).has_table(...)` first so this is also a safe no-op on a
    genuinely fresh install, where neither table has ever been created.

    Algorithm:
      1. Group role collapse: for every Group the OLD group_role_defs data
         shows holding more than one role, keep exactly the LOWEST role_id
         (earliest-created role, a simple and fully deterministic tie-
         break) and log which one was kept. Skipped for a Group whose
         role_id is already set (this migration's own prior run, or a
         group created directly under the new model).
      2. User group collapse: for every User the OLD user_groups data
         shows belonging to more than one group, keep the group whose
         assigned role is the WIDEST-access one, per _role_rank's explicit
         precedence order above (admin > any custom role > editor > user >
         viewer > no role at all); ties within the same rank break on the
         lowest group id, for determinism. This is a genuine, unavoidable
         access-REDUCING operation now that the union-of-groups feature is
         gone -- every affected user is logged (via this app's AuditLog,
         same mechanism every other state-changing action here uses) so
         an admin can review exactly who had a group membership dropped
         and which one was kept. Skipped for a User whose group_id is
         already set, or who is the bootstrap admin (that account is
         handled exclusively by ensure_super_admin_group, never here).
      3. Zero-group fallback: every remaining User with no group_id at all
         (never had one, or had zero groups in the old model) is placed
         into a find-or-create Group assigned the "user" RoleDef -- the
         least-privileged predefined role, chosen as a safe default rather
         than attempting to infer or preserve whatever the account might
         have implied before (there is no reliable prior signal to infer
         from for a user who was never actually in any group). Naming/
         collision handling mirrors the prior migrate_users_to_role_
         groups()'s own convention exactly: "User", or "User (auto)" /
         "User (auto N)" if that name is already taken by an unrelated
         group. The bootstrap admin is excluded from this step entirely
         (see ensure_super_admin_group, which must run first).

    Idempotent: a second run is a true no-op, since every step's guard
    (role_id/group_id already set) is checked before acting."""
    inspector = inspect(db.get_bind())

    changed = False

    # --- Step 1: collapse any Group holding >1 role -------------------------
    if inspector.has_table("group_role_defs"):
        rows = db.execute(text("SELECT group_id, role_id FROM group_role_defs ORDER BY group_id, role_id")).all()
        roles_by_group: dict[int, list[int]] = {}
        for group_id, role_id in rows:
            roles_by_group.setdefault(group_id, []).append(role_id)
        for group_id, role_ids in roles_by_group.items():
            group = db.get(Group, group_id)
            if group is None or group.role_id is not None:
                continue
            keep = min(role_ids)
            group.role_id = keep
            changed = True
            if len(role_ids) > 1:
                logger.warning(
                    "[single-group migration] Group '%s' (id=%s) had %d roles assigned (%s); "
                    "kept role_id=%d (lowest id).",
                    group.name, group.id, len(role_ids), sorted(role_ids), keep,
                )

    # --- Step 2: collapse any User belonging to >1 group ---------------------
    if inspector.has_table("user_groups"):
        rows = db.execute(text("SELECT user_id, group_id FROM user_groups ORDER BY user_id, group_id")).all()
        groups_by_user: dict[int, list[int]] = {}
        for user_id, group_id in rows:
            groups_by_user.setdefault(user_id, []).append(group_id)
        for user_id, group_ids in groups_by_user.items():
            user = db.get(User, user_id)
            if user is None or user.deleted or user.group_id is not None or user.is_bootstrap_admin:
                continue
            candidates = [g for g in (db.get(Group, gid) for gid in group_ids) if g is not None]
            if not candidates:
                continue

            def _candidate_rank(g: Group) -> tuple[int, int]:
                role = db.get(RoleDef, g.role_id) if g.role_id is not None else None
                return (_role_rank(role.slug if role is not None else None), g.id)

            chosen = min(candidates, key=_candidate_rank)
            user.group_id = chosen.id
            changed = True
            if len(candidates) > 1:
                dropped = [g.name for g in candidates if g.id != chosen.id]
                logger.warning(
                    "[single-group migration] User '%s' (id=%s) was in %d groups; kept '%s', dropped %s.",
                    user.username, user.id, len(candidates), chosen.name, dropped,
                )
                from .audit import log_action
                log_action(
                    db, user, "group_membership_reduced", target=user.username,
                    detail=f"single-group migration kept '{chosen.name}', dropped {dropped}",
                )

    # --- Step 3: zero-group fallback -----------------------------------------
    user_role = db.query(RoleDef).filter_by(slug="user").first()
    if user_role is not None:
        zero_group_users = db.query(User).filter(
            User.group_id.is_(None), User.deleted.is_(False), User.is_bootstrap_admin.is_(False),
        ).all()
        if zero_group_users:
            fallback_group = db.query(Group).filter(Group.role_id == user_role.id).order_by(Group.id).first()
            if fallback_group is None:
                name = "User"
                if db.query(Group).filter(Group.name == name).first() is not None:
                    name = "User (auto)"
                    n = 2
                    while db.query(Group).filter(Group.name == name).first() is not None:
                        name = f"User (auto {n})"
                        n += 1
                fallback_group = Group(
                    name=name, slug=None, role_id=user_role.id,
                    description=(
                        "Auto-created during the single-group/single-role permissions migration "
                        "as the default home for any account with no group assignment -- "
                        "reorganize freely."
                    ),
                )
                db.add(fallback_group)
                db.flush()
                changed = True
            for user in zero_group_users:
                user.group_id = fallback_group.id
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
