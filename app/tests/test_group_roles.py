"""Group-Only Permissions: groups are the EXCLUSIVE source of a user's
effective permissions. Covers permissions.py's effective_role_ids (now
purely the union of every role assigned, via group_role_defs, to every
group a user belongs to -- User.role_id/role are no longer consulted at
all, except for the super_admin hardcoded exemption, see below) and
routes/groups.py's role-assignment endpoints.

This replaces the earlier "Team-Based Permissions Phase 1" model, where a
user's own direct role_id was UNIONed on top of whatever their groups
granted. Backward compatibility for THAT change is instead proven in
test_permissions.py's TestMigrateUsersToRoleGroups (the auto-migration that
runs once at startup) -- this file's own TestEffectiveRoleIds tests the
group-only resolution logic itself, in isolation, against the NEW rules:
a user in zero groups (or in group(s) with zero assigned roles) gets ZERO
effective permissions, full stop, with the sole exception of the
super_admin role (see TestSuperAdminExemption), which never depends on
group membership at all."""
from vpnadmin.auth import hash_password
from vpnadmin.models import ApiScope, AuditLog, ObjectPermission, RoleApiScope, RoleDef, RoleKind, Group, User
from vpnadmin.permissions import effective_role_ids, has_permission, has_permission_any_scope

from .conftest import login


def _make_role(db_session, slug: str, *, object_key: str, action: str = "manage", scope: ApiScope | None = None) -> RoleDef:
    role = RoleDef(slug=slug, name=slug, kind=RoleKind.custom, is_system=False)
    db_session.add(role)
    db_session.flush()
    db_session.add(ObjectPermission(role_id=role.id, object_key=object_key, **{f"can_{action}": True}))
    if scope is not None:
        db_session.add(RoleApiScope(role_id=role.id, object_key=object_key, scope=scope))
    db_session.commit()
    return role


class TestEffectiveRoleIds:
    def test_user_in_zero_groups_has_no_effective_roles(self, db_session):
        """CORE RULE: a user in no group has NO effective role, full stop --
        no fallback to a personal role, no implicit "Default" group."""
        user = User(username="lonely", password_hash=hash_password("pw"), role_id=None)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == set()
        assert has_permission(db_session, user, "vpn_profiles", "view") is False

    def test_a_direct_role_id_with_no_group_grants_nothing(self, db_session):
        """The behavioral change from the old (Phase 1) model, made
        explicit: even a User row with role_id set gets ZERO effective
        permissions if they're in no group -- role_id is legacy/inert for
        permission purposes now."""
        role = _make_role(db_session, "solo-role", object_key="vpn_profiles", action="view")
        user = User(username="solo", password_hash=hash_password("pw"), role_id=role.id)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == set()
        assert has_permission(db_session, user, "vpn_profiles", "view") is False

    def test_user_in_group_with_zero_assigned_roles_gets_nothing(self, db_session):
        group = Group(name="Empty-Role Group")
        db_session.add(group)
        db_session.flush()
        user = User(username="grouped", password_hash=hash_password("pw"), role_id=None)
        user.groups.append(group)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == set()

    def test_user_in_group_with_assigned_role_gains_it(self, db_session):
        group_role = _make_role(db_session, "group-role", object_key="vpn_profiles", action="view")
        group = Group(name="Granting Group")
        group.role_defs.append(group_role)
        db_session.add(group)
        db_session.flush()
        user = User(username="grouponly", password_hash=hash_password("pw"), role_id=None)
        user.groups.append(group)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {group_role.id}
        assert has_permission(db_session, user, "vpn_profiles", "view") is True

    def test_two_groups_union_different_objects(self, db_session):
        """Conflict-resolution case 1 (trivial union): two groups grant
        permissions on DIFFERENT objects -- the user gets both."""
        role_a = _make_role(db_session, "role-a", object_key="vpn_profiles", action="view")
        role_b = _make_role(db_session, "role-b", object_key="settings", action="manage")
        group_a, group_b = Group(name="Group A"), Group(name="Group B")
        group_a.role_defs.append(role_a)
        group_b.role_defs.append(role_b)
        db_session.add_all([group_a, group_b])
        db_session.flush()
        user = User(username="two-groups-a", password_hash=hash_password("pw"), role_id=None)
        user.groups.extend([group_a, group_b])
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {role_a.id, role_b.id}
        assert has_permission(db_session, user, "vpn_profiles", "view") is True
        assert has_permission(db_session, user, "settings", "manage") is True
        assert has_permission(db_session, user, "users", "manage") is False  # neither role grants this

    def test_two_groups_same_object_action_different_roles_collapses_to_true(self, db_session):
        """Conflict-resolution case 2: two DIFFERENT roles (via two
        different groups) both grant the SAME object/action -- this RBAC
        system has no "deny" grants, only boolean can_X per role, so
        there's no possible conflict here: the redundant grants simply
        collapse to a single "yes", never an error or an ambiguous state."""
        role_a = _make_role(db_session, "dup-role-a", object_key="vpn_profiles", action="view")
        role_b = _make_role(db_session, "dup-role-b", object_key="vpn_profiles", action="view")
        group_a, group_b = Group(name="Dup Group A"), Group(name="Dup Group B")
        group_a.role_defs.append(role_a)
        group_b.role_defs.append(role_b)
        db_session.add_all([group_a, group_b])
        db_session.flush()
        user = User(username="two-groups-b", password_hash=hash_password("pw"), role_id=None)
        user.groups.extend([group_a, group_b])
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {role_a.id, role_b.id}
        assert has_permission(db_session, user, "vpn_profiles", "view") is True

    def test_scope_conflict_least_restrictive_wins(self, db_session):
        """Conflict-resolution case 3 (the one genuine place two roles'
        settings could look like they "conflict"): one granting role is
        scoped "own" for an object, another granting role (via a
        different group) is scoped "any" for the SAME object -- the union
        must resolve to "any" (least restrictive), never to "own" and
        never to an error. Mirrors _effective_scope's own "if ANY granting
        role has any-scope, the union is any-scope" rule."""
        own_role = _make_role(db_session, "scope-own", object_key="vpn_profiles", action="view", scope=ApiScope.own)
        any_role = _make_role(db_session, "scope-any", object_key="vpn_profiles", action="view")  # default scope: any
        group_own, group_any = Group(name="Own-Scope Group"), Group(name="Any-Scope Group")
        group_own.role_defs.append(own_role)
        group_any.role_defs.append(any_role)
        db_session.add_all([group_own, group_any])
        db_session.flush()
        user = User(username="scope-union", password_hash=hash_password("pw"), role_id=None)
        user.groups.extend([group_own, group_any])
        db_session.add(user)
        db_session.commit()

        assert has_permission(db_session, user, "vpn_profiles", "view") is True
        # has_permission_any_scope is what actually distinguishes "own" from
        # "any" -- see permissions.py's own docstring for why. True here
        # proves the union resolved to "any", not "own".
        assert has_permission_any_scope(db_session, user, "vpn_profiles", "view") is True

    def test_scope_stays_own_when_every_granting_role_is_own(self, db_session):
        """Converse of the above, for completeness: if EVERY granting role
        (across every group) is scoped "own", the union correctly stays
        "own" -- least-restrictive-wins only kicks in when at least one
        granting role is actually unrestricted."""
        own_role_a = _make_role(db_session, "scope-own-a", object_key="vpn_profiles", action="view", scope=ApiScope.own)
        own_role_b = _make_role(db_session, "scope-own-b", object_key="vpn_profiles", action="view", scope=ApiScope.own)
        group_a, group_b = Group(name="Own Group A"), Group(name="Own Group B")
        group_a.role_defs.append(own_role_a)
        group_b.role_defs.append(own_role_b)
        db_session.add_all([group_a, group_b])
        db_session.flush()
        user = User(username="scope-still-own", password_hash=hash_password("pw"), role_id=None)
        user.groups.extend([group_a, group_b])
        db_session.add(user)
        db_session.commit()

        assert has_permission(db_session, user, "vpn_profiles", "view") is True
        assert has_permission_any_scope(db_session, user, "vpn_profiles", "view") is False

    def test_system_and_custom_role_mix_unions_identically(self, db_session):
        """Conflict-resolution case 4: a system/predefined role (e.g.
        "editor", seeded by seed_system_roles) assigned to one group and a
        custom role assigned to another group, both applied to the same
        user -- the union works identically regardless of role type. No
        special-casing of RoleKind.system vs RoleKind.custom anywhere in
        _granting_role_ids/_effective_scope (both operate purely on
        role_id sets), and this test proves it end to end."""
        from vpnadmin.permissions import seed_system_roles
        seed_system_roles(db_session)
        system_role = db_session.query(RoleDef).filter_by(slug="editor").one()
        custom_role = _make_role(db_session, "mix-custom", object_key="reports", action="manage")
        group_sys, group_custom = Group(name="System Role Group"), Group(name="Custom Role Group")
        group_sys.role_defs.append(system_role)
        group_custom.role_defs.append(custom_role)
        db_session.add_all([group_sys, group_custom])
        db_session.flush()
        user = User(username="mix-user", password_hash=hash_password("pw"), role_id=None)
        user.groups.extend([group_sys, group_custom])
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {system_role.id, custom_role.id}
        # editor's own grant (vpn_profiles:update, see _SYSTEM_ROLES) ...
        assert has_permission(db_session, user, "vpn_profiles", "update") is True
        # ... and the custom role's grant, both present -- a clean union,
        # never an ambiguous/denying outcome regardless of role type.
        assert has_permission(db_session, user, "reports", "manage") is True


class TestSuperAdminExemption:
    """super_admin is reserved exclusively for the bootstrap admin account
    and is HARDCODED-exempt from the group-only model: its access must
    never depend on, and must never be affected by, group membership --
    verified here precisely (not assumed) since the group-only rewrite of
    effective_role_ids removed User.role_id from the general union, which
    would otherwise have been the first time super_admin's access could
    ever be gated on groups at all."""

    def test_super_admin_with_zero_groups_keeps_full_access(self, db_session):
        from vpnadmin.permissions import seed_system_roles
        seed_system_roles(db_session)
        super_admin_role = db_session.query(RoleDef).filter_by(slug="super_admin").one()
        user = User(username="root", password_hash=hash_password("pw"), role_id=super_admin_role.id, is_bootstrap_admin=True)
        db_session.add(user)
        db_session.commit()

        assert user.groups == []  # zero group memberships, the case under test
        assert effective_role_ids(db_session, user) == {super_admin_role.id}
        # Full access to everything, including objects a "zero groups"
        # user would otherwise never see any permission for.
        assert has_permission(db_session, user, "roles", "manage") is True
        assert has_permission(db_session, user, "settings", "manage") is True
        assert has_permission(db_session, user, "db_reporting", "manage") is True

    def test_super_admin_access_unaffected_by_group_membership_either_way(self, db_session):
        """Putting super_admin in a group (even a group granting nothing,
        or a group with a totally different/lesser role) must not change
        their access at all -- the exemption is a hardcoded short-circuit
        BEFORE group resolution ever runs, not "one more grant in the
        union"."""
        from vpnadmin.permissions import seed_system_roles
        seed_system_roles(db_session)
        super_admin_role = db_session.query(RoleDef).filter_by(slug="super_admin").one()
        viewer_role = db_session.query(RoleDef).filter_by(slug="viewer").one()
        empty_group = Group(name="Empty Group")
        viewer_group = Group(name="Viewer-Only Group")
        viewer_group.role_defs.append(viewer_role)
        db_session.add_all([empty_group, viewer_group])
        db_session.flush()
        user = User(username="root2", password_hash=hash_password("pw"), role_id=super_admin_role.id, is_bootstrap_admin=True)
        user.groups.extend([empty_group, viewer_group])
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {super_admin_role.id}
        assert has_permission(db_session, user, "settings", "manage") is True


class TestGroupRoleAssignmentApi:
    def test_denied_without_groups_manage(self, app_client, db_session):
        group = Group(name="API Group")
        db_session.add(group)
        db_session.commit()
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post(f"/api/groups/{group.id}/roles", json={"role_id": 1})
        assert r.status_code == 403

    def test_assign_and_remove_round_trip(self, app_client, db_session):
        role = db_session.query(RoleDef).filter_by(slug="editor").first()
        group = Group(name="Assignable Group")
        db_session.add(group)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/groups/{group.id}/roles", json={"role_id": role.id})
        assert r.status_code == 201
        assert {rl["id"] for rl in r.json()["roles"]} == {role.id}

        # Reflected back on the list endpoint too.
        listed = app_client.get("/api/groups").json()
        api_group = next(t for t in listed if t["id"] == group.id)
        assert {rl["id"] for rl in api_group["roles"]} == {role.id}

        r2 = app_client.delete(f"/api/groups/{group.id}/roles/{role.id}")
        assert r2.status_code == 200
        listed2 = app_client.get("/api/groups").json()
        api_group2 = next(t for t in listed2 if t["id"] == group.id)
        assert api_group2["roles"] == []

    def test_assign_and_remove_are_audit_logged(self, app_client, db_session):
        role = db_session.query(RoleDef).filter_by(slug="viewer").first()
        group = Group(name="Audited Group")
        db_session.add(group)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        app_client.post(f"/api/groups/{group.id}/roles", json={"role_id": role.id})
        app_client.delete(f"/api/groups/{group.id}/roles/{role.id}")

        actions = [a.action for a in db_session.query(AuditLog).order_by(AuditLog.id).all()]
        assert "group_role_assigned" in actions
        assert "group_role_removed" in actions
        assigned = db_session.query(AuditLog).filter_by(action="group_role_assigned").one()
        assert assigned.target == "Audited Group"
        assert assigned.detail == "viewer"
        assert assigned.username == "admin"

    def test_available_roles_endpoint_gated_and_lists_roles(self, app_client, db_session):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/groups/available-roles")
        assert r.status_code == 403

        login(app_client, "admin", "adminpass123")
        r2 = app_client.get("/api/groups/available-roles")
        assert r2.status_code == 200
        slugs = {r["slug"] for r in r2.json()}
        assert "admin" in slugs and "viewer" in slugs

    def test_available_roles_excludes_super_admin(self, app_client, db_session):
        """super_admin is reserved for the bootstrap admin account and
        never sourced from group membership (see effective_role_ids'
        hardcoded exemption) -- it must not be offered as an assignable
        role on the Groups page at all."""
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/groups/available-roles")
        assert r.status_code == 200
        assert "super_admin" not in {row["slug"] for row in r.json()}

    def test_assigning_super_admin_role_to_a_group_is_rejected(self, app_client, db_session):
        """Server-side backstop behind the (now super_admin-free) Assign
        Roles dropdown -- a direct API call can't slip it in either."""
        super_admin_role = db_session.query(RoleDef).filter_by(slug="super_admin").one()
        group = Group(name="Sneaky Group")
        db_session.add(group)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/groups/{group.id}/roles", json={"role_id": super_admin_role.id})
        assert r.status_code == 400
        assert "super admin" in r.json()["detail"].lower()
