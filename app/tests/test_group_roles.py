"""Single-Group, Single-Role Permissions: a user belongs to AT MOST one
group, and a group is assigned AT MOST one role -- that role is the user's
ONLY source of permissions (see permissions.py's effective_role_ids). Covers
effective_role_ids itself, routes/groups.py's role-assignment/member-move
endpoints, and the immutable "SuperAdmin" group's server-side guards.

This replaces the earlier "Group-Only Permissions" model, where a user
could belong to several groups and a group could be assigned several
roles, with effective permissions being the UNION across all of it.
Backward compatibility for that change is covered in test_permissions.py's
TestMigrateGroupsAndUsersToSingleAssignment (the auto-migration that runs
once at startup) -- this file's own TestEffectiveRoleIds tests the
single-group resolution logic itself, in isolation, against the NEW rules:
a user with no group (or whose group has no role assigned) gets ZERO
effective permissions, full stop, with the sole exception of the
super_admin role (see TestSuperAdminExemption), which never depends on
group membership at all."""
from vpnadmin.auth import hash_password
from vpnadmin.models import SUPER_ADMIN_GROUP_NAME, AuditLog, Group, ObjectPermission, RoleDef, RoleKind, User
from vpnadmin.permissions import effective_role_ids, ensure_super_admin_group, has_permission

from .conftest import login


def _make_role(db_session, slug: str, *, object_key: str, action: str = "manage") -> RoleDef:
    role = RoleDef(slug=slug, name=slug, kind=RoleKind.custom, is_system=False)
    db_session.add(role)
    db_session.flush()
    db_session.add(ObjectPermission(role_id=role.id, object_key=object_key, **{f"can_{action}": True}))
    db_session.commit()
    return role


class TestEffectiveRoleIds:
    def test_user_with_no_group_has_no_effective_roles(self, db_session):
        """CORE RULE: a user with no group has NO effective role, full
        stop -- no fallback to a personal role."""
        user = User(username="lonely", password_hash=hash_password("pw"), role_id=None)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == set()
        assert has_permission(db_session, user, "vpn_profiles", "view") is False

    def test_a_direct_role_id_with_no_group_grants_nothing(self, db_session):
        """A User row with role_id set gets ZERO effective permissions if
        they're in no group -- role_id is legacy/inert for permission
        purposes now."""
        role = _make_role(db_session, "solo-role", object_key="vpn_profiles", action="view")
        user = User(username="solo", password_hash=hash_password("pw"), role_id=role.id)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == set()
        assert has_permission(db_session, user, "vpn_profiles", "view") is False

    def test_user_in_group_with_no_assigned_role_gets_nothing(self, db_session):
        group = Group(name="Roleless Group")
        db_session.add(group)
        db_session.flush()
        user = User(username="grouped", password_hash=hash_password("pw"), role_id=None, group_id=group.id)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == set()

    def test_user_in_group_with_assigned_role_gains_it(self, db_session):
        group_role = _make_role(db_session, "group-role", object_key="vpn_profiles", action="view")
        group = Group(name="Granting Group", role_id=group_role.id)
        db_session.add(group)
        db_session.flush()
        user = User(username="grouponly", password_hash=hash_password("pw"), role_id=None, group_id=group.id)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {group_role.id}
        assert has_permission(db_session, user, "vpn_profiles", "view") is True

    def test_system_and_custom_role_both_resolve_identically(self, db_session):
        """No special-casing of RoleKind.system vs RoleKind.custom
        anywhere in _granting_role_ids/_effective_scope (both operate
        purely on role_id) -- proven for both kinds here."""
        from vpnadmin.permissions import seed_system_roles
        seed_system_roles(db_session)
        system_role = db_session.query(RoleDef).filter_by(slug="editor").one()
        group = Group(name="System Role Group", role_id=system_role.id)
        db_session.add(group)
        db_session.flush()
        user = User(username="sys-user", password_hash=hash_password("pw"), role_id=None, group_id=group.id)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {system_role.id}
        assert has_permission(db_session, user, "vpn_profiles", "update") is True  # editor's own grant

        custom_role = _make_role(db_session, "custom-role", object_key="reports", action="manage")
        custom_group = Group(name="Custom Role Group", role_id=custom_role.id)
        db_session.add(custom_group)
        db_session.flush()
        custom_user = User(username="custom-user", password_hash=hash_password("pw"), role_id=None, group_id=custom_group.id)
        db_session.add(custom_user)
        db_session.commit()

        assert effective_role_ids(db_session, custom_user) == {custom_role.id}
        assert has_permission(db_session, custom_user, "reports", "manage") is True


class TestSuperAdminExemption:
    """super_admin is reserved exclusively for the bootstrap admin account
    and is HARDCODED-exempt from the group model: its access must never
    depend on, and must never be affected by, group membership -- verified
    here precisely (not assumed)."""

    def test_super_admin_with_no_group_keeps_full_access(self, db_session):
        from vpnadmin.permissions import seed_system_roles
        seed_system_roles(db_session)
        super_admin_role = db_session.query(RoleDef).filter_by(slug="super_admin").one()
        user = User(username="root", password_hash=hash_password("pw"), role_id=super_admin_role.id, is_bootstrap_admin=True)
        db_session.add(user)
        db_session.commit()

        assert user.group is None  # no group membership, the case under test
        assert effective_role_ids(db_session, user) == {super_admin_role.id}
        # Full access to everything, including objects a group-less user
        # would otherwise never see any permission for.
        assert has_permission(db_session, user, "roles", "manage") is True
        assert has_permission(db_session, user, "settings", "manage") is True
        assert has_permission(db_session, user, "db_reporting", "manage") is True

    def test_super_admin_access_unaffected_by_its_own_groups_role(self, db_session):
        """The SuperAdmin group's own role assignment is COSMETIC (see
        ensure_super_admin_group's docstring) -- putting super_admin in a
        group granting a totally different/lesser role must not change
        its access at all, since the exemption is a hardcoded short-circuit
        BEFORE group resolution ever runs, not "sourced from the group"."""
        from vpnadmin.permissions import seed_system_roles
        seed_system_roles(db_session)
        super_admin_role = db_session.query(RoleDef).filter_by(slug="super_admin").one()
        viewer_role = db_session.query(RoleDef).filter_by(slug="viewer").one()
        viewer_group = Group(name="Viewer-Only Group", role_id=viewer_role.id)
        db_session.add(viewer_group)
        db_session.flush()
        user = User(username="root2", password_hash=hash_password("pw"), role_id=super_admin_role.id,
                    is_bootstrap_admin=True, group_id=viewer_group.id)
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
        r = app_client.put(f"/api/groups/{group.id}/role", json={"role_id": 1})
        assert r.status_code == 403

    def test_set_and_clear_role_round_trip(self, app_client, db_session):
        role = db_session.query(RoleDef).filter_by(slug="editor").first()
        group = Group(name="Assignable Group")
        db_session.add(group)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.put(f"/api/groups/{group.id}/role", json={"role_id": role.id})
        assert r.status_code == 200
        assert r.json()["role"]["id"] == role.id

        # Reflected back on the list endpoint too.
        listed = app_client.get("/api/groups").json()
        api_group = next(t for t in listed if t["id"] == group.id)
        assert api_group["role"]["id"] == role.id

        r2 = app_client.put(f"/api/groups/{group.id}/role", json={"role_id": None})
        assert r2.status_code == 200
        assert r2.json()["role"] is None

    def test_setting_a_role_replaces_not_adds(self, app_client, db_session):
        """A group has AT MOST one role -- setting a second one REPLACES
        the first, it never results in more than one."""
        role_a = db_session.query(RoleDef).filter_by(slug="editor").one()
        role_b = db_session.query(RoleDef).filter_by(slug="viewer").one()
        group = Group(name="Single Role Group", role_id=role_a.id)
        db_session.add(group)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.put(f"/api/groups/{group.id}/role", json={"role_id": role_b.id})
        assert r.status_code == 200
        assert r.json()["role"]["id"] == role_b.id

        db_session.expire_all()
        assert db_session.get(Group, group.id).role_id == role_b.id

    def test_assign_and_clear_are_audit_logged(self, app_client, db_session):
        role = db_session.query(RoleDef).filter_by(slug="viewer").first()
        group = Group(name="Audited Group")
        db_session.add(group)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        app_client.put(f"/api/groups/{group.id}/role", json={"role_id": role.id})
        app_client.put(f"/api/groups/{group.id}/role", json={"role_id": None})

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
        """Server-side backstop behind the (now super_admin-free) Role
        picker -- a direct API call can't slip it in either."""
        super_admin_role = db_session.query(RoleDef).filter_by(slug="super_admin").one()
        group = Group(name="Sneaky Group")
        db_session.add(group)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.put(f"/api/groups/{group.id}/role", json={"role_id": super_admin_role.id})
        assert r.status_code == 400
        assert "super admin" in r.json()["detail"].lower()


class TestSuperAdminGroupImmutability:
    """The "SuperAdmin" group (permissions.py's ensure_super_admin_group)
    is immutable, enforced server-side in routes/groups.py -- every
    rejection case gets its own test here, exercised by an ordinary admin
    (groups:manage via the group-only/single-role model)."""

    def _bootstrap_and_super_admin_group(self, db_session, app_client):
        ensure_super_admin_group(db_session)
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.is_bootstrap_admin = True
        db_session.commit()
        ensure_super_admin_group(db_session)  # picks up the just-flagged bootstrap admin
        db_session.expire_all()
        group = db_session.query(Group).filter_by(name=SUPER_ADMIN_GROUP_NAME).one()
        return group

    def test_visible_on_groups_list(self, app_client, db_session):
        group = self._bootstrap_and_super_admin_group(db_session, app_client)
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/groups")
        assert r.status_code == 200
        row = next(g for g in r.json() if g["id"] == group.id)
        assert row["is_super_admin_group"] is True
        assert row["role"]["slug"] == "super_admin"

    def test_cannot_be_renamed_or_redescribed(self, app_client, db_session):
        group = self._bootstrap_and_super_admin_group(db_session, app_client)
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/groups/{group.id}", json={"name": "Renamed"})
        assert r.status_code == 400
        r2 = app_client.patch(f"/api/groups/{group.id}", json={"description": "nope"})
        assert r2.status_code == 400

    def test_cannot_be_deleted(self, app_client, db_session):
        group = self._bootstrap_and_super_admin_group(db_session, app_client)
        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/groups/{group.id}")
        assert r.status_code == 400
        assert "super" in r.json()["detail"].lower()

    def test_role_can_never_be_changed_away_from_super_admin(self, app_client, db_session):
        group = self._bootstrap_and_super_admin_group(db_session, app_client)
        editor_role = db_session.query(RoleDef).filter_by(slug="editor").one()
        login(app_client, "admin", "adminpass123")
        r = app_client.put(f"/api/groups/{group.id}/role", json={"role_id": editor_role.id})
        assert r.status_code == 400
        r2 = app_client.put(f"/api/groups/{group.id}/role", json={"role_id": None})
        assert r2.status_code == 400

    def test_cannot_add_a_member(self, app_client, db_session):
        group = self._bootstrap_and_super_admin_group(db_session, app_client)
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/groups/{group.id}/members", json={"user_id": viewer_id})
        assert r.status_code == 400

    def test_cannot_remove_the_bootstrap_admin(self, app_client, db_session):
        group = self._bootstrap_and_super_admin_group(db_session, app_client)
        bootstrap = db_session.query(User).filter(User.is_bootstrap_admin.is_(True)).one()
        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/groups/{group.id}/members/{bootstrap.id}")
        assert r.status_code == 400
        db_session.expire_all()
        assert db_session.get(User, bootstrap.id).group_id == group.id  # unchanged

    def test_bootstrap_admin_cannot_be_moved_to_a_different_group_via_user_edit(self, app_client, db_session):
        """The other place group membership could be changed -- PATCH
        /api/users/{id}'s group_id field -- already skips the bootstrap
        admin entirely (see routes/users.py's update_user); confirmed here
        specifically for a target whose group is the SuperAdmin group."""
        group = self._bootstrap_and_super_admin_group(db_session, app_client)
        bootstrap = db_session.query(User).filter(User.is_bootstrap_admin.is_(True)).one()
        other_group = Group(name="Somewhere Else")
        db_session.add(other_group)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{bootstrap.id}", json={"group_id": other_group.id})
        assert r.status_code == 200  # silently a no-op, not an error -- same as every other bootstrap-admin guard
        db_session.expire_all()
        assert db_session.get(User, bootstrap.id).group_id == group.id
