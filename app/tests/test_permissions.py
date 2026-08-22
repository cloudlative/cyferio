"""Tests for permissions.py's system-role seeding, including the
rename_legacy_vpn_self_service_role() migration fixup (see its own
docstring / db.py's _seed_rbac for why it exists and must run first), and
migrate_users_to_role_groups() -- the group-only permissions auto-migration
(see its own docstring for the algorithm) that's the single most
important guarantee in this whole feature: nobody's access changes on
deploy."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from vpnadmin.auth import hash_password
from vpnadmin.db import Base
from vpnadmin.models import Group, ObjectPermission, RoleDef, User, group_role_defs, user_groups
from vpnadmin.permissions import ACTIONS, OBJECTS, _has_permission, effective_role_ids, has_permission


def _fresh_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


class TestSeedSystemRoles:
    def test_fresh_seed_creates_user_role_not_legacy_slug(self):
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        seed_system_roles(db)
        assert db.query(RoleDef).filter_by(slug="user").first() is not None
        assert db.query(RoleDef).filter_by(slug="vpn_self_service").first() is None
        assert db.query(RoleDef).filter_by(slug="user").first().name == "User"

    def test_backfills_new_object_onto_a_preexisting_system_role(self):
        """Regression test for a real bug found live: a system role
        (e.g. "admin") seeded BEFORE "db_reporting" was added to OBJECTS
        never picked up the new permission row, because the old
        implementation skipped an existing role entirely (`if role is not
        None: continue`) instead of backfilling just the missing object.
        Simulates that exact scenario: an "admin" RoleDef that already
        exists with only a subset of today's OBJECTS granted (as if seeded
        by an older code version), then confirms a second seed_system_roles()
        call fills in the gap without touching what was already there."""
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        role = RoleDef(slug="admin", name="Admin", is_system=True)
        db.add(role)
        db.flush()
        # Only "dashboard" granted -- stands in for "every object that
        # existed when this role was originally seeded, before db_reporting
        # was added to the registry".
        db.add(ObjectPermission(role_id=role.id, object_key="dashboard", can_manage=True))
        db.commit()

        seed_system_roles(db)

        perms = {p.object_key: p for p in db.query(ObjectPermission).filter_by(role_id=role.id).all()}
        assert "db_reporting" in perms
        assert perms["db_reporting"].can_manage is True
        # The pre-existing row must be untouched, not replaced (same object
        # instance's can_manage value, not just an equal one).
        assert perms["dashboard"].can_manage is True

    def test_mfa_admin_backfills_onto_a_preexisting_admin_role_at_manage_level(self):
        """"mfa_admin" was split out of "users" (see permissions.py's
        OBJECTS entry) specifically so existing deployments aren't locked
        out: a system role seeded before this split -- with users:manage
        already granted -- must pick up mfa_admin at can_manage=True too on
        the next seed_system_roles() call, mirroring what users:manage
        already gave "admin" for MFA actions before the split. Simulates a
        pre-split "admin" row the same way
        test_backfills_new_object_onto_a_preexisting_system_role does for
        db_reporting."""
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        role = RoleDef(slug="admin", name="Admin", is_system=True)
        db.add(role)
        db.flush()
        db.add(ObjectPermission(role_id=role.id, object_key="users", can_manage=True))
        db.commit()

        seed_system_roles(db)

        perms = {p.object_key: p for p in db.query(ObjectPermission).filter_by(role_id=role.id).all()}
        assert "mfa_admin" in perms
        assert perms["mfa_admin"].can_manage is True
        assert perms["users"].can_manage is True  # untouched

    def test_viewer_role_does_not_get_mfa_admin(self):
        """Viewer never had users:manage (only users:view), so it must not
        pick up mfa_admin either -- confirms the blanket "view everything"
        comprehension in _SYSTEM_ROLES' viewer spec deliberately excludes
        mfa_admin (same exclusion list as db_reporting/system_audit)."""
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        seed_system_roles(db)

        viewer = db.query(RoleDef).filter_by(slug="viewer").one()
        perm = db.query(ObjectPermission).filter_by(role_id=viewer.id, object_key="mfa_admin").first()
        assert perm is None

    def test_never_touches_an_already_granted_object(self):
        """A deliberately customized existing row (e.g. an admin manually
        revoked a system role's access to one module) must survive a
        re-seed -- the backfill only fills gaps, it never re-asserts or
        resets a row that's already present."""
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        role = RoleDef(slug="admin", name="Admin", is_system=True)
        db.add(role)
        db.flush()
        db.add(ObjectPermission(role_id=role.id, object_key="dashboard", can_manage=False))  # deliberately revoked
        db.commit()

        seed_system_roles(db)

        perm = db.query(ObjectPermission).filter_by(role_id=role.id, object_key="dashboard").one()
        assert perm.can_manage is False


class TestRenameLegacyVpnSelfServiceRole:
    def test_renames_existing_legacy_row_in_place(self):
        from vpnadmin.permissions import rename_legacy_vpn_self_service_role

        db = _fresh_session()
        legacy = RoleDef(slug="vpn_self_service", name="VPN Self-Service User", is_system=True)
        db.add(legacy)
        db.commit()
        legacy_id = legacy.id

        rename_legacy_vpn_self_service_role(db)

        assert db.query(RoleDef).filter_by(slug="vpn_self_service").first() is None
        renamed = db.query(RoleDef).filter_by(slug="user").first()
        assert renamed is not None
        assert renamed.id == legacy_id  # same row, not a new one -- existing role_id FKs still resolve
        assert renamed.name == "User"

    def test_noop_when_no_legacy_row_exists(self):
        from vpnadmin.permissions import rename_legacy_vpn_self_service_role

        db = _fresh_session()
        rename_legacy_vpn_self_service_role(db)
        assert db.query(RoleDef).count() == 0

    def test_noop_when_user_role_already_exists(self):
        """Even if a stray vpn_self_service row somehow also exists, never
        touch it once a "user" row is already present -- avoids clobbering
        an admin's deliberate customization of the real, active role."""
        from vpnadmin.permissions import rename_legacy_vpn_self_service_role

        db = _fresh_session()
        db.add(RoleDef(slug="user", name="User", is_system=True))
        db.add(RoleDef(slug="vpn_self_service", name="VPN Self-Service User", is_system=True))
        db.commit()

        rename_legacy_vpn_self_service_role(db)

        assert db.query(RoleDef).filter_by(slug="vpn_self_service").first() is not None
        assert db.query(RoleDef).count() == 2

    def test_runs_before_seed_avoids_duplicate_role(self):
        """The real ordering db.py's _seed_rbac uses: rename first, then
        seed_system_roles -- must not end up with both vpn_self_service and
        a freshly-created "user" row."""
        from vpnadmin.permissions import rename_legacy_vpn_self_service_role, seed_system_roles

        db = _fresh_session()
        legacy = RoleDef(slug="vpn_self_service", name="VPN Self-Service User", is_system=True)
        db.add(legacy)
        db.commit()
        legacy_id = legacy.id

        rename_legacy_vpn_self_service_role(db)
        seed_system_roles(db)

        assert db.query(RoleDef).filter_by(slug="user").count() == 1
        assert db.query(RoleDef).filter_by(slug="vpn_self_service").first() is None
        assert db.query(RoleDef).filter_by(slug="user").first().id == legacy_id


class TestMigrateUsersToRoleGroups:
    """The group-only permissions auto-migration. THE test that proves
    "nobody's access changes on day one" is test_migration_preserves_every_
    role_s_permissions_exactly below -- everything else here covers
    idempotency and the specific collision/skip rules from the function's
    own docstring."""

    def _seed(self, db):
        from vpnadmin.permissions import seed_system_roles
        seed_system_roles(db)
        return {r.slug: r for r in db.query(RoleDef).all()}

    def test_migration_preserves_every_role_s_permissions_exactly(self):
        """THE regression test: simulate "every current user has some
        role_id set, no groups exist yet" (today's reality for every
        pre-existing deployment), capture what has_permission() would have
        returned for every OBJECTS x ACTIONS combination under the OLD
        logic (a bare role_id lookup -- Phase 1's effective_role_ids for a
        user in zero teams was exactly {user.role_id}, and pre-migration
        there ARE zero groups, so this is precisely equivalent), run the
        migration, then assert has_permission() under the NEW (group-only)
        logic produces the EXACT same result for every single combination,
        for a representative user of every system role (super_admin,
        admin, editor, viewer, user) plus one custom role."""
        from vpnadmin.permissions import migrate_users_to_role_groups

        db = _fresh_session()
        roles = self._seed(db)
        custom = RoleDef(slug="custom-auditor", name="Custom Auditor", is_system=False)
        db.add(custom)
        db.flush()
        db.add(ObjectPermission(role_id=custom.id, object_key="audit_log", can_view=True))
        db.commit()
        roles["custom-auditor"] = custom

        sample_slugs = ["super_admin", "admin", "editor", "viewer", "user", "custom-auditor"]
        users = {}
        for slug in sample_slugs:
            u = User(username=f"u-{slug}", password_hash=hash_password("pw"), role_id=roles[slug].id)
            if slug == "super_admin":
                u.is_bootstrap_admin = True
            db.add(u)
            users[slug] = u
        db.commit()

        # "Before" snapshot, using the OLD logic directly: a bare
        # role_id -> ObjectPermission lookup, no groups involved (there are
        # none yet) -- exactly what Phase 1's effective_role_ids resolved
        # to for a user in zero teams.
        before = {
            slug: {
                (obj, action): _has_permission(db, {roles[slug].id}, obj, action)
                for obj in OBJECTS for action in ACTIONS
            }
            for slug in sample_slugs
        }

        migrate_users_to_role_groups(db)
        db.expire_all()  # force a fresh read of .groups for every user below

        after = {
            slug: {
                (obj, action): has_permission(db, users[slug], obj, action)
                for obj in OBJECTS for action in ACTIONS
            }
            for slug in sample_slugs
        }

        for slug in sample_slugs:
            assert after[slug] == before[slug], f"permission set changed for role '{slug}' across the migration"

    def test_creates_one_group_per_distinct_role_and_adds_holders(self):
        from vpnadmin.permissions import migrate_users_to_role_groups

        db = _fresh_session()
        roles = self._seed(db)
        alice = User(username="alice", password_hash=hash_password("pw"), role_id=roles["admin"].id)
        bob = User(username="bob", password_hash=hash_password("pw"), role_id=roles["admin"].id)
        carol = User(username="carol", password_hash=hash_password("pw"), role_id=roles["viewer"].id)
        db.add_all([alice, bob, carol])
        db.commit()

        migrate_users_to_role_groups(db)
        db.expire_all()

        admin_groups = [g for g in db.query(Group).all() if roles["admin"] in g.role_defs]
        assert len(admin_groups) == 1
        assert {u.username for u in admin_groups[0].members} == {"alice", "bob"}
        viewer_groups = [g for g in db.query(Group).all() if roles["viewer"] in g.role_defs]
        assert len(viewer_groups) == 1
        assert {u.username for u in viewer_groups[0].members} == {"carol"}

    def test_excludes_super_admin_from_migration(self):
        """super_admin is exempted from the group-only model entirely (see
        effective_role_ids' hardcoded exemption) -- migrating it into a
        group would be pointless clutter, not a real backward-compat
        need, so the migration must skip it."""
        from vpnadmin.permissions import migrate_users_to_role_groups

        db = _fresh_session()
        roles = self._seed(db)
        root = User(username="root", password_hash=hash_password("pw"), role_id=roles["super_admin"].id, is_bootstrap_admin=True)
        db.add(root)
        db.commit()

        migrate_users_to_role_groups(db)
        db.expire_all()

        assert db.query(Group).count() == 0
        assert root.groups == []
        # And access is still fully intact regardless (the hardcoded
        # exemption, not group membership, is what grants it).
        assert has_permission(db, root, "settings", "manage") is True

    def test_idempotent_running_twice_produces_identical_end_state(self):
        from vpnadmin.permissions import migrate_users_to_role_groups

        db = _fresh_session()
        roles = self._seed(db)
        alice = User(username="alice2", password_hash=hash_password("pw"), role_id=roles["admin"].id)
        db.add(alice)
        db.commit()

        migrate_users_to_role_groups(db)
        db.expire_all()
        group_count_1 = db.query(Group).count()
        membership_count_1 = db.query(user_groups).count()
        assignment_count_1 = db.query(group_role_defs).count()

        migrate_users_to_role_groups(db)  # second run -- must be a no-op
        db.expire_all()

        assert db.query(Group).count() == group_count_1
        assert db.query(user_groups).count() == membership_count_1
        assert db.query(group_role_defs).count() == assignment_count_1
        assert effective_role_ids(db, alice) == {roles["admin"].id}

    def test_skips_a_user_already_in_a_group_with_the_equivalent_role(self):
        """A user an admin already manually organized into a group with
        the same role_id (before the migration ever ran, or between two
        runs) must not get a redundant second membership in the
        auto-created migration group."""
        from vpnadmin.permissions import migrate_users_to_role_groups

        db = _fresh_session()
        roles = self._seed(db)
        manual_group = Group(name="Hand-Rolled Editors")
        manual_group.role_defs.append(roles["editor"])
        db.add(manual_group)
        db.flush()
        dave = User(username="dave", password_hash=hash_password("pw"), role_id=roles["editor"].id)
        dave.groups.append(manual_group)
        db.add(dave)
        db.commit()

        migrate_users_to_role_groups(db)
        db.expire_all()

        assert dave.groups == [manual_group]  # no second, auto-created group membership
        assert db.query(Group).count() == 1  # no new group created either
