"""Tests for permissions.py's system-role seeding, including the
rename_legacy_vpn_self_service_role() migration fixup (see its own
docstring / db.py's _seed_rbac for why it exists and must run first), and
migrate_groups_and_users_to_single_assignment() -- the single-group/
single-role permissions auto-migration (see its own docstring for the
algorithm) that's the single most important guarantee in this whole
feature: nobody's access changes on deploy."""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from vpnadmin.auth import hash_password
from vpnadmin.db import Base
from vpnadmin.models import SUPER_ADMIN_GROUP_NAME, Group, ObjectPermission, RoleDef, User
from vpnadmin.permissions import ACTIONS, OBJECTS, ensure_super_admin_group, has_permission


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


class TestEnsureSuperAdminGroup:
    """permissions.py's ensure_super_admin_group -- the immutable
    "SuperAdmin" group's idempotent creation/maintenance, mirroring
    db.py's promote_bootstrap_admin_to_super_admin's own structure and
    tests almost exactly."""

    def test_noop_when_super_admin_role_not_yet_seeded(self):
        db = _fresh_session()
        ensure_super_admin_group(db)
        assert db.query(Group).count() == 0

    def test_creates_group_but_no_bootstrap_admin_yet_is_a_partial_noop(self):
        """Fresh-install ordering: seed_system_roles has run, but
        bootstrap_admin() (main.py's lifespan) hasn't created the account
        yet -- the group is still created (so it's visible/ready), but
        nothing to point its membership at."""
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        seed_system_roles(db)
        ensure_super_admin_group(db)

        group = db.query(Group).filter_by(name=SUPER_ADMIN_GROUP_NAME).one()
        role = db.query(RoleDef).filter_by(slug="super_admin").one()
        assert group.role_id == role.id

    def test_places_bootstrap_admin_into_the_group(self):
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        seed_system_roles(db)
        role = db.query(RoleDef).filter_by(slug="super_admin").one()
        bootstrap = User(username="root", password_hash=hash_password("pw"), role_id=role.id, is_bootstrap_admin=True)
        db.add(bootstrap)
        db.commit()

        ensure_super_admin_group(db)
        db.expire_all()

        group = db.query(Group).filter_by(name=SUPER_ADMIN_GROUP_NAME).one()
        assert db.query(User).filter_by(username="root").one().group_id == group.id

    def test_idempotent_running_twice_produces_identical_end_state(self):
        from vpnadmin.permissions import seed_system_roles

        db = _fresh_session()
        seed_system_roles(db)
        role = db.query(RoleDef).filter_by(slug="super_admin").one()
        bootstrap = User(username="root", password_hash=hash_password("pw"), role_id=role.id, is_bootstrap_admin=True)
        db.add(bootstrap)
        db.commit()

        ensure_super_admin_group(db)
        db.expire_all()
        group_count_1 = db.query(Group).count()

        ensure_super_admin_group(db)  # second run -- must be a no-op
        db.expire_all()

        assert db.query(Group).count() == group_count_1
        group = db.query(Group).filter_by(name=SUPER_ADMIN_GROUP_NAME).one()
        assert db.query(User).filter_by(username="root").one().group_id == group.id


class TestMigrateGroupsAndUsersToSingleAssignment:
    """The single-group/single-role permissions auto-migration. THE test
    that proves "nobody's access changes on day one" is
    test_migration_preserves_every_role_s_permissions_exactly below --
    everything else here covers idempotency and the specific tie-break/
    fallback rules from the function's own docstring."""

    def _seed(self, db):
        from vpnadmin.permissions import seed_system_roles

        seed_system_roles(db)
        return {r.slug: r for r in db.query(RoleDef).all()}

    def _create_legacy_group_tables(self, db):
        """Simulates an already-provisioned deployment that still has data
        in the pre-single-assignment group_role_defs/user_groups join
        tables -- these are no longer mapped in models.py (see Group's own
        docstring), so a real production database created by an older
        version of this app is the only place they'd still exist; this
        recreates that physical shape by hand via raw DDL against the same
        connection the test's session uses."""
        db.execute(text("CREATE TABLE group_role_defs (group_id INTEGER, role_id INTEGER)"))
        db.execute(text("CREATE TABLE user_groups (user_id INTEGER, group_id INTEGER)"))
        db.commit()

    def _assign_role_to_group_legacy(self, db, group_id, role_id):
        db.execute(text("INSERT INTO group_role_defs (group_id, role_id) VALUES (:g, :r)"), {"g": group_id, "r": role_id})
        db.commit()

    def _add_user_to_group_legacy(self, db, user_id, group_id):
        db.execute(text("INSERT INTO user_groups (user_id, group_id) VALUES (:u, :g)"), {"u": user_id, "g": group_id})
        db.commit()

    def test_migration_preserves_every_role_s_permissions_exactly(self):
        """THE regression test: for every predefined system role
        (super_admin, admin, editor, viewer, user) plus one custom role,
        create a representative user ALREADY in a single group with that
        one role assigned (the realistic post-Groups-feature state every
        real deployment is in by the time this migration ships), capture
        what has_permission() returns for every OBJECTS x ACTIONS
        combination, run the migration (a true no-op for these
        already-single-assignment users), then assert has_permission()
        afterward is IDENTICAL. This is intentionally the trivial case --
        no union was ever actually needed for a single-group user, single-
        group-single-role migration input equals its own output -- but
        it's still the single most important guarantee: this migration
        must never be the thing that silently changes someone's access."""
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
            group = Group(name=f"{slug}-group", role_id=roles[slug].id)
            db.add(group)
            db.flush()
            u = User(username=f"u-{slug}", password_hash=hash_password("pw"), role_id=roles[slug].id, group_id=group.id)
            if slug == "super_admin":
                u.is_bootstrap_admin = True
            db.add(u)
            users[slug] = u
        db.commit()

        before = {
            slug: {
                (obj, action): has_permission(db, users[slug], obj, action)
                for obj in OBJECTS for action in ACTIONS
            }
            for slug in sample_slugs
        }

        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment
        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        after = {
            slug: {
                (obj, action): has_permission(db, users[slug], obj, action)
                for obj in OBJECTS for action in ACTIONS
            }
            for slug in sample_slugs
        }

        for slug in sample_slugs:
            assert after[slug] == before[slug], f"permission set changed for role '{slug}' across the migration"

    def test_collapses_a_group_with_multiple_roles_to_the_lowest_role_id(self):
        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        self._create_legacy_group_tables(db)
        group = Group(name="Multi-Role Group")
        db.add(group)
        db.commit()
        self._assign_role_to_group_legacy(db, group.id, roles["admin"].id)
        self._assign_role_to_group_legacy(db, group.id, roles["viewer"].id)

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        refreshed = db.query(Group).filter_by(name="Multi-Role Group").one()
        assert refreshed.role_id == min(roles["admin"].id, roles["viewer"].id)

    def test_collapses_a_user_in_multiple_groups_to_the_widest_access_one(self):
        """Explicit precedence order: admin > custom > editor > user >
        viewer. A user in an "editor" group and an "admin" group must end
        up in the admin group."""
        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        self._create_legacy_group_tables(db)
        editor_group = Group(name="Editor Group", role_id=roles["editor"].id)
        admin_group = Group(name="Admin Group", role_id=roles["admin"].id)
        db.add_all([editor_group, admin_group])
        db.flush()
        user = User(username="multi-group-user", password_hash=hash_password("pw"))
        db.add(user)
        db.commit()
        self._add_user_to_group_legacy(db, user.id, editor_group.id)
        self._add_user_to_group_legacy(db, user.id, admin_group.id)

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        assert db.query(User).filter_by(username="multi-group-user").one().group_id == admin_group.id

    def test_custom_role_outranks_editor_user_viewer_but_not_admin(self):
        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        self._create_legacy_group_tables(db)
        custom = RoleDef(slug="custom-mid", name="Custom Mid", is_system=False)
        db.add(custom)
        db.commit()
        viewer_group = Group(name="Viewer Group", role_id=roles["viewer"].id)
        custom_group = Group(name="Custom Group", role_id=custom.id)
        db.add_all([viewer_group, custom_group])
        db.flush()
        user = User(username="custom-mid-user", password_hash=hash_password("pw"))
        db.add(user)
        db.commit()
        self._add_user_to_group_legacy(db, user.id, viewer_group.id)
        self._add_user_to_group_legacy(db, user.id, custom_group.id)

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        # Custom beats viewer...
        assert db.query(User).filter_by(username="custom-mid-user").one().group_id == custom_group.id

        admin_group = Group(name="Admin Group 2", role_id=roles["admin"].id)
        db.add(admin_group)
        db.flush()
        user2 = User(username="custom-vs-admin-user", password_hash=hash_password("pw"))
        db.add(user2)
        db.commit()
        self._add_user_to_group_legacy(db, user2.id, custom_group.id)
        self._add_user_to_group_legacy(db, user2.id, admin_group.id)

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        # ...but admin beats custom.
        assert db.query(User).filter_by(username="custom-vs-admin-user").one().group_id == admin_group.id

    def test_multi_group_reduction_is_audit_logged(self):
        from vpnadmin.models import AuditLog
        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        self._create_legacy_group_tables(db)
        editor_group = Group(name="Editor Group", role_id=roles["editor"].id)
        admin_group = Group(name="Admin Group", role_id=roles["admin"].id)
        db.add_all([editor_group, admin_group])
        db.flush()
        user = User(username="logged-user", password_hash=hash_password("pw"))
        db.add(user)
        db.commit()
        self._add_user_to_group_legacy(db, user.id, editor_group.id)
        self._add_user_to_group_legacy(db, user.id, admin_group.id)

        migrate_groups_and_users_to_single_assignment(db)

        entry = db.query(AuditLog).filter_by(action="group_membership_reduced").one()
        assert entry.username == "logged-user"
        assert "Admin Group" in entry.detail
        assert "Editor Group" in entry.detail

    def test_excludes_bootstrap_admin_from_the_multi_group_reduction(self):
        """The bootstrap admin is handled exclusively by
        ensure_super_admin_group -- even if legacy data somehow shows it
        in multiple groups, this migration must not touch its group_id."""
        from vpnadmin.permissions import ensure_super_admin_group, migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        self._create_legacy_group_tables(db)
        root = User(username="root", password_hash=hash_password("pw"), role_id=roles["super_admin"].id, is_bootstrap_admin=True)
        db.add(root)
        db.commit()
        ensure_super_admin_group(db)
        db.expire_all()
        original_group_id = db.query(User).filter_by(username="root").one().group_id

        editor_group = Group(name="Editor Group", role_id=roles["editor"].id)
        db.add(editor_group)
        db.flush()
        self._add_user_to_group_legacy(db, root.id, editor_group.id)

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        assert db.query(User).filter_by(username="root").one().group_id == original_group_id

    def test_zero_group_user_falls_back_to_a_user_role_group(self):
        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        lonely = User(username="lonely", password_hash=hash_password("pw"))
        db.add(lonely)
        db.commit()

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        refreshed = db.query(User).filter_by(username="lonely").one()
        assert refreshed.group_id is not None
        assert refreshed.group.role_id == roles["user"].id
        assert refreshed.group.name == "User"

    def test_zero_group_fallback_name_collision_appends_auto(self):
        """Mirrors the prior migrate_users_to_role_groups()'s own
        collision-avoidance convention exactly: a "User" group that
        already exists for an unrelated purpose (no "user" role assigned)
        is never repurposed -- the fallback group gets " (auto)" appended
        instead."""
        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        unrelated = Group(name="User", role_id=roles["viewer"].id)  # not the "user" role -- unrelated purpose
        db.add(unrelated)
        db.commit()
        lonely = User(username="lonely2", password_hash=hash_password("pw"))
        db.add(lonely)
        db.commit()

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        refreshed = db.query(User).filter_by(username="lonely2").one()
        assert refreshed.group.name == "User (auto)"
        assert refreshed.group.role_id == roles["user"].id

    def test_excludes_bootstrap_admin_from_the_zero_group_fallback(self):
        from vpnadmin.permissions import ensure_super_admin_group, migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        root = User(username="root2", password_hash=hash_password("pw"), role_id=roles["super_admin"].id, is_bootstrap_admin=True)
        db.add(root)
        db.commit()
        ensure_super_admin_group(db)
        db.expire_all()
        super_admin_group_id = db.query(User).filter_by(username="root2").one().group_id

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()

        assert db.query(User).filter_by(username="root2").one().group_id == super_admin_group_id
        # And access is still fully intact regardless (the hardcoded
        # exemption, not group membership, is what grants it).
        assert has_permission(db, root, "settings", "manage") is True

    def test_idempotent_running_twice_produces_identical_end_state(self):
        from vpnadmin.permissions import migrate_groups_and_users_to_single_assignment

        db = _fresh_session()
        roles = self._seed(db)
        self._create_legacy_group_tables(db)
        editor_group = Group(name="Editor Group", role_id=roles["editor"].id)
        admin_group = Group(name="Admin Group", role_id=roles["admin"].id)
        db.add_all([editor_group, admin_group])
        db.flush()
        user = User(username="idempotent-user", password_hash=hash_password("pw"))
        db.add(user)
        db.commit()
        self._add_user_to_group_legacy(db, user.id, editor_group.id)
        self._add_user_to_group_legacy(db, user.id, admin_group.id)
        lonely = User(username="idempotent-lonely", password_hash=hash_password("pw"))
        db.add(lonely)
        db.commit()

        migrate_groups_and_users_to_single_assignment(db)
        db.expire_all()
        group_count_1 = db.query(Group).count()
        user_group_1 = db.query(User).filter_by(username="idempotent-user").one().group_id
        lonely_group_1 = db.query(User).filter_by(username="idempotent-lonely").one().group_id

        migrate_groups_and_users_to_single_assignment(db)  # second run -- must be a no-op
        db.expire_all()

        assert db.query(Group).count() == group_count_1
        assert db.query(User).filter_by(username="idempotent-user").one().group_id == user_group_1
        assert db.query(User).filter_by(username="idempotent-lonely").one().group_id == lonely_group_1
