"""Tests for permissions.py's system-role seeding, including the
rename_legacy_vpn_self_service_role() migration fixup (see its own
docstring / db.py's _seed_rbac for why it exists and must run first)."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from vpnadmin.db import Base
from vpnadmin.models import ObjectPermission, RoleDef


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
