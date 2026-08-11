"""Tests for permissions.py's system-role seeding, including the
rename_legacy_vpn_self_service_role() migration fixup (see its own
docstring / db.py's _seed_rbac for why it exists and must run first)."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from vpnadmin.db import Base
from vpnadmin.models import RoleDef


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
