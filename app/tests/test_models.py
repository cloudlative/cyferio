from vpnadmin.auth import hash_password
from vpnadmin.models import AuditLog, Role, User


class TestUserModel:
    def test_create_and_query_user(self, db_session):
        u = User(username="Alice", password_hash=hash_password("pw"), role=Role.admin)
        db_session.add(u)
        db_session.commit()

        found = db_session.query(User).filter(User.username == "alice").first()
        assert found is not None
        assert found.role == Role.admin

    def test_username_is_normalized_lowercase(self, db_session):
        u = User(username="  BobSmith  ", password_hash=hash_password("pw"))
        db_session.add(u)
        db_session.commit()
        assert u.username == "bobsmith"

    def test_default_role_is_viewer(self, db_session):
        u = User(username="charlie", password_hash=hash_password("pw"))
        db_session.add(u)
        db_session.commit()
        assert u.role == Role.viewer

    def test_default_active_true(self, db_session):
        u = User(username="dana", password_hash=hash_password("pw"))
        db_session.add(u)
        db_session.commit()
        assert u.is_active is True


class TestAuditLogModel:
    def test_create_audit_entry(self, db_session):
        entry = AuditLog(username="admin", action="add_client", target="alice", detail="alice added.", success=True)
        db_session.add(entry)
        db_session.commit()

        found = db_session.query(AuditLog).filter(AuditLog.target == "alice").first()
        assert found is not None
        assert found.success is True
        assert found.timestamp is not None
