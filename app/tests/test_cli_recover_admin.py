"""Super Admin Recovery Mechanism (vpnadmin/cli_recover_admin.py) -- the
break-glass path back onto the bootstrap admin account. Exercises the
individual action functions directly against db_session (the same pattern
every other migration-function test in this repo uses) rather than main()/
SessionLocal(), since main() deliberately points at the real configured
DATABASE_URL (a *different* in-memory SQLite DB than db_session's own
engine in this test process) -- see recover-admin.sh for the real-world
invocation path (docker exec + this module's CLI), which is out of scope
for a unit test.
"""
from vpnadmin.auth import hash_password, verify_password
from vpnadmin.cli_recover_admin import clear_mfa, regenerate_recovery_codes, reset_password, unlock
from vpnadmin.models import AuditLog, MfaRecoveryCode, User


def _make_bootstrap_admin(db_session, **overrides) -> User:
    admin = User(
        username="admin", password_hash=hash_password("originalpass123"),
        is_bootstrap_admin=True, **overrides,
    )
    db_session.add(admin)
    db_session.commit()
    return admin


class TestResetPassword:
    def test_generates_a_new_working_password_and_forces_a_change(self, db_session, capsys):
        admin = _make_bootstrap_admin(db_session, failed_login_attempts=3)
        reset_password(db_session, admin)

        assert not verify_password("originalpass123", admin.password_hash)
        assert admin.must_reset_password is True
        assert admin.failed_login_attempts == 0
        assert admin.locked_until is None

        printed = capsys.readouterr().out
        assert "New temporary password" in printed
        # The printed password actually works.
        new_password = printed.split(": ", 1)[1].splitlines()[0]
        assert verify_password(new_password, admin.password_hash)

    def test_audit_logged(self, db_session):
        admin = _make_bootstrap_admin(db_session)
        reset_password(db_session, admin)
        log = db_session.query(AuditLog).filter_by(action="bootstrap_admin_recovered").one()
        assert log.target == "admin"
        assert "cli:recover-admin.sh" in log.username
        assert "password reset" in log.detail


class TestClearMfa:
    def test_disables_mfa_and_forces_reenrollment(self, db_session):
        admin = _make_bootstrap_admin(db_session, mfa_enabled=True, mfa_secret_encrypted="ciphertext")
        db_session.add(MfaRecoveryCode(user_id=admin.id, code_hash="somehash"))
        db_session.commit()

        clear_mfa(db_session, admin)

        assert admin.mfa_enabled is False
        assert admin.mfa_secret_encrypted is None
        assert admin.mfa_setup_required is True
        assert db_session.query(MfaRecoveryCode).filter_by(user_id=admin.id).count() == 0


class TestUnlock:
    def test_clears_both_password_and_mfa_lockout_counters(self, db_session):
        admin = _make_bootstrap_admin(db_session, failed_login_attempts=5, mfa_failed_attempts=5)
        unlock(db_session, admin)
        assert admin.failed_login_attempts == 0
        assert admin.locked_until is None
        assert admin.mfa_failed_attempts == 0
        assert admin.mfa_locked_until is None


class TestRegenerateRecoveryCodes:
    def test_skipped_when_mfa_not_enabled(self, db_session, capsys):
        admin = _make_bootstrap_admin(db_session, mfa_enabled=False)
        regenerate_recovery_codes(db_session, admin)
        assert db_session.query(MfaRecoveryCode).filter_by(user_id=admin.id).count() == 0
        assert "doesn't currently have MFA enabled" in capsys.readouterr().out

    def test_generates_fresh_codes_when_mfa_enabled(self, db_session, capsys):
        admin = _make_bootstrap_admin(db_session, mfa_enabled=True, mfa_secret_encrypted="ciphertext")
        db_session.add(MfaRecoveryCode(user_id=admin.id, code_hash="stalehash"))
        db_session.commit()

        regenerate_recovery_codes(db_session, admin)

        codes = db_session.query(MfaRecoveryCode).filter_by(user_id=admin.id).all()
        assert len(codes) > 0
        assert all(c.code_hash != "stalehash" for c in codes)
        assert "New recovery codes" in capsys.readouterr().out


class TestDeletedAccountRestore:
    def test_reset_password_undeletes_a_soft_deleted_bootstrap_account(self, db_session):
        from datetime import datetime, timezone

        from vpnadmin.cli_recover_admin import _get_bootstrap_admin

        _make_bootstrap_admin(db_session, deleted=True, deleted_at=datetime.now(timezone.utc))
        admin = _get_bootstrap_admin(db_session)
        assert admin.deleted is False
        assert admin.deleted_at is None
