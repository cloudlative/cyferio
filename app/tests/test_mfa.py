"""Multi-Factor Authentication (TOTP) -- see the feature's plan for the
full design. Covers: policy precedence resolution, enrollment, login-flow
branching, OTP lockout, recovery codes, trusted devices, and admin
actions."""
import json
from datetime import datetime, timezone

import pyotp

from vpnadmin import app_settings
from vpnadmin import mfa as mfa_module
from vpnadmin.auth import hash_password
from vpnadmin.models import AuditLog, MfaRecoveryCode, RoleDef, User

from .conftest import login


def _make_user(db_session, username, *, role_slug="user", password="somepass123"):
    role = db_session.query(RoleDef).filter_by(slug=role_slug).first()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id, email=f"{username}@example.com")
    db_session.add(user)
    db_session.commit()
    return user


def _enroll(db_session, user, secret="JBSWY3DPEHPK3PXP"):
    user.mfa_secret_encrypted = mfa_module.encrypt_secret(secret)
    user.mfa_enabled = True
    user.mfa_enrolled_at = datetime.now(timezone.utc)
    db_session.commit()
    return secret


class TestEffectivePolicyPrecedence:
    def test_defaults_to_optional(self, db_session):
        user = _make_user(db_session, "alice")
        assert mfa_module.effective_policy(user, db_session) == "optional"

    def test_global_required(self, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_mode", "required")
        user = _make_user(db_session, "alice")
        assert mfa_module.effective_policy(user, db_session) == "required"

    def test_disabled_is_a_kill_switch_even_for_an_enrolled_user(self, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_mode", "disabled")
        user = _make_user(db_session, "alice")
        _enroll(db_session, user)
        user.mfa_policy_override = "required"  # even an explicit override is overridden by the kill switch
        assert mfa_module.effective_policy(user, db_session) == "exempt"

    def test_role_requirement_overrides_global_mode(self, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_mode", "optional")
        monkeypatch.setattr(app_settings.runtime, "mfa_role_requirements", json.dumps({"user": "required"}))
        user = _make_user(db_session, "alice", role_slug="user")
        assert mfa_module.effective_policy(user, db_session) == "required"

    def test_per_user_override_wins_over_role_and_global(self, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_mode", "required")
        monkeypatch.setattr(app_settings.runtime, "mfa_role_requirements", json.dumps({"user": "required"}))
        user = _make_user(db_session, "alice", role_slug="user")
        user.mfa_policy_override = "exempt"
        assert mfa_module.effective_policy(user, db_session) == "exempt"


class TestEnrollment:
    def test_full_self_service_enrollment_flow(self, app_client, db_session, monkeypatch):
        _make_user(db_session, "alice")
        login(app_client, "alice", "somepass123")

        fixed_secret = "JBSWY3DPEHPK3PXP"
        monkeypatch.setattr(mfa_module, "generate_secret", lambda: fixed_secret)

        r = app_client.get("/mfa/setup")
        assert r.status_code == 200

        code = pyotp.TOTP(fixed_secret).now()
        r = app_client.post("/mfa/setup", data={"code": code})
        assert r.status_code == 200
        assert "enabled" in r.text.lower()

        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_enabled is True
        assert alice.mfa_enrolled_at is not None
        assert mfa_module.decrypt_secret(alice.mfa_secret_encrypted) == fixed_secret
        assert mfa_module.remaining_recovery_codes_count(alice, db_session) == 10

        actions = {e.action for e in db_session.query(AuditLog).filter_by(username="alice").all()}
        assert "mfa_enrolled" in actions
        assert "mfa_enabled" in actions

    def test_wrong_code_rejects_enrollment(self, app_client, db_session, monkeypatch):
        _make_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        monkeypatch.setattr(mfa_module, "generate_secret", lambda: "JBSWY3DPEHPK3PXP")
        app_client.get("/mfa/setup")
        r = app_client.post("/mfa/setup", data={"code": "000000"})
        assert r.status_code == 401
        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_enabled is False


class TestLoginFlowBranching:
    def test_optional_and_not_enrolled_logs_in_normally(self, app_client, db_session):
        _make_user(db_session, "alice")
        r = app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"

    def test_optional_and_enrolled_is_challenged(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        _enroll(db_session, alice)
        r = app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/mfa/verify"

    def test_required_and_not_enrolled_redirects_to_mandatory_setup(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_mode", "required")
        _make_user(db_session, "alice")
        r = app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/mfa/setup"

    def test_exempt_user_never_challenged_even_if_enrolled(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_mode", "required")
        alice = _make_user(db_session, "alice")
        _enroll(db_session, alice)
        alice.mfa_policy_override = "exempt"
        db_session.commit()
        r = app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"

    def test_verify_with_correct_totp_completes_login(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        secret = _enroll(db_session, alice)
        app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        code = pyotp.TOTP(secret).now()
        r = app_client.post("/mfa/verify", data={"code": code}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"
        # A subsequent authenticated request now succeeds.
        r = app_client.get("/api/me/mfa")
        assert r.status_code == 200
        assert r.json()["mfa_enabled"] is True


class TestOtpLockout:
    def test_locks_out_after_threshold_wrong_codes(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "account_lockout_threshold", 3)
        monkeypatch.setattr(app_settings.runtime, "account_lockout_minutes", 15)
        alice = _make_user(db_session, "alice")
        _enroll(db_session, alice)
        app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)

        for _ in range(3):
            r = app_client.post("/mfa/verify", data={"code": "000000"})
            assert r.status_code == 401

        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_locked_until is not None

        # Even the correct code is now rejected while locked.
        secret = mfa_module.decrypt_secret(alice.mfa_secret_encrypted)
        code = pyotp.TOTP(secret).now()
        r = app_client.post("/mfa/verify", data={"code": code})
        assert r.status_code == 423


class TestRecoveryCodes:
    def test_recovery_code_completes_login_and_is_single_use(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        _enroll(db_session, alice)
        codes = mfa_module.replace_recovery_codes(alice, db_session)
        app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)

        r = app_client.post("/mfa/verify", data={"recovery_code": codes[0]}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"

        entry = db_session.query(AuditLog).filter_by(username="alice", action="recovery_code_used").one()
        assert entry is not None

        # Using the SAME code again (a fresh login attempt) fails.
        app_client.post("/logout")
        app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        r = app_client.post("/mfa/verify", data={"recovery_code": codes[0]})
        assert r.status_code == 401

    def test_regenerating_invalidates_old_codes(self, db_session):
        alice = _make_user(db_session, "alice")
        _enroll(db_session, alice)
        old_codes = mfa_module.replace_recovery_codes(alice, db_session)
        new_codes = mfa_module.replace_recovery_codes(alice, db_session)
        assert old_codes != new_codes
        assert mfa_module.consume_recovery_code(alice, old_codes[0], db_session) is False
        assert mfa_module.consume_recovery_code(alice, new_codes[0], db_session) is True
        assert db_session.query(MfaRecoveryCode).filter_by(user_id=alice.id, used_at=None).count() == len(new_codes) - 1


class TestTrustedDevice:
    def test_remembered_device_skips_the_challenge(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_remember_device_days", 30)
        alice = _make_user(db_session, "alice")
        secret = _enroll(db_session, alice)

        app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        code = pyotp.TOTP(secret).now()
        app_client.post("/mfa/verify", data={"code": code, "remember_device": "true"})
        assert app_client.cookies.get(mfa_module.TRUSTED_DEVICE_COOKIE_NAME) is not None

        app_client.post("/logout")
        r = app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"  # skipped straight past /mfa/verify

    def test_trusted_device_never_bypasses_mandatory_enrollment(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "mfa_remember_device_days", 30)
        alice = _make_user(db_session, "alice")
        # A trusted-device row exists (e.g. from before the policy tightened
        # to "required"), but alice has never actually enrolled.
        token = mfa_module.issue_trusted_device_token(alice, db_session, days=30, user_agent="pytest", ip="127.0.0.1")
        app_client.cookies.set(mfa_module.TRUSTED_DEVICE_COOKIE_NAME, token)
        monkeypatch.setattr(app_settings.runtime, "mfa_mode", "required")

        r = app_client.post("/login", data={"username": "alice", "password": "somepass123"}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/mfa/setup"


def _login_and_pass_mfa(app_client, db_session, user, secret):
    app_client.post("/login", data={"username": user.username, "password": "somepass123"}, follow_redirects=False)
    code = pyotp.TOTP(secret).now()
    app_client.post("/mfa/verify", data={"code": code}, follow_redirects=False)


class TestSelfServiceDisable:
    def test_disable_requires_correct_password(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        secret = _enroll(db_session, alice)
        _login_and_pass_mfa(app_client, db_session, alice, secret)
        r = app_client.post("/api/me/mfa/disable", json={"password": "wrongpassword"})
        assert r.status_code == 403
        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_enabled is True

    def test_disable_with_correct_password_succeeds(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        secret = _enroll(db_session, alice)
        _login_and_pass_mfa(app_client, db_session, alice, secret)
        r = app_client.post("/api/me/mfa/disable", json={"password": "somepass123"})
        assert r.status_code == 200
        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_enabled is False
        assert db_session.query(MfaRecoveryCode).filter_by(user_id=alice.id).count() == 0
        assert db_session.query(AuditLog).filter_by(username="alice", action="mfa_disabled").count() == 1


class TestAdminActions:
    def test_reset_clears_enrollment_and_forces_re_enrollment(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        _enroll(db_session, alice)
        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{alice.id}/mfa/reset")
        assert r.status_code == 200
        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_enabled is False
        assert alice.mfa_setup_required is True
        assert db_session.query(AuditLog).filter_by(username="admin", action="mfa_reset_by_admin").count() == 1

    def test_disable_by_admin_does_not_force_re_enrollment(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        _enroll(db_session, alice)
        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{alice.id}/mfa/disable")
        assert r.status_code == 200
        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_enabled is False
        assert alice.mfa_setup_required is False
        assert db_session.query(AuditLog).filter_by(username="admin", action="mfa_disabled_by_admin").count() == 1

    def test_force_enroll_does_not_touch_existing_enrollment(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        secret = _enroll(db_session, alice)
        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{alice.id}/mfa/force-enroll")
        assert r.status_code == 200
        alice = db_session.query(User).filter_by(username="alice").one()
        assert alice.mfa_enabled is True  # untouched
        assert mfa_module.decrypt_secret(alice.mfa_secret_encrypted) == secret  # untouched
        assert alice.mfa_setup_required is True
        assert db_session.query(AuditLog).filter_by(username="admin", action="mfa_force_enroll").count() == 1

    def test_viewer_cannot_call_admin_mfa_actions(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post(f"/api/users/{alice.id}/mfa/reset")
        assert r.status_code == 403

    def test_setting_override_to_exempt_logs_mfa_bypass_granted(self, app_client, db_session):
        alice = _make_user(db_session, "alice")
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{alice.id}", json={"mfa_policy_override": "exempt"})
        assert r.status_code == 200
        assert db_session.query(AuditLog).filter_by(username="admin", action="mfa_bypass_granted").count() == 1


class TestSettingsApi:
    def test_admin_can_configure_global_mode_and_role_requirements(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={
            "mfa_mode": "required",
            "mfa_role_requirements": {"user": "optional"},
            "mfa_remember_device_days": 14,
        })
        assert r.status_code == 200
        body = r.json()
        assert body["mfa_mode"] == "required"
        assert body["mfa_role_requirements"] == {"user": "optional"}
        assert body["mfa_remember_device_days"] == 14
        assert app_settings.runtime.mfa_mode == "required"

    def test_mfa_mode_change_is_audit_logged_with_old_and_new_value(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/settings", json={"mfa_mode": "required"})
        entry = db_session.query(AuditLog).filter_by(action="mfa_mode_changed").one()
        assert entry.detail == "optional -> required"

    def test_unknown_role_slug_rejected(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"mfa_role_requirements": {"not-a-real-role": "required"}})
        assert r.status_code == 400
