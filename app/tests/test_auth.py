import re

from vpnadmin.auth import hash_password, verify_password
from vpnadmin.models import Role, Team, User

from .conftest import login


class TestPasswordHashing:
    def test_correct_password_verifies(self):
        h = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", h) is True

    def test_wrong_password_fails(self):
        h = hash_password("correct horse battery staple")
        assert verify_password("wrong password", h) is False

    def test_long_password_does_not_crash(self):
        # bcrypt silently ignores bytes beyond 72 -- must not raise.
        h = hash_password("x" * 200)
        assert verify_password("x" * 200, h) is True

    def test_malformed_hash_returns_false_not_crash(self):
        assert verify_password("anything", "not-a-real-bcrypt-hash") is False


class TestLoginFlow:
    def test_login_page_loads(self, app_client):
        r = app_client.get("/login")
        assert r.status_code == 200

    def test_correct_login_redirects_to_users(self, app_client):
        # Users is the default landing page for an account that can manage
        # users (see pages.py's root() route) -- httpx TestClient follows
        # redirects by default, so this exercises the full "/" -> "/users"
        # chain, not just the login endpoint's own immediate redirect.
        r = login(app_client, "admin", "adminpass123")
        assert r.status_code == 200
        assert r.url.path == "/users"

    def test_wrong_password_rejected(self, app_client):
        r = login(app_client, "admin", "wrongpassword")
        assert r.status_code == 401

    def test_unknown_username_rejected(self, app_client):
        r = login(app_client, "nosuchuser", "whatever123")
        assert r.status_code == 401

    def test_inactive_user_cannot_login(self, app_client, db_session):
        db_session.query(User).filter(User.username == "viewer").update({"is_active": False})
        db_session.commit()
        r = login(app_client, "viewer", "viewerpass123")
        assert r.status_code == 401

    def test_dashboard_requires_login(self, app_client):
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_root_requires_login(self, app_client):
        r = app_client.get("/dashboard", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_dashboard_accessible_after_login(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/dashboard")
        assert r.status_code == 200

    def test_root_lands_on_users_for_admin(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/users"

    def test_root_lands_on_dashboard_when_no_users_permission(self, app_client):
        # "viewer" can view the dashboard but doesn't have users:manage --
        # should fall through to /dashboard, not /users.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/dashboard"

    def test_logout_clears_session(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.post("/logout")
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303


class TestFaqPage:
    def test_faq_requires_login(self, app_client):
        r = app_client.get("/faq", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_faq_accessible_to_admin(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/faq")
        assert r.status_code == 200
        assert "FAQ" in r.text

    def test_faq_accessible_to_viewer(self, app_client):
        # No permission gate beyond being logged in -- every role should
        # reach this, not just admins (see pages.py's faq_page docstring).
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/faq")
        assert r.status_code == 200


class TestForgotPasswordFlow:
    @staticmethod
    def _mock_smtp(monkeypatch, sent: dict):
        # Replaces the whole send function, so it never touches
        # mailer._resolve_default_provider/the EmailProvider table at
        # all -- no EmailProvider row needs to exist in these tests.
        import vpnadmin.routes.auth as auth_mod

        def fake_send(*, db, to_address, username, reset_url, ttl_minutes):
            sent["to"] = to_address
            sent["username"] = username
            sent["reset_url"] = reset_url

        monkeypatch.setattr(auth_mod.mailer, "send_password_reset_email", fake_send)

    def test_page_loads(self, app_client):
        r = app_client.get("/forgot-password")
        assert r.status_code == 200

    def test_unknown_email_gets_generic_message_no_mail_sent(self, app_client, monkeypatch):
        sent = {}
        self._mock_smtp(monkeypatch, sent)
        r = app_client.post("/forgot-password", data={"email": "nosuchaccount@example.com"})
        assert r.status_code == 200
        assert "if an account" in r.text.lower()
        assert sent == {}  # no account matched -- never even tried to send

    def test_malformed_email_rejected(self, app_client):
        r = app_client.post("/forgot-password", data={"email": "not-an-email"})
        assert r.status_code == 400

    def test_known_email_full_round_trip_resets_password(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()

        sent = {}
        self._mock_smtp(monkeypatch, sent)
        r = app_client.post("/forgot-password", data={"email": "ADMIN@EXAMPLE.COM"})  # case-insensitive match
        assert r.status_code == 200
        assert sent["to"] == "admin@example.com"
        assert sent["username"] == "admin"

        token = re.search(r"[?&]token=([^&\s\"']+)", sent["reset_url"]).group(1)

        # GET with the real token shows the set-new-password form.
        r = app_client.get(f"/reset-password?token={token}")
        assert r.status_code == 200
        assert "new_password" in r.text

        # Old password still works until the reset is actually submitted.
        r = login(app_client, "admin", "adminpass123")
        assert r.status_code == 200
        app_client.post("/logout")

        r = app_client.post("/reset-password", data={"token": token, "new_password": "BrandNewPass1!", "confirm_password": "BrandNewPass1!"})
        assert r.status_code == 200

        # New password works, old one no longer does.
        r = login(app_client, "admin", "BrandNewPass1!")
        assert r.status_code == 200
        assert r.url.path == "/users"
        app_client.post("/logout")
        r = login(app_client, "admin", "adminpass123")
        assert r.status_code == 401

        # Single-use: the same token can't be replayed.
        r = app_client.post("/reset-password", data={"token": token, "new_password": "AnotherOne1!", "confirm_password": "AnotherOne1!"})
        assert r.status_code == 400
        assert "invalid or has expired" in r.text.lower()

    def test_mismatched_passwords_rejected(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        sent = {}
        self._mock_smtp(monkeypatch, sent)
        app_client.post("/forgot-password", data={"email": "admin@example.com"})
        token = re.search(r"[?&]token=([^&\s\"']+)", sent["reset_url"]).group(1)

        r = app_client.post("/reset-password", data={"token": token, "new_password": "BrandNewPass1!", "confirm_password": "Different1!"})
        assert r.status_code == 400
        assert "don't match" in r.text.lower()

    def test_weak_new_password_rejected(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()
        sent = {}
        self._mock_smtp(monkeypatch, sent)
        app_client.post("/forgot-password", data={"email": "admin@example.com"})
        token = re.search(r"[?&]token=([^&\s\"']+)", sent["reset_url"]).group(1)

        r = app_client.post("/reset-password", data={"token": token, "new_password": "weak", "confirm_password": "weak"})
        assert r.status_code == 400

    def test_bogus_token_shows_invalid_state(self, app_client):
        r = app_client.get("/reset-password?token=not-a-real-token")
        assert r.status_code == 200
        assert "invalid or has expired" in r.text.lower()

        r = app_client.post("/reset-password", data={"token": "not-a-real-token", "new_password": "BrandNewPass1!", "confirm_password": "BrandNewPass1!"})
        assert r.status_code == 400


class TestLoginCaptcha:
    """CAPTCHA gating on /login -- see captcha.py for the provider-agnostic
    verify()/is_configured() unit tests themselves (tests/test_captcha.py);
    these cover the login route's own wiring around them."""

    def test_no_captcha_widget_when_unconfigured(self, app_client):
        r = app_client.get("/login")
        assert "cf-turnstile" not in r.text
        assert "g-recaptcha" not in r.text

    def test_login_rejected_without_captcha_when_configured(self, app_client, monkeypatch):
        import vpnadmin.routes.auth as auth_mod
        monkeypatch.setattr(auth_mod.captcha, "is_configured", lambda: True)
        monkeypatch.setattr(auth_mod.captcha, "widget_context", lambda: {"site_key": "x", "widget_js": "https://example.com/x.js", "widget_class": "cf-turnstile"})
        monkeypatch.setattr(auth_mod.captcha, "verify", lambda token, remote_ip=None: False)
        r = login(app_client, "admin", "adminpass123")
        assert r.status_code == 400
        assert "captcha" in r.text.lower()

    def test_login_succeeds_with_passing_captcha(self, app_client, monkeypatch):
        import vpnadmin.routes.auth as auth_mod
        monkeypatch.setattr(auth_mod.captcha, "is_configured", lambda: True)
        monkeypatch.setattr(auth_mod.captcha, "widget_context", lambda: {"site_key": "x", "widget_js": "https://example.com/x.js", "widget_class": "cf-turnstile"})
        monkeypatch.setattr(auth_mod.captcha, "verify", lambda token, remote_ip=None: True)
        r = login(app_client, "admin", "adminpass123")
        assert r.status_code == 200
        assert r.url.path == "/users"


class TestRoleGating:
    def test_viewer_can_read_clients_api(self, app_client, monkeypatch):
        import vpnadmin.routes.clients as clients_mod
        monkeypatch.setattr(clients_mod.cli, "list_clients", lambda: [])
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/clients")
        assert r.status_code == 200

    def test_viewer_cannot_add_client(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/clients", json={"name": "eve", "mac": "aa:bb:cc:dd:ee:ff"})
        assert r.status_code == 403

    def test_viewer_cannot_revoke_client(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.delete("/api/clients/someone")
        assert r.status_code == 403

    def test_viewer_cannot_manage_users(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/users")
        assert r.status_code == 403

    def test_viewer_users_page_redirects_home(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/users", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"

    def test_admin_can_manage_users(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/users")
        assert r.status_code == 200


class TestSelfLockoutGuardrails:
    def test_admin_cannot_demote_self(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        r = app_client.patch(f"/api/users/{admin_id}", json={"role": "viewer"})
        assert r.status_code == 400

    def test_admin_cannot_deactivate_self(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        r = app_client.patch(f"/api/users/{admin_id}", json={"is_active": False})
        assert r.status_code == 400

    def test_admin_cannot_delete_self(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        r = app_client.delete(f"/api/users/{admin_id}")
        assert r.status_code == 400

    def test_bootstrap_admin_cannot_be_demoted_even_by_another_admin(self, app_client, db_session):
        # ONLY the bootstrap admin (the very first admin account a
        # deployment ever creates -- see User.is_bootstrap_admin) can never
        # be demoted, by anyone, including another admin.
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.is_bootstrap_admin = True
        second_admin = User(username="admin2", password_hash=hash_password("admin2pass123"), role=Role.admin)
        db_session.add(second_admin)
        db_session.commit()

        login(app_client, "admin2", "admin2pass123")
        r = app_client.patch(f"/api/users/{admin.id}", json={"role": "viewer"})
        assert r.status_code == 400
        assert "cannot be demoted" in r.json()["detail"].lower()

        db_session.expire_all()
        assert db_session.query(User).filter(User.username == "admin").one().role == Role.admin

    def test_bootstrap_admin_cannot_be_deactivated_or_deleted_by_another_admin(self, app_client, db_session):
        # Task #65: the bootstrap-admin protection also covers deactivate
        # and both delete paths (soft + permanent), not just role changes.
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.is_bootstrap_admin = True
        second_admin = User(username="admin2", password_hash=hash_password("admin2pass123"), role=Role.admin)
        db_session.add(second_admin)
        db_session.commit()

        login(app_client, "admin2", "admin2pass123")

        r = app_client.patch(f"/api/users/{admin.id}", json={"is_active": False})
        assert r.status_code == 400

        r = app_client.delete(f"/api/users/{admin.id}")
        assert r.status_code == 400

        # Permanent-delete requires the target to already be soft-deleted,
        # which the check above proves the API itself will never do to the
        # bootstrap admin -- simulate that (otherwise-unreachable) state
        # directly to prove the belt-and-suspenders guard in the permanent-
        # delete endpoint itself also rejects it, not just relying on
        # soft-delete never happening in the first place.
        admin.deleted = True
        db_session.commit()
        r = app_client.delete(f"/api/users/{admin.id}/permanent")
        assert r.status_code == 400

    def test_non_bootstrap_admin_can_be_demoted_by_another_admin(self, app_client, db_session):
        # A NON-bootstrap admin account remains demotable by another admin,
        # same as before the bootstrap-only rule existed -- this is the
        # corrected scope: it's not "no admin can ever be demoted", only
        # the specific bootstrap account.
        second_admin = User(username="admin2", password_hash=hash_password("admin2pass123"), role=Role.admin)
        db_session.add(second_admin)
        db_session.commit()
        assert second_admin.is_bootstrap_admin is False

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{second_admin.id}", json={"role": "viewer"})
        assert r.status_code == 200
        assert r.json()["role"] == "viewer"

    def test_admin_can_still_be_deactivated_by_another_admin(self, app_client, db_session):
        # A non-bootstrap admin can still be deactivated by another admin,
        # when another active admin remains.
        second_admin = User(username="admin2", password_hash=hash_password("admin2pass123"), role=Role.admin)
        db_session.add(second_admin)
        db_session.commit()

        login(app_client, "admin2", "admin2pass123")
        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        r = app_client.patch(f"/api/users/{admin_id}", json={"is_active": False})
        assert r.status_code == 200


class TestSoftDeleteAndRestore:
    def test_delete_soft_deletes_not_hard_deletes(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id

        r = app_client.delete(f"/api/users/{viewer_id}")
        assert r.status_code == 200

        # Row still exists in the DB, just marked deleted -- not gone.
        db_session.expire_all()
        target = db_session.get(User, viewer_id)
        assert target is not None
        assert target.deleted is True
        assert target.deleted_at is not None
        assert target.is_active is False

    def test_deleted_user_hidden_from_main_list_shown_in_deleted_list(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        app_client.delete(f"/api/users/{viewer_id}")

        active = app_client.get("/api/users").json()
        assert all(u["username"] != "viewer" for u in active)

        deleted = app_client.get("/api/users/deleted").json()
        assert any(u["username"] == "viewer" for u in deleted)

    def test_deleted_user_cannot_login(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        app_client.delete(f"/api/users/{viewer_id}")
        app_client.post("/logout")

        r = login(app_client, "viewer", "viewerpass123")
        assert r.status_code == 401

    def test_restore_brings_user_back(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        app_client.delete(f"/api/users/{viewer_id}")

        r = app_client.patch(f"/api/users/{viewer_id}", json={"deleted": False, "is_active": True})
        assert r.status_code == 200

        active = app_client.get("/api/users").json()
        assert any(u["username"] == "viewer" for u in active)
        deleted = app_client.get("/api/users/deleted").json()
        assert all(u["username"] != "viewer" for u in deleted)

    def test_cannot_delete_last_admin(self, app_client, db_session):
        second_admin = User(username="admin2", password_hash=hash_password("admin2pass123"), role=Role.admin)
        db_session.add(second_admin)
        db_session.commit()
        login(app_client, "admin2", "admin2pass123")

        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        r = app_client.delete(f"/api/users/{admin_id}")
        assert r.status_code == 200  # two admins exist, this one is fine

        # admin2 is now the only admin -- deleting it (even via itself,
        # blocked by self-lockout) or being the sole survivor is the
        # relevant state; assert no *third* admin could remove it either.
        third_admin_check = db_session.query(User).filter(
            User.role == Role.admin, User.is_active.is_(True), User.deleted.is_(False)
        ).count()
        assert third_admin_check == 1


class TestPermanentDelete:
    def test_permanent_delete_requires_prior_soft_delete(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.delete(f"/api/users/{viewer_id}/permanent")
        assert r.status_code == 404

    def test_permanent_delete_removes_row_from_db(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        app_client.delete(f"/api/users/{viewer_id}")  # soft-delete first

        r = app_client.delete(f"/api/users/{viewer_id}/permanent")
        assert r.status_code == 200

        db_session.expire_all()
        assert db_session.get(User, viewer_id) is None

    def test_permanent_delete_logged_before_row_removed(self, app_client, db_session):
        from vpnadmin.models import AuditLog

        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        app_client.delete(f"/api/users/{viewer_id}")
        app_client.delete(f"/api/users/{viewer_id}/permanent")

        entry = db_session.query(AuditLog).filter(AuditLog.action == "permanently_delete_user").one()
        assert entry.target == "viewer"  # username snapshot, not a FK -- survives the row's deletion

    def test_permanent_delete_admin_only(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        app_client.delete(f"/api/users/{viewer_id}")
        app_client.post("/logout")

        # Re-create a second viewer to log in as (the original was just
        # soft-deleted and can no longer authenticate).
        second_viewer = User(username="viewer2", password_hash=hash_password("viewer2pass123"), role=Role.viewer)
        db_session.add(second_viewer)
        db_session.commit()
        login(app_client, "viewer2", "viewer2pass123")
        r = app_client.delete(f"/api/users/{viewer_id}/permanent")
        assert r.status_code == 403


class TestFirstNameRequired:
    def test_create_user_without_first_name_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "nofirstname", "password": "Somepass123!", "email": "nofirstname@example.com",
        })
        assert r.status_code == 422

    def test_create_user_with_blank_first_name_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "blankfirstname", "password": "Somepass123!", "first_name": "   ",
            "email": "blankfirstname@example.com",
        })
        assert r.status_code == 422

    def test_create_user_with_first_name_succeeds(self, app_client, monkeypatch):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "hasfirstname", "password": "Somepass123!", "first_name": "Alex",
            "email": "hasfirstname@example.com", "mac": "aa:bb:cc:dd:ee:ff",
        })
        assert r.status_code == 201
        assert r.json()["first_name"] == "Alex"

    def test_create_user_without_email_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "noemail", "password": "Somepass123!", "first_name": "Noel",
        })
        assert r.status_code == 422

    def test_create_user_with_blank_email_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "blankemail", "password": "Somepass123!", "first_name": "Blank", "email": "   ",
        })
        assert r.status_code == 422

    def test_admin_edit_cannot_blank_out_first_name(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.patch(f"/api/users/{viewer_id}", json={"first_name": ""})
        assert r.status_code == 422

    def test_self_service_cannot_blank_out_first_name(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"first_name": "  "})
        assert r.status_code == 422


class TestSelfServiceProfile:
    def test_can_view_own_profile(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/users/me")
        assert r.status_code == 200
        assert r.json()["username"] == "viewer"

    def test_viewer_can_update_own_profile_fields(self, app_client, db_session):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"first_name": "Val"})
        assert r.status_code == 200
        assert r.json()["first_name"] == "Val"

    def test_viewer_cannot_change_own_teams(self, app_client, db_session):
        """Team membership is deliberately not self-service for anyone (see
        update_my_profile's own comment) -- UpdateProfileRequest has no
        team_ids field at all, so one included in the request body is
        silently ignored (Pydantic's default extra="ignore" behavior),
        never rejected and never applied. Previously (pre-f1d2e5d) this
        endpoint DID accept team_ids -- see that commit's "Profile page:
        removed the self-service Teams field entirely" note for why this
        test's expected outcome flipped from "applies" to "ignored"."""
        team = Team(name="Support")
        db_session.add(team)
        db_session.commit()

        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"first_name": "Val", "team_ids": [team.id]})
        assert r.status_code == 200
        body = r.json()
        assert body["first_name"] == "Val"
        assert body["teams"] == []

    def test_viewer_cannot_change_own_teams_with_multiple_ids(self, app_client, db_session):
        t1 = Team(name="Support")
        t2 = Team(name="Infra")
        db_session.add_all([t1, t2])
        db_session.commit()

        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"team_ids": [t1.id, t2.id]})
        assert r.status_code == 200
        assert r.json()["teams"] == []

    def test_profile_update_cannot_change_role(self, app_client, db_session):
        login(app_client, "viewer", "viewerpass123")
        app_client.patch("/api/users/me", json={"first_name": "Val"})
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        assert viewer.role == Role.viewer  # UpdateProfileRequest has no role field at all

    def test_self_password_change_requires_current_password(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"new_password": "Brandnewpass123!"})
        assert r.status_code == 400

    def test_self_password_change_wrong_current_password_rejected(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={
            "current_password": "wrongpass", "new_password": "Brandnewpass123!",
        })
        assert r.status_code == 400

    def test_self_password_change_succeeds_and_new_password_works(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={
            "current_password": "viewerpass123", "new_password": "Brandnewpass123!",
        })
        assert r.status_code == 200

        app_client.post("/logout")
        r = login(app_client, "viewer", "Brandnewpass123!")
        assert r.status_code == 200

    def test_admin_can_reset_another_users_password_without_current_password(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.patch(f"/api/users/{viewer_id}", json={"password": "Resetbyadmin123!"})
        assert r.status_code == 200

        app_client.post("/logout")
        r = login(app_client, "viewer", "Resetbyadmin123!")
        assert r.status_code == 200

    def test_admin_edit_cannot_change_created_at(self, app_client, db_session):
        # created_at was made deliberately immutable through the API --
        # UpdateUserRequest no longer even has the field, so sending it
        # should be silently ignored (extra field), not applied.
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        original = viewer.created_at
        r = app_client.patch(f"/api/users/{viewer.id}", json={"created_at": "2000-01-01T00:00:00Z"})
        assert r.status_code == 200
        db_session.refresh(viewer)
        assert viewer.created_at == original


class TestTeams:
    def test_teams_groups_users_including_unassigned(self, app_client, db_session):
        # admin/viewer both start with no team -- both fall into "Unassigned".
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/teams")
        assert r.status_code == 200
        data = r.json()
        assert any(g["team"] == "Unassigned" and g["count"] == 2 for g in data)

    def test_teams_groups_by_team_assignment(self, app_client, db_session):
        team = Team(name="Platform")
        db_session.add(team)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        viewer.teams = [team]
        db_session.commit()
        r = app_client.get("/api/teams")
        assert r.status_code == 200
        data = r.json()
        platform = next(g for g in data if g["team"] == "Platform")
        assert platform["count"] == 1
        assert platform["members"][0]["username"] == "viewer"

    def test_user_appears_under_every_team_they_belong_to(self, app_client, db_session):
        # Task #63: membership is many-to-many -- a user in two teams must
        # show up in both teams' member lists, not just one.
        t1 = Team(name="Platform")
        t2 = Team(name="Security")
        db_session.add_all([t1, t2])
        db_session.commit()
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        viewer.teams = [t1, t2]
        db_session.commit()

        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/teams")
        data = r.json()
        platform = next(g for g in data if g["team"] == "Platform")
        security = next(g for g in data if g["team"] == "Security")
        assert any(m["username"] == "viewer" for m in platform["members"])
        assert any(m["username"] == "viewer" for m in security["members"])
        unassigned = next(g for g in data if g["team"] == "Unassigned")
        assert all(m["username"] != "viewer" for m in unassigned["members"])

    def test_deleted_users_excluded_from_teams(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        r = app_client.delete(f"/api/users/{viewer.id}")
        assert r.status_code == 200
        r = app_client.get("/api/teams")
        total_members = sum(g["count"] for g in r.json())
        assert total_members == 1  # only admin left

    def test_empty_team_shows_up_with_zero_members(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/teams", json={"name": "Ghost Team"})
        assert r.status_code == 201
        r = app_client.get("/api/teams")
        ghost = next(g for g in r.json() if g["team"] == "Ghost Team")
        assert ghost["count"] == 0

    def test_viewer_cannot_create_team(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/teams", json={"name": "Nope"})
        assert r.status_code == 403

    def test_duplicate_team_name_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/teams", json={"name": "Ops"})
        assert r.status_code == 201
        r = app_client.post("/api/teams", json={"name": "Ops"})
        assert r.status_code == 409

    def test_delete_team_blocked_when_members_assigned(self, app_client, db_session):
        # Corrected behavior (task #61): deleting a non-empty team is
        # rejected, not auto-unassigned-then-deleted.
        team = Team(name="Ops")
        db_session.add(team)
        db_session.commit()
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        viewer.teams = [team]
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/teams/{team.id}")
        assert r.status_code == 400
        assert "members assigned" in r.json()["detail"].lower()

        db_session.expire_all()
        assert db_session.get(Team, team.id) is not None
        still_there = db_session.query(User).filter(User.username == "viewer").one()
        assert team in still_there.teams  # untouched, not unassigned

    def test_delete_team_succeeds_when_empty(self, app_client, db_session):
        team = Team(name="Ghost")
        db_session.add(team)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/teams/{team.id}")
        assert r.status_code == 200
        db_session.expire_all()
        assert db_session.get(Team, team.id) is None

    def test_assign_user_to_team_via_admin_edit_endpoint(self, app_client, db_session):
        team = Team(name="Infra")
        db_session.add(team)
        db_session.commit()
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{viewer_id}", json={"team_ids": [team.id]})
        assert r.status_code == 200
        assert r.json()["teams"] == ["Infra"]

    def test_assign_user_to_multiple_teams_via_admin_edit_endpoint(self, app_client, db_session):
        t1 = Team(name="Infra")
        t2 = Team(name="Security")
        db_session.add_all([t1, t2])
        db_session.commit()
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{viewer_id}", json={"team_ids": [t1.id, t2.id]})
        assert r.status_code == 200
        assert sorted(r.json()["teams"]) == ["Infra", "Security"]

    def test_assign_user_to_nonexistent_team_rejected(self, app_client, db_session):
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{viewer_id}", json={"team_ids": [99999]})
        assert r.status_code == 400

    def test_add_and_remove_team_member_endpoints(self, app_client, db_session):
        team = Team(name="Infra")
        db_session.add(team)
        db_session.commit()
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/teams/{team.id}/members", json={"user_id": viewer_id})
        assert r.status_code == 201
        db_session.expire_all()
        assert team in db_session.get(User, viewer_id).teams

        r = app_client.delete(f"/api/teams/{team.id}/members/{viewer_id}")
        assert r.status_code == 200
        db_session.expire_all()
        assert team not in db_session.get(User, viewer_id).teams
