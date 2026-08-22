import re

from vpnadmin.auth import hash_password, verify_password
from vpnadmin.models import RoleDef, Role, Group, User

from .conftest import login


def _make_admin(db_session, username: str, password: str) -> User:
    """Group-only permissions: a role only grants anything via group
    membership now (see permissions.py's effective_role_ids) -- the old
    `role=Role.admin` alone (still set here, for realism/legacy-column
    parity) is not enough to actually make this user functionally an
    admin any more. This helper creates a group with the real "admin"
    RoleDef assigned and puts the new user in it, so it genuinely has
    users:manage (etc.) the way conftest.py's own "admin" fixture does
    (via migrate_users_to_role_groups(), called explicitly there for the
    exact same reason -- this mirrors that for a SECOND admin account a
    test creates after that fixture already ran)."""
    admin_role = db_session.query(RoleDef).filter_by(slug="admin").one()
    group = Group(name=f"{username}-admin-group")
    group.role_defs.append(admin_role)
    db_session.add(group)
    db_session.flush()
    user = User(username=username, password_hash=hash_password(password), role=Role.admin, role_id=admin_role.id)
    user.groups.append(group)
    db_session.add(user)
    db_session.commit()
    return user


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

    def test_correct_login_redirects_to_dashboard(self, app_client):
        # Dashboard is this app's default landing page (see pages.py's
        # root() route) -- httpx TestClient follows redirects by default,
        # so this exercises the full "/" -> "/dashboard" chain, not just
        # the login endpoint's own immediate redirect.
        r = login(app_client, "admin", "adminpass123")
        assert r.status_code == 200
        assert r.url.path == "/dashboard"

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

    def test_root_lands_on_dashboard_for_admin(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/dashboard"

    def test_root_lands_on_dashboard_for_viewer(self, app_client):
        # "viewer" can view the dashboard but doesn't have users:manage --
        # dashboard is checked first regardless, so this lands the same
        # place an admin does.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/dashboard"

    def test_root_falls_through_to_users_without_dashboard_permission(self, app_client, db_session):
        # A role with users:manage but no dashboard visibility at all --
        # dashboard is checked first and fails, so this falls through to
        # the next-best admin-only destination, /users.
        from vpnadmin.models import Group, ObjectPermission, RoleDef

        role = RoleDef(slug="users-only", name="Users Only", is_system=False)
        db_session.add(role)
        db_session.commit()
        db_session.add(ObjectPermission(role_id=role.id, object_key="users", can_manage=True))
        db_session.commit()
        # Group-only permissions: a role only grants anything via group
        # membership now -- see permissions.py's effective_role_ids.
        group = Group(name="Users Only Group")
        group.role_defs.append(role)
        db_session.add(group)
        db_session.flush()
        u = User(username="usersonly", password_hash=hash_password("somepass123"), role_id=role.id)
        u.groups.append(group)
        db_session.add(u)
        db_session.commit()

        login(app_client, "usersonly", "somepass123")
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/users"

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
        assert r.url.path == "/dashboard"
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
        assert r.url.path == "/dashboard"


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
    def test_role_field_in_patch_is_silently_ignored_not_an_error(self, app_client, db_session):
        """Group-only permissions: PATCH /api/users/{id} no longer accepts
        a `role` field at all (see UpdateUserRequest) -- setting a
        personal role would silently do nothing now, so the field was
        removed rather than left in place doing nothing. Pydantic ignores
        unknown fields by default, so this must be a harmless no-op (200,
        nothing changed), never a 400/422 -- confirms the removal didn't
        leave a broken or half-working code path behind. Replaces the old
        "admin cannot demote self via role" test, which tested an API
        capability that no longer exists at all (self-lockout via
        deactivate/delete, tested below, is what remains relevant)."""
        login(app_client, "admin", "adminpass123")
        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        r = app_client.patch(f"/api/users/{admin_id}", json={"role": "viewer"})
        assert r.status_code == 200
        assert "role" not in r.json()  # confirms _serialize() no longer exposes a stale/legacy "role" key either

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

    def test_bootstrap_admin_group_membership_cannot_be_changed_by_another_admin(self, app_client, db_session):
        """Group-only permissions equivalent of the old "cannot be
        demoted via role" protection: since a role can no longer be
        assigned directly to anyone, the bootstrap admin's (super_admin's)
        "Not modifiable by anyone but itself" guarantee now applies to
        group_ids instead -- see routes/users.py's update_user, which
        skips the group_ids branch entirely for a is_bootstrap_admin
        target. Confirms another admin's attempt to change it is silently
        a no-op (200, unchanged), not an error and not actually applied."""
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.is_bootstrap_admin = True
        db_session.commit()
        # conftest's app_client fixture already auto-migrated "admin" into
        # its own group (see migrate_users_to_role_groups) -- capture that
        # starting set to confirm it's UNCHANGED after the attempted edit
        # below, not that it's empty.
        original_group_ids = {g.id for g in admin.groups}
        _make_admin(db_session, "admin2", "admin2pass123")  #_make_admin(db_session, "admin2", "admin2pass123")
        other_group = Group(name="Some Other Group")
        db_session.add(other_group)
        db_session.commit()

        login(app_client, "admin2", "admin2pass123")
        r = app_client.patch(f"/api/users/{admin.id}", json={"group_ids": [other_group.id]})
        assert r.status_code == 200

        db_session.expire_all()
        refreshed = db_session.query(User).filter(User.username == "admin").one()
        assert {g.id for g in refreshed.groups} == original_group_ids

    def test_bootstrap_admin_cannot_be_deactivated_or_deleted_by_another_admin(self, app_client, db_session):
        # Task #65: the bootstrap-admin protection also covers deactivate
        # and both delete paths (soft + permanent), not just role changes.
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.is_bootstrap_admin = True
        db_session.commit()
        _make_admin(db_session, "admin2", "admin2pass123")

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

    def test_non_bootstrap_admin_can_be_demoted_via_group_membership_by_another_admin(self, app_client, db_session):
        # A NON-bootstrap admin account remains demotable by another admin,
        # same as before the bootstrap-only rule existed -- this is the
        # corrected scope: it's not "no admin can ever be demoted", only
        # the specific bootstrap account. "Demoted" now means "removed
        # from their admin-granting group(s)" -- the group-only
        # equivalent of the old "PATCH role=viewer" capability, which no
        # longer exists (see test_role_field_in_patch_is_silently_ignored
        # _not_an_error above).
        second_admin = _make_admin(db_session, "admin2", "admin2pass123")
        assert second_admin.is_bootstrap_admin is False

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{second_admin.id}", json={"group_ids": []})
        assert r.status_code == 200
        assert r.json()["groups"] == []

        db_session.expire_all()
        from vpnadmin.permissions import has_permission
        assert has_permission(db_session, second_admin, "users", "manage") is False

    def test_admin_can_still_be_deactivated_by_another_admin(self, app_client, db_session):
        # A non-bootstrap admin can still be deactivated by another admin,
        # when another active admin remains.
        _make_admin(db_session, "admin2", "admin2pass123")

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
        _make_admin(db_session, "admin2", "admin2pass123")
        login(app_client, "admin2", "admin2pass123")

        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        r = app_client.delete(f"/api/users/{admin_id}")
        assert r.status_code == 200  # two admins exist, this one is fine

        # admin2 is now the only remaining user who can manage users --
        # deleting it (even via itself, blocked by self-lockout) or being
        # the sole survivor is the relevant state; assert no *third* admin
        # could remove it either. "Admin" is no longer a role_id/enum
        # value to filter on directly -- checked via the real permission
        # (users:manage), same as _guard_against_self_lockout itself does.
        from vpnadmin.permissions import has_permission
        remaining = [
            u for u in db_session.query(User).filter(User.is_active.is_(True), User.deleted.is_(False)).all()
            if has_permission(db_session, u, "users", "manage")
        ]
        assert len(remaining) == 1
        assert remaining[0].username == "admin2"


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

    def test_viewer_cannot_change_own_groups(self, app_client, db_session):
        """Group membership is deliberately not self-service for anyone (see
        update_my_profile's own comment) -- UpdateProfileRequest has no
        group_ids field at all, so one included in the request body is
        silently ignored (Pydantic's default extra="ignore" behavior),
        never rejected and never applied. Previously (pre-f1d2e5d) this
        endpoint DID accept group_ids -- see that commit's "Profile page:
        removed the self-service Groups field entirely" note for why this
        test's expected outcome flipped from "applies" to "ignored"."""
        group = Group(name="Support")
        db_session.add(group)
        db_session.commit()
        # conftest's app_client fixture already auto-migrated "viewer" into
        # its own group (see migrate_users_to_role_groups) -- capture that
        # starting set to confirm it's UNCHANGED below, not that it's empty.
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        original_groups = sorted(g.name for g in viewer.groups)

        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"first_name": "Val", "group_ids": [group.id]})
        assert r.status_code == 200
        body = r.json()
        assert body["first_name"] == "Val"
        assert sorted(body["groups"]) == original_groups

    def test_viewer_cannot_change_own_groups_with_multiple_ids(self, app_client, db_session):
        t1 = Group(name="Support")
        t2 = Group(name="Infra")
        db_session.add_all([t1, t2])
        db_session.commit()
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        original_groups = sorted(g.name for g in viewer.groups)

        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"group_ids": [t1.id, t2.id]})
        assert r.status_code == 200
        assert sorted(r.json()["groups"]) == original_groups

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


class TestGroups:
    def test_groups_groups_users_including_unassigned(self, app_client, db_session):
        # Under group-only permissions, conftest's app_client fixture
        # auto-migrates "admin"/"viewer" into their own groups (see
        # migrate_users_to_role_groups) so their existing access survives
        # -- neither is actually "Unassigned" any more. Confirms the
        # "Unassigned" bucket is empty here, and a genuinely group-less
        # user still lands in it.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/groups")
        assert r.status_code == 200
        data = r.json()
        assert any(g["group"] == "Unassigned" and g["count"] == 0 for g in data)

        # A genuinely group-less user still lands in "Unassigned".
        db_session.add(User(username="loner", password_hash=hash_password("pw")))
        db_session.commit()
        r2 = app_client.get("/api/groups")
        assert any(g["group"] == "Unassigned" and g["count"] == 1 for g in r2.json())

    def test_groups_groups_by_group_assignment(self, app_client, db_session):
        group = Group(name="Platform")
        db_session.add(group)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        viewer.groups = [group]
        db_session.commit()
        r = app_client.get("/api/groups")
        assert r.status_code == 200
        data = r.json()
        platform = next(g for g in data if g["group"] == "Platform")
        assert platform["count"] == 1
        assert platform["members"][0]["username"] == "viewer"

    def test_user_appears_under_every_group_they_belong_to(self, app_client, db_session):
        # Task #63: membership is many-to-many -- a user in two groups must
        # show up in both groups' member lists, not just one.
        t1 = Group(name="Platform")
        t2 = Group(name="Security")
        db_session.add_all([t1, t2])
        db_session.commit()
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        viewer.groups = [t1, t2]
        db_session.commit()

        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/groups")
        data = r.json()
        platform = next(g for g in data if g["group"] == "Platform")
        security = next(g for g in data if g["group"] == "Security")
        assert any(m["username"] == "viewer" for m in platform["members"])
        assert any(m["username"] == "viewer" for m in security["members"])
        unassigned = next(g for g in data if g["group"] == "Unassigned")
        assert all(m["username"] != "viewer" for m in unassigned["members"])

    def test_deleted_users_excluded_from_groups(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        r = app_client.delete(f"/api/users/{viewer.id}")
        assert r.status_code == 200
        r = app_client.get("/api/groups")
        total_members = sum(g["count"] for g in r.json())
        assert total_members == 1  # only admin left

    def test_empty_group_shows_up_with_zero_members(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/groups", json={"name": "Ghost Group"})
        assert r.status_code == 201
        r = app_client.get("/api/groups")
        ghost = next(g for g in r.json() if g["group"] == "Ghost Group")
        assert ghost["count"] == 0

    def test_viewer_cannot_create_group(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/groups", json={"name": "Nope"})
        assert r.status_code == 403

    def test_duplicate_group_name_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/groups", json={"name": "Ops"})
        assert r.status_code == 201
        r = app_client.post("/api/groups", json={"name": "Ops"})
        assert r.status_code == 409

    def test_delete_group_blocked_when_members_assigned(self, app_client, db_session):
        # Corrected behavior (task #61): deleting a non-empty group is
        # rejected, not auto-unassigned-then-deleted.
        group = Group(name="Ops")
        db_session.add(group)
        db_session.commit()
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        viewer.groups = [group]
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/groups/{group.id}")
        assert r.status_code == 400
        assert "members assigned" in r.json()["detail"].lower()

        db_session.expire_all()
        assert db_session.get(Group, group.id) is not None
        still_there = db_session.query(User).filter(User.username == "viewer").one()
        assert group in still_there.groups  # untouched, not unassigned

    def test_delete_group_succeeds_when_empty(self, app_client, db_session):
        group = Group(name="Ghost")
        db_session.add(group)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/groups/{group.id}")
        assert r.status_code == 200
        db_session.expire_all()
        assert db_session.get(Group, group.id) is None

    def test_assign_user_to_group_via_admin_edit_endpoint(self, app_client, db_session):
        group = Group(name="Infra")
        db_session.add(group)
        db_session.commit()
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{viewer_id}", json={"group_ids": [group.id]})
        assert r.status_code == 200
        assert r.json()["groups"] == ["Infra"]

    def test_assign_user_to_multiple_groups_via_admin_edit_endpoint(self, app_client, db_session):
        t1 = Group(name="Infra")
        t2 = Group(name="Security")
        db_session.add_all([t1, t2])
        db_session.commit()
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id

        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{viewer_id}", json={"group_ids": [t1.id, t2.id]})
        assert r.status_code == 200
        assert sorted(r.json()["groups"]) == ["Infra", "Security"]

    def test_assign_user_to_nonexistent_group_rejected(self, app_client, db_session):
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{viewer_id}", json={"group_ids": [99999]})
        assert r.status_code == 400

    def test_add_and_remove_group_member_endpoints(self, app_client, db_session):
        group = Group(name="Infra")
        db_session.add(group)
        db_session.commit()
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/groups/{group.id}/members", json={"user_id": viewer_id})
        assert r.status_code == 201
        db_session.expire_all()
        assert group in db_session.get(User, viewer_id).groups

        r = app_client.delete(f"/api/groups/{group.id}/members/{viewer_id}")
        assert r.status_code == 200
        db_session.expire_all()
        assert group not in db_session.get(User, viewer_id).groups
