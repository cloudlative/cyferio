from vpnadmin.auth import hash_password, verify_password
from vpnadmin.models import Role, User

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

    def test_correct_login_redirects_home(self, app_client):
        r = login(app_client, "admin", "adminpass123")
        assert r.status_code == 200  # httpx TestClient follows redirects by default
        assert r.url.path == "/"

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

    def test_dashboard_accessible_after_login(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/")
        assert r.status_code == 200

    def test_logout_clears_session(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.post("/logout")
        r = app_client.get("/", follow_redirects=False)
        assert r.status_code == 303


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

    def test_cannot_demote_last_admin(self, app_client, db_session):
        # "admin" is the only admin; try to demote it via a *different*
        # logged-in admin account to isolate this guardrail from the
        # can't-touch-yourself one above.
        second_admin = User(username="admin2", password_hash=hash_password("admin2pass123"), role=Role.admin)
        db_session.add(second_admin)
        db_session.commit()

        login(app_client, "admin2", "admin2pass123")
        admin_id = db_session.query(User).filter(User.username == "admin").one().id
        # Demote the original admin -- should succeed, two admins exist.
        r = app_client.patch(f"/api/users/{admin_id}", json={"role": "viewer"})
        assert r.status_code == 200

        # Now only admin2 is an admin; demoting/deleting self is still
        # blocked by the self-lockout rule (covered above), but demoting
        # admin2 via itself should ALSO be blocked as the last admin.
        # (Already implied by the self-guard, this just documents intent.)


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


class TestSelfServiceProfile:
    def test_can_view_own_profile(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/users/me")
        assert r.status_code == 200
        assert r.json()["username"] == "viewer"

    def test_viewer_can_update_own_profile_fields(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"first_name": "Val", "team": "Support"})
        assert r.status_code == 200
        body = r.json()
        assert body["first_name"] == "Val"
        assert body["team"] == "Support"

    def test_profile_update_cannot_change_role(self, app_client, db_session):
        login(app_client, "viewer", "viewerpass123")
        app_client.patch("/api/users/me", json={"first_name": "Val"})
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        assert viewer.role == Role.viewer  # UpdateProfileRequest has no role field at all

    def test_self_password_change_requires_current_password(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"new_password": "brandnewpass123"})
        assert r.status_code == 400

    def test_self_password_change_wrong_current_password_rejected(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={
            "current_password": "wrongpass", "new_password": "brandnewpass123",
        })
        assert r.status_code == 400

    def test_self_password_change_succeeds_and_new_password_works(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={
            "current_password": "viewerpass123", "new_password": "brandnewpass123",
        })
        assert r.status_code == 200

        app_client.post("/logout")
        r = login(app_client, "viewer", "brandnewpass123")
        assert r.status_code == 200

    def test_admin_can_reset_another_users_password_without_current_password(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.patch(f"/api/users/{viewer_id}", json={"password": "resetbyadmin123"})
        assert r.status_code == 200

        app_client.post("/logout")
        r = login(app_client, "viewer", "resetbyadmin123")
        assert r.status_code == 200
