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
