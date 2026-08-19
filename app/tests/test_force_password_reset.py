"""Covers the Edit User "Force Password Reset on Next Login" checkbox:
an admin can flag/unflag an existing account's User.must_reset_password
independent of resetting its password, new users are still auto-flagged
at creation, and a self-service change still clears the flag either way."""
from vpnadmin.models import User

from .conftest import login


class TestForcePasswordResetToggle:
    def test_new_user_is_auto_flagged(self, app_client, db_session, monkeypatch):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "freshuser", "password": "Somepass123!", "first_name": "Fresh",
            "email": "freshuser@example.com", "mac": "aa:bb:cc:dd:ee:10",
        })
        assert r.status_code == 201
        user = db_session.query(User).filter(User.username == "freshuser").one()
        assert user.must_reset_password is True

    def test_admin_can_flag_existing_user_without_changing_password(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        old_hash = viewer.password_hash
        assert viewer.must_reset_password is False

        r = app_client.patch(f"/api/users/{viewer.id}", json={"force_password_reset": True})
        assert r.status_code == 200
        assert r.json()["must_reset_password"] is True
        db_session.refresh(viewer)
        assert viewer.must_reset_password is True
        assert viewer.password_hash == old_hash  # unchanged -- no password field was sent

    def test_admin_can_cancel_a_pending_request(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        app_client.patch(f"/api/users/{viewer.id}", json={"force_password_reset": True})
        db_session.refresh(viewer)
        assert viewer.must_reset_password is True

        r = app_client.patch(f"/api/users/{viewer.id}", json={"force_password_reset": False})
        assert r.status_code == 200
        assert r.json()["must_reset_password"] is False
        db_session.refresh(viewer)
        assert viewer.must_reset_password is False

    def test_password_reset_always_wins_over_a_stale_unchecked_box(self, app_client, db_session):
        """A password reset in the same request forces True regardless of
        force_password_reset's value -- a freshly admin-set password is
        exactly as unconfirmed as any other reset, see update_user()."""
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()

        r = app_client.patch(f"/api/users/{viewer.id}", json={
            "password": "NewSecurePass123!", "force_password_reset": False,
        })
        assert r.status_code == 200
        assert r.json()["must_reset_password"] is True

    def test_omitting_the_field_leaves_the_flag_untouched(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        viewer.must_reset_password = True
        db_session.commit()

        r = app_client.patch(f"/api/users/{viewer.id}", json={"first_name": "Viewer"})
        assert r.status_code == 200
        assert r.json()["must_reset_password"] is True

    def test_self_service_change_clears_an_admin_set_flag(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        app_client.patch(f"/api/users/{viewer.id}", json={"force_password_reset": True})

        # Same client, re-logged-in as the flagged user, to exercise the
        # self-service path -- matches this suite's own convention
        # elsewhere (e.g. test_audit_endpoint.py) of reusing app_client
        # across a login-as-admin-then-as-viewer sequence.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={
            "current_password": "viewerpass123", "new_password": "Somepass123!",
        })
        assert r.status_code == 200
        db_session.refresh(viewer)
        assert viewer.must_reset_password is False
