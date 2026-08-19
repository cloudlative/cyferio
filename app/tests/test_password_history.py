"""Covers Settings -> Security's "Remember last N passwords": a new
password can't match the account's current password or its last N
previous ones, checked on every password-setting path (self-service
change, admin reset, forgot-password reset) and tunable/disableable via
app_settings.runtime.password_history_count.

Note: the fixture login passwords ("viewerpass123"/"adminpass123") don't
themselves satisfy the complexity policy (no uppercase/special char), so
they're never resubmitted as a `new_password` here -- only ever used as
`current_password`/the initial login. Every reuse scenario below is built
from complexity-compliant passwords."""
import re

from vpnadmin import app_settings
from vpnadmin.models import User

from .conftest import login


class TestPasswordHistorySelfService:
    def test_default_blocks_current_password_as_new(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"current_password": "viewerpass123", "new_password": "Compliant1!"})
        assert r.status_code == 200

        r = app_client.patch("/api/users/me", json={"current_password": "Compliant1!", "new_password": "Compliant1!"})
        assert r.status_code == 400
        assert "current password" in r.json()["detail"].lower()

    def test_blocks_reuse_within_the_configured_window(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        passwords = ["Firstpass1!", "Secondpass2!", "Thirdpass3!"]
        current = "viewerpass123"
        for pw in passwords:
            r = app_client.patch("/api/users/me", json={"current_password": current, "new_password": pw})
            assert r.status_code == 200
            current = pw

        # Default history count is 3 -- after 3 changes, Firstpass1! (the
        # 1st change-to password) is still within the tracked window
        # (history = [Secondpass2!'s old hash i.e. Firstpass1!, Firstpass1!'s
        # old hash i.e. viewerpass123, ...]).
        r = app_client.patch("/api/users/me", json={"current_password": current, "new_password": "Firstpass1!"})
        assert r.status_code == 400
        assert "recently" in r.json()["detail"].lower()

    def test_password_outside_the_window_is_allowed_again(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        # With history_count=3, after change k the tracked window holds the
        # N most recent PRIOR passwords (pw_{k-1}..pw_{k-N}) -- Firstpass1!
        # (pw1) only rolls out once k > N+1, i.e. on the 5th change.
        passwords = ["Firstpass1!", "Secondpass2!", "Thirdpass3!", "Fourthpass4!", "Fifthpass5!"]
        current = "viewerpass123"
        for pw in passwords:
            r = app_client.patch("/api/users/me", json={"current_password": current, "new_password": pw})
            assert r.status_code == 200
            current = pw

        r = app_client.patch("/api/users/me", json={"current_password": current, "new_password": "Firstpass1!"})
        assert r.status_code == 200

    def test_disabled_when_history_count_is_zero(self, app_client, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "password_history_count", 0)
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"current_password": "viewerpass123", "new_password": "Compliant1!"})
        assert r.status_code == 200
        # Even reusing the immediately-previous password is allowed once disabled.
        r = app_client.patch("/api/users/me", json={"current_password": "Compliant1!", "new_password": "Compliant1!"})
        assert r.status_code == 200

    def test_admin_can_tune_the_count_via_settings(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"password_history_count": 1})
        assert r.status_code == 200
        assert r.json()["password_history_count"] == 1

        app_client.post("/logout")
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"current_password": "viewerpass123", "new_password": "Onlyone1!"})
        assert r.status_code == 200
        r = app_client.patch("/api/users/me", json={"current_password": "Onlyone1!", "new_password": "Andtwo2!"})
        assert r.status_code == 200
        # With N=1, Onlyone1! is still the sole tracked entry here (it was
        # the password immediately before this 2nd change) -- reusing it
        # now is still blocked.
        r = app_client.patch("/api/users/me", json={"current_password": "Andtwo2!", "new_password": "Onlyone1!"})
        assert r.status_code == 400

        # A 3rd change rolls Onlyone1! out of the 1-entry window.
        r = app_client.patch("/api/users/me", json={"current_password": "Andtwo2!", "new_password": "Andthree3!"})
        assert r.status_code == 200
        r = app_client.patch("/api/users/me", json={"current_password": "Andthree3!", "new_password": "Onlyone1!"})
        assert r.status_code == 200

    def test_rejects_out_of_range_history_count(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"password_history_count": 51})
        assert r.status_code == 422


class TestPasswordHistoryAdminReset:
    def test_admin_reset_blocks_reuse_of_users_current_password(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.patch(f"/api/users/{viewer_id}", json={"password": "FirstSet1!"})
        assert r.status_code == 200

        r = app_client.patch(f"/api/users/{viewer_id}", json={"password": "FirstSet1!"})
        assert r.status_code == 400
        assert "current password" in r.json()["detail"].lower()

    def test_admin_reset_records_history_that_self_service_then_honors(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.patch(f"/api/users/{viewer_id}", json={"password": "AdminSetPass1!"})
        assert r.status_code == 200

        app_client.post("/logout")
        login(app_client, "viewer", "AdminSetPass1!")
        # The user's password immediately before this admin reset
        # (viewerpass123, non-compliant so it can never be re-submitted as
        # new_password) doesn't matter here -- what matters is that the
        # reset itself recorded AdminSetPass1! into history, so trying to
        # go right back to it after a further self-service change is blocked.
        r = app_client.patch("/api/users/me", json={"current_password": "AdminSetPass1!", "new_password": "SelfChange1!"})
        assert r.status_code == 200
        r = app_client.patch("/api/users/me", json={"current_password": "SelfChange1!", "new_password": "AdminSetPass1!"})
        assert r.status_code == 400


class TestPasswordHistoryForgotPassword:
    def _mock_smtp(self, monkeypatch, sent):
        import vpnadmin.routes.auth as auth_mod

        def fake_send(*, db, to_address, username, reset_url, ttl_minutes):
            sent["to"] = to_address
            sent["username"] = username
            sent["reset_url"] = reset_url
        monkeypatch.setattr(auth_mod.mailer, "send_password_reset_email", fake_send)

    def test_forgot_password_reset_blocks_reuse_of_current_password(self, app_client, db_session, monkeypatch):
        admin = db_session.query(User).filter(User.username == "admin").one()
        admin.email = "admin@example.com"
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        app_client.patch("/api/users/me", json={"current_password": "adminpass123", "new_password": "Compliant1!"})
        app_client.post("/logout")

        sent = {}
        self._mock_smtp(monkeypatch, sent)
        app_client.post("/forgot-password", data={"email": "admin@example.com"})
        token = re.search(r"[?&]token=([^&\s\"']+)", sent["reset_url"]).group(1)

        r = app_client.post("/reset-password", data={"token": token, "new_password": "Compliant1!", "confirm_password": "Compliant1!"})
        assert r.status_code == 400
        assert "current password" in r.text.lower()
