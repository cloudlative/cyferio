"""Self-service VPN Login Country (PATCH /api/users/me's login_country field)
-- see UpdateProfileRequest.login_country's docstring in routes/users.py for
the design. Covers: saving/clearing a country collapses onto the same
User.restrict_login_by_country/allowed_login_countries columns an admin
edits, the sync onto the linked VPN profile's client_policy.json (the
mechanism that actually gates VPN connections), validation, and that an
admin can still override/clear afterwards.
"""
from vpnadmin import policy_store
from vpnadmin.config import settings
from vpnadmin.models import User

from .conftest import login


class TestSelfServiceLoginCountry:
    def test_set_country_persists_and_syncs_policy(self, app_client, db_session, monkeypatch, tmp_path):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "geouser", "password": "Somepass123!", "first_name": "Geo",
            "email": "geouser@example.com", "mac": "aa:bb:cc:dd:ee:10",
        })
        app_client.post("/logout")
        login(app_client, "geouser", "Somepass123!")

        r = app_client.patch("/api/users/me", json={"login_country": "pk"})
        assert r.status_code == 200
        body = r.json()
        assert body["restrict_login_by_country"] is True
        assert body["allowed_login_countries"] == ["PK"]

        user = db_session.query(User).filter(User.username == "geouser").one()
        assert user.restrict_login_by_country is True

        assert policy_store.get_policy("geouser")["allowed_countries"] == ["PK"]

    def test_clearing_country_removes_restriction(self, app_client, monkeypatch, tmp_path):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "geouser2", "password": "Somepass123!", "first_name": "Geo2",
            "email": "geouser2@example.com", "mac": "aa:bb:cc:dd:ee:11",
        })
        app_client.post("/logout")
        login(app_client, "geouser2", "Somepass123!")

        app_client.patch("/api/users/me", json={"login_country": "AE"})
        r = app_client.patch("/api/users/me", json={"login_country": None})
        assert r.status_code == 200
        body = r.json()
        assert body["restrict_login_by_country"] is False
        assert body["allowed_login_countries"] == []
        assert policy_store.get_policy("geouser2").get("allowed_countries") in (None, [])

    def test_users_without_linked_profile_do_not_error(self, app_client, db_session):
        # "viewer" (seeded fixture) has no vpn_profile_link -- the sync must
        # be a no-op, not a crash, same posture as update_user's own
        # "no linked profile" case.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"login_country": "US"})
        assert r.status_code == 200
        assert r.json()["allowed_login_countries"] == ["US"]

    def test_invalid_country_code_rejected(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"login_country": "USA"})
        assert r.status_code == 422

    def test_omitted_field_leaves_restriction_untouched(self, app_client, db_session):
        login(app_client, "viewer", "viewerpass123")
        app_client.patch("/api/users/me", json={"login_country": "GB"})
        r = app_client.patch("/api/users/me", json={"first_name": "Viewy"})
        assert r.status_code == 200
        assert r.json()["allowed_login_countries"] == ["GB"]

    def test_admin_can_override_self_set_country(self, app_client, db_session, monkeypatch, tmp_path):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "geouser3", "password": "Somepass123!", "first_name": "Geo3",
            "email": "geouser3@example.com", "mac": "aa:bb:cc:dd:ee:12",
        })
        app_client.post("/logout")
        login(app_client, "geouser3", "Somepass123!")
        app_client.patch("/api/users/me", json={"login_country": "PK"})
        app_client.post("/logout")

        login(app_client, "admin", "adminpass123")
        user_id = None
        r = app_client.get("/api/users")
        for u in r.json():
            if u["username"] == "geouser3":
                user_id = u["id"]
        assert user_id is not None
        r = app_client.patch(f"/api/users/{user_id}", json={"restrict_login_by_country": False, "allowed_login_countries": []})
        assert r.status_code == 200
        assert r.json()["restrict_login_by_country"] is False
