"""Self-service VPN login country (PATCH /api/users/me's login_country
field) -- see UpdateProfileRequest.login_country's docstring in
routes/users.py for the design. As of the Portal/VPN restriction
decoupling, this writes STRAIGHT to policy_store (VPN Access Restrictions)
and never touches User.restrict_login_by_country/allowed_login_countries
(Portal Login Restrictions) -- so it can restrict VPN access but must never
affect this account's own ability to sign in to the portal.
"""
from vpnadmin import policy_store
from vpnadmin.config import settings
from vpnadmin.models import User

from .conftest import login


class TestSelfServiceLoginCountry:
    def test_set_country_writes_only_to_vpn_policy_not_portal_columns(self, app_client, db_session, monkeypatch, tmp_path):
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
        assert body["vpn_restrict_by_country"] is True
        assert body["vpn_allowed_countries"] == ["PK"]
        # The Portal-side columns must be completely untouched.
        assert body["restrict_login_by_country"] is False
        assert body["allowed_login_countries"] == []

        user = db_session.query(User).filter(User.username == "geouser").one()
        assert user.restrict_login_by_country is False
        assert user.allowed_login_countries is None

        assert policy_store.get_policy("geouser")["allowed_countries"] == ["PK"]

    def test_clearing_country_removes_vpn_restriction(self, app_client, monkeypatch, tmp_path):
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
        assert body["vpn_restrict_by_country"] is False
        assert body["vpn_allowed_countries"] == []
        assert policy_store.get_policy("geouser2").get("allowed_countries") in (None, [])

    def test_users_without_linked_profile_get_a_clear_error(self, app_client):
        # "viewer" (seeded fixture) has no vpn_profile_link -- there's
        # nowhere for a VPN-only restriction to live yet.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"login_country": "US"})
        assert r.status_code == 400
        assert "vpn profile" in r.json()["detail"].lower()

    def test_invalid_country_code_rejected(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch("/api/users/me", json={"login_country": "USA"})
        assert r.status_code == 422

    def test_omitted_field_leaves_vpn_restriction_untouched(self, app_client, monkeypatch, tmp_path):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "geouser4", "password": "Somepass123!", "first_name": "Geo4",
            "email": "geouser4@example.com", "mac": "aa:bb:cc:dd:ee:13",
        })
        app_client.post("/logout")
        login(app_client, "geouser4", "Somepass123!")
        app_client.patch("/api/users/me", json={"login_country": "GB"})
        r = app_client.patch("/api/users/me", json={"first_name": "Geo Renamed"})
        assert r.status_code == 200
        assert r.json()["vpn_allowed_countries"] == ["GB"]

    def test_setting_vpn_country_does_not_block_own_portal_login(self, app_client, monkeypatch, tmp_path):
        """Scenario D from the restriction-decoupling task: a self-set VPN
        login country must never interfere with this same account's portal
        authentication, even from a different country."""
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "geouser5", "password": "Somepass123!", "first_name": "Geo5",
            "email": "geouser5@example.com", "mac": "aa:bb:cc:dd:ee:14",
        })
        app_client.post("/logout")
        login(app_client, "geouser5", "Somepass123!")
        app_client.patch("/api/users/me", json={"login_country": "PK"})
        app_client.post("/logout")

        # Portal login from a totally different, unrelated country still
        # succeeds -- no geoip restriction was ever configured for the
        # PORTAL side of this account, only the VPN side.
        import vpnadmin.routes.auth as auth_mod
        monkeypatch.setattr(auth_mod.geoip, "lookup_country", lambda ip: "US")
        r = login(app_client, "geouser5", "Somepass123!")
        assert r.status_code == 200
        assert r.url.path in ("/change-password", "/my-vpn-profile", "/profile", "/users", "/dashboard")

    def test_admin_can_clear_vpn_restriction_via_manage_restrictions_api(self, app_client, monkeypatch, tmp_path):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "geouser6", "password": "Somepass123!", "first_name": "Geo6",
            "email": "geouser6@example.com", "mac": "aa:bb:cc:dd:ee:15",
        })
        app_client.post("/logout")
        login(app_client, "geouser6", "Somepass123!")
        app_client.patch("/api/users/me", json={"login_country": "PK"})
        app_client.post("/logout")

        login(app_client, "admin", "adminpass123")
        r = app_client.put("/api/clients/geouser6/policy", json={"allowed_countries": []})
        assert r.status_code == 200
        assert policy_store.get_policy("geouser6").get("allowed_countries") in (None, [])
