"""Separate VPN Access Restrictions from Portal Login Restrictions --
verifies the two systems (User.restrict_login_by_*/allowed_login_* for
Portal, policy_store's client_policy.json allowed_* for VPN) are fully
independent: editing one never touches the other, and each is enforced
only by its own authentication flow. See:
  - routes/users.py's create_user/update_user/update_my_profile (no more
    Portal->VPN policy_store sync for country/city/asn/ip)
  - app_settings.migrate_decouple_portal_and_vpn_restrictions (the
    one-time backfill for existing deployments)
  - routes/auth.py's login check (Portal-only, never touches policy_store)
  - routes/clients.py's PUT /{name}/policy (VPN-only, never touches User)
"""
from vpnadmin import policy_store
from vpnadmin.config import settings
from vpnadmin.models import User

from .conftest import login


def _create_user_with_profile(app_client, username, mac_suffix, monkeypatch, tmp_path):
    from vpnadmin.routes import users as users_mod
    monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
    monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
    login(app_client, "admin", "adminpass123")
    r = app_client.post("/api/users", json={
        "username": username, "password": "Somepass123!", "first_name": username.title(),
        "email": f"{username}@example.com", "mac": f"aa:bb:cc:dd:ee:{mac_suffix}",
    })
    assert r.status_code == 201
    return r.json()["id"]


class TestScenarioA_IndependentCountryRestrictions:
    """Portal login allowed from Country A; VPN access allowed only from
    Country B. Confirm both operate independently."""

    def test_portal_and_vpn_country_restrictions_stay_independent(self, app_client, db_session, monkeypatch, tmp_path):
        user_id = _create_user_with_profile(app_client, "scenarioa", "20", monkeypatch, tmp_path)

        # Admin sets a Portal restriction to Country A ("PK")...
        r = app_client.patch(f"/api/users/{user_id}", json={
            "restrict_login_by_country": True, "allowed_login_countries": ["PK"],
        })
        assert r.status_code == 200
        assert r.json()["restrict_login_by_country"] is True
        assert r.json()["allowed_login_countries"] == ["PK"]
        # ...and, separately, a VPN restriction to Country B ("US").
        r = app_client.put("/api/clients/scenarioa/policy", json={"allowed_countries": ["US"]})
        assert r.status_code == 200
        assert r.json()["policy"]["allowed_countries"] == ["US"]

        # Both values persisted independently -- neither write clobbered
        # the other's storage.
        user = db_session.query(User).filter(User.username == "scenarioa").one()
        assert user.restrict_login_by_country is True
        assert user.allowed_login_countries == '["PK"]'
        assert policy_store.get_policy("scenarioa")["allowed_countries"] == ["US"]

        # Editing the Portal restriction again doesn't touch the VPN one.
        app_client.patch(f"/api/users/{user_id}", json={"allowed_login_countries": ["PK", "AE"]})
        assert policy_store.get_policy("scenarioa")["allowed_countries"] == ["US"]

        # Editing the VPN restriction again doesn't touch the Portal one.
        app_client.put("/api/clients/scenarioa/policy", json={"allowed_countries": ["US", "CA"]})
        user = db_session.query(User).filter(User.username == "scenarioa").one()
        assert user.allowed_login_countries == '["PK", "AE"]'


class TestScenarioB_VpnRestrictionDoesNotBlockPortal:
    """User can access the portal even though VPN access is restricted."""

    def test_vpn_only_restriction_leaves_portal_login_unaffected(self, app_client, monkeypatch, tmp_path):
        _create_user_with_profile(app_client, "scenariob", "21", monkeypatch, tmp_path)
        app_client.put("/api/clients/scenariob/policy", json={"allowed_countries": ["JP"]})
        app_client.post("/logout")

        import vpnadmin.routes.auth as auth_mod
        # geoip says this login attempt is coming from a country nowhere
        # near the VPN-only restriction -- must not matter, since Portal
        # login never reads policy_store at all.
        monkeypatch.setattr(auth_mod.geoip, "lookup_country", lambda ip: "BR")
        r = login(app_client, "scenariob", "Somepass123!")
        assert r.status_code == 200


class TestScenarioC_PortalRestrictionBlocksLoginIndependently:
    """User can establish VPN connection (i.e. VPN policy is unrestricted);
    user is blocked from portal login due to Portal restrictions."""

    def test_portal_restriction_blocks_login_even_with_unrestricted_vpn(self, app_client, db_session, monkeypatch, tmp_path):
        user_id = _create_user_with_profile(app_client, "scenarioc", "22", monkeypatch, tmp_path)
        # No VPN Access Restriction ever set for this client -- policy_store
        # has no entry, i.e. fully unrestricted VPN access.
        assert policy_store.get_policy("scenarioc") == {}

        r = app_client.patch(f"/api/users/{user_id}", json={
            "restrict_login_by_country": True, "allowed_login_countries": ["PK"],
        })
        assert r.status_code == 200
        app_client.post("/logout")

        import vpnadmin.routes.auth as auth_mod
        monkeypatch.setattr(auth_mod.geoip, "lookup_country", lambda ip: "US")
        r = login(app_client, "scenarioc", "Somepass123!")
        assert r.status_code == 403
        assert "not permitted" in r.text.lower()
        # VPN policy remains untouched/unrestricted throughout.
        assert policy_store.get_policy("scenarioc") == {}


class TestScenarioD_SelfServiceVpnCountryIsVpnOnly:
    """User-configured VPN country restriction affects VPN access only and
    does not interfere with portal authentication (covered in depth in
    test_self_service_login_country.py; this is the end-to-end version
    exercising the real login route)."""

    def test_self_service_vpn_country_does_not_block_portal_login(self, app_client, monkeypatch, tmp_path):
        _create_user_with_profile(app_client, "scenariod", "23", monkeypatch, tmp_path)
        app_client.post("/logout")
        login(app_client, "scenariod", "Somepass123!")
        r = app_client.patch("/api/users/me", json={"login_country": "PK"})
        assert r.status_code == 200
        assert r.json()["vpn_allowed_countries"] == ["PK"]
        assert r.json()["restrict_login_by_country"] is False
        app_client.post("/logout")

        import vpnadmin.routes.auth as auth_mod
        monkeypatch.setattr(auth_mod.geoip, "lookup_country", lambda ip: "DE")
        r = login(app_client, "scenariod", "Somepass123!")
        assert r.status_code == 200


class TestMigrateDecouplePortalAndVpnRestrictions:
    def test_copies_active_portal_restrictions_into_vpn_policy_once(self, app_client, db_session, monkeypatch, tmp_path):
        from vpnadmin import app_settings

        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        user_id = _create_user_with_profile(app_client, "legacyuser", "24", monkeypatch, tmp_path)
        app_client.patch(f"/api/users/{user_id}", json={
            "restrict_login_by_country": True, "allowed_login_countries": ["PK"],
            "restrict_login_by_city": False,
        })
        # Simulate a pre-decoupling deployment: no migration has run yet,
        # and (as would already be true on any pre-existing install) VPN
        # policy has nothing of its own for this client.
        assert policy_store.get_policy("legacyuser").get("allowed_countries") is None
        row = app_settings.get_settings_row(db_session)
        row.restrictions_decoupled_at = None
        db_session.commit()

        app_settings.migrate_decouple_portal_and_vpn_restrictions(db_session)

        assert policy_store.get_policy("legacyuser")["allowed_countries"] == ["PK"]

    def test_is_a_no_op_on_second_run(self, app_client, db_session, monkeypatch, tmp_path):
        from vpnadmin import app_settings

        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        user_id = _create_user_with_profile(app_client, "legacyuser2", "25", monkeypatch, tmp_path)
        app_client.patch(f"/api/users/{user_id}", json={
            "restrict_login_by_country": True, "allowed_login_countries": ["PK"],
        })
        app_settings.migrate_decouple_portal_and_vpn_restrictions(db_session)
        # An admin now deliberately clears the VPN-side restriction while
        # keeping the Portal one -- a legitimate independent edit.
        app_client.put("/api/clients/legacyuser2/policy", json={"allowed_countries": []})
        assert policy_store.get_policy("legacyuser2").get("allowed_countries") in (None, [])

        # Re-running the migration must NOT re-impose the restriction --
        # it already ran once (restrictions_decoupled_at is set).
        app_settings.migrate_decouple_portal_and_vpn_restrictions(db_session)
        assert policy_store.get_policy("legacyuser2").get("allowed_countries") in (None, [])
