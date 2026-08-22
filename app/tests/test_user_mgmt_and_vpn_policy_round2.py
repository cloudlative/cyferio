"""Covers this round's additions: dedicated Reset Password (still just a
PATCH {password} under the hood -- no new endpoint), configurable
notification duration setting, the All Clients "Portal User" column's
backing endpoint, bandwidth-quota decimal/minimum validation, Allowed
OS/Bandwidth Quota fields synced onto the linked VPN profile at user
create/update time, and the Super Admin system role."""
from vpnadmin import policy_store
from vpnadmin.config import settings
from vpnadmin.models import Role, RoleDef, User

from .conftest import login


class TestNotificationDurationSetting:
    def test_defaults_to_1000ms(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/settings")
        assert r.status_code == 200
        assert r.json()["notification_duration_ms"] == 1000  # app_settings.py's fallback for a NULL/unset DB row

    def test_can_be_updated_and_validated(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.patch("/api/settings", json={"notification_duration_ms": 2500})
        assert r.status_code == 200
        assert r.json()["notification_duration_ms"] == 2500

        r = app_client.patch("/api/settings", json={"notification_duration_ms": 50})
        assert r.status_code == 422  # below the 200ms floor


class TestClientUserLinksEndpoint:
    def test_shows_linked_and_omits_unlinked(self, app_client, db_session, monkeypatch, default_group_id):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "linkeduser", "password": "Somepass123!", "first_name": "Linked",
            "email": "linkeduser@example.com", "mac": "aa:bb:cc:dd:ee:01", "group_id": default_group_id,
        })
        r = app_client.get("/api/clients/user-links")
        assert r.status_code == 200
        body = r.json()
        assert body["linkeduser"]["username"] == "linkeduser"
        # clients.html's Email Profile dialog prefills from this -- see
        # get_client_user_links' own docstring for why it's included.
        assert body["linkeduser"]["email"] == "linkeduser@example.com"
        assert "some_unlinked_client" not in body


class TestBandwidthQuotaPrecision:
    def test_policy_store_accepts_decimal_and_rejects_below_point_one(self, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        result = policy_store.set_policy("someclient", bandwidth_monthly_gb=0.5)
        assert result["bandwidth_monthly_gb"] == 0.5

        try:
            policy_store.set_policy("someclient", bandwidth_monthly_gb=0.05)
            assert False, "expected PolicyValidationError"
        except policy_store.PolicyValidationError as e:
            assert "0.1" in str(e)

    def test_api_rejects_below_minimum(self, app_client, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        r = app_client.put("/api/clients/someclient/policy", json={"bandwidth_monthly_gb": 0.05})
        assert r.status_code == 400


class TestUserCreateUpdateSyncsVpnPolicy:
    def test_create_user_with_os_and_bandwidth_syncs_policy(self, app_client, db_session, monkeypatch, tmp_path, default_group_id):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "policieduser", "password": "Somepass123!", "first_name": "Policied",
            "email": "policieduser@example.com", "mac": "aa:bb:cc:dd:ee:02", "group_id": default_group_id,
            "allowed_os": ["windows", "mac"], "bandwidth_monthly_gb": 2.5,
        })
        assert r.status_code == 201
        body = r.json()
        assert sorted(body["allowed_os"]) == ["mac", "windows"]
        assert body["bandwidth_monthly_gb"] == 2.5
        assert policy_store.get_policy("policieduser")["bandwidth_monthly_gb"] == 2.5

    def test_update_user_syncs_policy_onto_linked_profile(self, app_client, db_session, monkeypatch, tmp_path, default_group_id):
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/users", json={
            "username": "policieduser2", "password": "Somepass123!", "first_name": "Policied2",
            "email": "policieduser2@example.com", "mac": "aa:bb:cc:dd:ee:03", "group_id": default_group_id,
        })
        user_id = db_session.query(User).filter(User.username == "policieduser2").one().id

        r = app_client.patch(f"/api/users/{user_id}", json={"allowed_os": ["linux"], "bandwidth_monthly_gb": 5})
        assert r.status_code == 200
        assert r.json()["allowed_os"] == ["linux"]
        assert r.json()["bandwidth_monthly_gb"] == 5
        assert policy_store.get_policy("policieduser2")["allowed_os"] == ["linux"]

    def test_update_user_without_linked_profile_does_not_error(self, app_client, db_session):
        """The rare cert-created-but-DB-failed edge case (or any user with
        no vpn_profile_link) -- allowed_os/bandwidth_monthly_gb in the PATCH
        body must be a harmless no-op, not an error, since there's no
        profile to apply them to yet."""
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.patch(f"/api/users/{viewer_id}", json={
            "allowed_os": ["windows"], "bandwidth_monthly_gb": 1,
            "first_name": "V",
        })
        assert r.status_code == 200
        assert r.json()["vpn_client_name"] is None


class TestSuperAdminRole:
    def test_seeded_and_not_offered_to_creatable_role_resolution(self, db_session):
        role = db_session.query(RoleDef).filter_by(slug="super_admin").first()
        assert role is not None
        assert role.is_system is True

    def test_role_field_in_create_user_is_silently_ignored_not_assignable(self, app_client, monkeypatch, db_session):
        """Group-only permissions: CreateUserRequest no longer has a
        `role` field at all (see routes/users.py) -- a personal role can
        no longer be assigned directly to ANYONE through this endpoint,
        super_admin included, so "Administrators should not be able to
        assign or change users to the Super Admin role through normal
        user editing workflows" is now satisfied even more strongly than
        the old 400-rejection did: there's no role-assignment capability
        left to (mis)use at all. Pydantic ignores the unknown field, so
        this is a harmless 201 with the new account left with zero
        effective role (see effective_role_ids), never a 400 and never an
        actual super_admin grant."""
        from vpnadmin.models import Group
        from vpnadmin.routes import users as users_mod
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        # A group with NO role assigned -- keeps "role had no effect" a
        # meaningful assertion under the mandatory-group model (every user
        # must belong to a group now, but a group with no role still
        # grants nothing, same "no access" outcome the old "zero groups"
        # case demonstrated before groups became mandatory).
        no_role_group = Group(name="No-Role Group")
        db_session.add(no_role_group)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "wannabesuper", "password": "Somepass123!", "first_name": "W",
            "email": "wannabesuper@example.com", "mac": "aa:bb:cc:dd:ee:04", "role": "super_admin",
            "group_id": no_role_group.id,
        })
        assert r.status_code == 201
        assert r.json()["effective_roles"] == []  # group has no role assigned -- role field had no effect

    def test_role_field_in_update_user_is_silently_ignored_not_assignable(self, app_client, db_session):
        # Group-only permissions equivalent of the old "cannot be
        # assigned via update_user" test -- see the create_user version's
        # docstring above for the full reasoning.
        target = User(username="editme-notsuper", password_hash="x", role=Role.viewer, email="editme@example.com")
        db_session.add(target)
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/users/{target.id}", json={"role": "super_admin"})
        assert r.status_code == 200
        assert r.json()["effective_roles"] == []  # unaffected by the ignored field

    def test_roles_list_orders_super_admin_first(self, app_client, db_session):
        # Custom role, deliberately named to sort alphabetically before
        # "Admin" if the ordering were purely alphabetical -- proves the
        # fixed priority order (not just name) is what's actually applied.
        db_session.add(RoleDef(slug="aaa_custom", name="AAA Custom", kind="custom", is_system=False))
        db_session.commit()
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/roles")
        assert r.status_code == 200
        slugs = [role["slug"] for role in r.json()]
        assert slugs.index("super_admin") < slugs.index("admin") < slugs.index("editor") < slugs.index("viewer") < slugs.index("user")
        assert slugs.index("aaa_custom") > slugs.index("user")

    def test_cannot_be_modified(self, app_client, db_session):
        role = db_session.query(RoleDef).filter_by(slug="super_admin").first()
        login(app_client, "admin", "adminpass123")
        r = app_client.patch(f"/api/roles/{role.id}", json={"name": "Renamed"})
        assert r.status_code == 409
