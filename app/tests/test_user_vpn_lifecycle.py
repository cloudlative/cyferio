"""User<->VPN Profile lifecycle unification: create_user provisions a VPN
profile as part of creating the portal user, GET /api/clients/unassigned
powers Edit User's "attach existing profile" dropdown, POST
/api/users/{id}/vpn-link performs that attach, and permanently deleting a
user purges its linked (non-protected) VPN profile."""

from vpnadmin.models import Role, User, VpnProfileLink

from .conftest import login


class TestCreateUserProvisionsVpnProfile:
    def test_success_creates_cert_user_and_link(self, app_client, db_session, monkeypatch):
        from vpnadmin.routes import users as users_mod

        calls = {}
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: calls.setdefault("add_client", (name, mac)) or f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "newvpnuser",
                "password": "Somepass123!",
                "first_name": "New",
                "email": "newvpnuser@example.com",
                "mac": "aa:bb:cc:dd:ee:ff",
            },
        )
        assert r.status_code == 201
        assert calls["add_client"] == ("newvpnuser", "aa:bb:cc:dd:ee:ff")
        assert r.json()["vpn_client_name"] == "newvpnuser"

        link = db_session.query(VpnProfileLink).filter(VpnProfileLink.vpn_client_name == "newvpnuser").one()
        assert link.link_source == "created_with_profile"
        user = db_session.query(User).filter(User.username == "newvpnuser").one()
        assert link.user_id == user.id

    def test_cert_creation_failure_leaves_no_user_created(self, app_client, db_session, monkeypatch):
        from vpnadmin.cli_wrapper import ScriptError
        from vpnadmin.routes import users as users_mod

        def fake_add_client(name, mac):
            raise ScriptError("MAC already registered to another client.")

        monkeypatch.setattr(users_mod.cli, "add_client", fake_add_client)
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "failedvpnuser",
                "password": "Somepass123!",
                "first_name": "Failed",
                "email": "failedvpnuser@example.com",
                "mac": "aa:bb:cc:dd:ee:ff",
            },
        )
        assert r.status_code == 400
        assert db_session.query(User).filter(User.username == "failedvpnuser").first() is None

    def test_missing_mac_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "nomacuser",
                "password": "Somepass123!",
                "first_name": "No",
                "email": "nomacuser@example.com",
            },
        )
        assert r.status_code == 422


class TestUnassignedClients:
    def test_excludes_already_linked_clients(self, app_client, db_session, monkeypatch):
        from vpnadmin.routes import clients as clients_mod

        monkeypatch.setattr(
            clients_mod.cli,
            "get_clients_snapshot",
            lambda: [
                {"name": "linked-client", "in_db": True, "mac_count": 1},
                {"name": "free-client", "in_db": True, "mac_count": 1},
            ],
        )
        someone = User(username="linkedowner", password_hash="x", role=Role.viewer)
        db_session.add(someone)
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=someone.id, vpn_client_name="linked-client", link_source="manual_admin_link"))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/clients/unassigned")
        assert r.status_code == 200
        names = [c["name"] for c in r.json()]
        assert names == ["free-client"]

    def test_viewer_forbidden(self, app_client, monkeypatch):
        from vpnadmin.routes import clients as clients_mod

        monkeypatch.setattr(clients_mod.cli, "get_clients_snapshot", lambda: [])
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/clients/unassigned")
        assert r.status_code == 403


class TestVpnLink:
    def test_attach_unassigned_profile(self, app_client, db_session):
        target = User(username="linkme", password_hash="x", role=Role.viewer, first_name="Link", email="linkme@example.com")
        db_session.add(target)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{target.id}/vpn-link", json={"vpn_client_name": "orphan-cert"})
        assert r.status_code == 201
        assert r.json()["vpn_client_name"] == "orphan-cert"

        link = db_session.query(VpnProfileLink).filter(VpnProfileLink.user_id == target.id).one()
        assert link.vpn_client_name == "orphan-cert"
        assert link.link_source == "manual_admin_link"

    def test_cannot_attach_already_linked_profile(self, app_client, db_session):
        owner = User(username="owner1", password_hash="x", role=Role.viewer)
        other = User(username="wants-link", password_hash="x", role=Role.viewer)
        db_session.add_all([owner, other])
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=owner.id, vpn_client_name="taken-cert", link_source="manual_admin_link"))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{other.id}/vpn-link", json={"vpn_client_name": "taken-cert"})
        assert r.status_code == 409

    def test_cannot_attach_when_user_already_linked(self, app_client, db_session):
        target = User(username="already-linked", password_hash="x", role=Role.viewer)
        db_session.add(target)
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=target.id, vpn_client_name="existing-cert", link_source="manual_admin_link"))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{target.id}/vpn-link", json={"vpn_client_name": "another-cert"})
        assert r.status_code == 400


class TestPermanentDeletePurgesVpnProfile:
    def test_purges_non_protected_link(self, app_client, db_session, monkeypatch):
        from vpnadmin import vpn_identity_sync as sync_mod

        calls = []
        monkeypatch.setattr(sync_mod.cli, "revoke_client", lambda name: calls.append(("revoke", name)))
        monkeypatch.setattr(sync_mod.cli, "purge_revoked", lambda name: calls.append(("purge", name)))

        target = User(username="todelete", password_hash="x", role=Role.viewer, deleted=True)
        db_session.add(target)
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=target.id, vpn_client_name="todelete-cert", link_source="manual_admin_link", protected_from_auto_revoke=False))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/users/{target.id}/permanent")
        assert r.status_code == 200
        assert ("purge", "todelete-cert") in calls

    def test_protected_link_never_touched(self, app_client, db_session, monkeypatch):
        from vpnadmin import vpn_identity_sync as sync_mod

        calls = []
        monkeypatch.setattr(sync_mod.cli, "revoke_client", lambda name: calls.append(("revoke", name)))
        monkeypatch.setattr(sync_mod.cli, "purge_revoked", lambda name: calls.append(("purge", name)))

        target = User(username="protected-user", password_hash="x", role=Role.viewer, deleted=True)
        db_session.add(target)
        db_session.commit()
        db_session.add(
            VpnProfileLink(
                user_id=target.id,
                vpn_client_name="protected-cert",
                link_source="migration_exact_match",
                protected_from_auto_revoke=True,
            )
        )
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/users/{target.id}/permanent")
        assert r.status_code == 200
        assert calls == []


class TestEmailRequiredOnEdit:
    def test_blanking_email_rejected(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        r = app_client.patch(f"/api/users/{viewer.id}", json={"email": ""})
        assert r.status_code == 422

    def test_omitting_email_in_partial_update_is_unaffected(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer = db_session.query(User).filter(User.username == "viewer").one()
        r = app_client.patch(f"/api/users/{viewer.id}", json={"deleted": False, "is_active": True})
        assert r.status_code == 200
