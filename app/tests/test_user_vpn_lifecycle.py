"""User<->VPN Profile lifecycle unification: create_user provisions a VPN
profile as part of creating the portal user, GET /api/clients/unassigned
powers Edit User's "attach existing profile" dropdown, POST
/api/users/{id}/vpn-link performs that attach, and permanently deleting a
user purges its linked (non-protected) VPN profile."""
from vpnadmin.models import Role, User, VpnProfileLink

from .conftest import login


class TestCreateUserProvisionsVpnProfile:
    def test_success_creates_cert_user_and_link(self, app_client, db_session, monkeypatch, default_group_id):
        from vpnadmin.routes import users as users_mod
        calls = {}
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: calls.setdefault("add_client", (name, mac)) or f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "newvpnuser", "password": "Somepass123!", "first_name": "New",
            "email": "newvpnuser@example.com", "mac": "aa:bb:cc:dd:ee:ff", "group_id": default_group_id,
        })
        assert r.status_code == 201
        assert calls["add_client"] == ("newvpnuser", "aa:bb:cc:dd:ee:ff")
        assert r.json()["vpn_client_name"] == "newvpnuser"

        link = db_session.query(VpnProfileLink).filter(VpnProfileLink.vpn_client_name == "newvpnuser").one()
        assert link.link_source == "created_with_profile"
        user = db_session.query(User).filter(User.username == "newvpnuser").one()
        assert link.user_id == user.id

    def test_cert_creation_failure_leaves_no_user_created(self, app_client, db_session, monkeypatch, default_group_id):
        from vpnadmin.routes import users as users_mod
        from vpnadmin.cli_wrapper import ScriptError

        def fake_add_client(name, mac):
            raise ScriptError("MAC already registered to another client.")
        monkeypatch.setattr(users_mod.cli, "add_client", fake_add_client)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "failedvpnuser", "password": "Somepass123!", "first_name": "Failed",
            "email": "failedvpnuser@example.com", "mac": "aa:bb:cc:dd:ee:ff", "group_id": default_group_id,
        })
        assert r.status_code == 400
        assert db_session.query(User).filter(User.username == "failedvpnuser").first() is None

    def test_missing_mac_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/users", json={
            "username": "nomacuser", "password": "Somepass123!", "first_name": "No",
            "email": "nomacuser@example.com",
        })
        assert r.status_code == 422


class TestUnassignedClients:
    def test_excludes_already_linked_clients(self, app_client, db_session, monkeypatch):
        from vpnadmin.routes import clients as clients_mod
        monkeypatch.setattr(clients_mod.cli, "get_clients_snapshot", lambda: [
            {"name": "linked-client", "in_db": True, "mac_count": 1},
            {"name": "free-client", "in_db": True, "mac_count": 1},
        ])
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

    def test_reassign_replaces_existing_link(self, app_client, db_session):
        # Task feedback: "Remove the immutable behavior for the VPN
        # Profile association... Allow administrators to modify an
        # existing VPN Profile assignment."
        target = User(username="already-linked", password_hash="x", role=Role.viewer)
        db_session.add(target)
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=target.id, vpn_client_name="existing-cert", link_source="manual_admin_link"))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{target.id}/vpn-link", json={"vpn_client_name": "another-cert"})
        assert r.status_code == 201
        assert r.json()["vpn_client_name"] == "another-cert"

        # Exactly one link for this user, pointing at the new client -- the
        # old one is gone (not duplicated, not left dangling).
        links = db_session.query(VpnProfileLink).filter(VpnProfileLink.user_id == target.id).all()
        assert len(links) == 1
        assert links[0].vpn_client_name == "another-cert"
        # The old client is now unassigned, not deleted -- available to
        # attach to another user.
        assert db_session.query(VpnProfileLink).filter(VpnProfileLink.vpn_client_name == "existing-cert").first() is None

    def test_reassign_to_already_linked_client_rejected(self, app_client, db_session):
        owner = User(username="owner2", password_hash="x", role=Role.viewer)
        target = User(username="reassign-me", password_hash="x", role=Role.viewer)
        db_session.add_all([owner, target])
        db_session.commit()
        db_session.add_all([
            VpnProfileLink(user_id=owner.id, vpn_client_name="owner2-cert", link_source="manual_admin_link"),
            VpnProfileLink(user_id=target.id, vpn_client_name="reassign-me-cert", link_source="manual_admin_link"),
        ])
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{target.id}/vpn-link", json={"vpn_client_name": "owner2-cert"})
        assert r.status_code == 409
        # Rejected before touching anything -- target keeps its original link.
        link = db_session.query(VpnProfileLink).filter(VpnProfileLink.user_id == target.id).one()
        assert link.vpn_client_name == "reassign-me-cert"

    def test_reassign_to_same_client_rejected(self, app_client, db_session):
        target = User(username="same-client-user", password_hash="x", role=Role.viewer)
        db_session.add(target)
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=target.id, vpn_client_name="same-cert", link_source="manual_admin_link"))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{target.id}/vpn-link", json={"vpn_client_name": "same-cert"})
        assert r.status_code == 400

    def test_reassign_does_not_carry_over_portal_restrictions(self, app_client, db_session, monkeypatch, tmp_path):
        # Regression guard for the coupling bug this session already fixed
        # once for create_user/update_user (see
        # app_settings.migrate_decouple_portal_and_vpn_restrictions) --
        # link_vpn_profile must not re-introduce it.
        from vpnadmin import policy_store
        from vpnadmin.config import settings
        monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
        target = User(
            username="restrictedportal", password_hash="x", role=Role.viewer,
            restrict_login_by_country=True, allowed_login_countries='["PK"]',
        )
        db_session.add(target)
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=target.id, vpn_client_name="old-cert", link_source="manual_admin_link"))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/users/{target.id}/vpn-link", json={"vpn_client_name": "new-cert"})
        assert r.status_code == 201
        assert policy_store.get_policy("new-cert").get("allowed_countries") in (None, [])


class TestVpnUnlink:
    def test_clear_assignment(self, app_client, db_session):
        target = User(username="clearme", password_hash="x", role=Role.viewer)
        db_session.add(target)
        db_session.commit()
        db_session.add(VpnProfileLink(user_id=target.id, vpn_client_name="clearme-cert", link_source="manual_admin_link"))
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/users/{target.id}/vpn-link")
        assert r.status_code == 200
        assert r.json()["vpn_client_name"] is None
        assert db_session.query(VpnProfileLink).filter(VpnProfileLink.user_id == target.id).first() is None
        # Client itself still exists as far as this app's DB is concerned
        # (no VpnProfileLink row referencing it, i.e. unassigned) -- this
        # endpoint never touches cli_wrapper/the underlying cert.
        assert db_session.query(VpnProfileLink).filter(VpnProfileLink.vpn_client_name == "clearme-cert").first() is None

    def test_clear_with_no_link_rejected(self, app_client, db_session):
        target = User(username="nolinktoclear", password_hash="x", role=Role.viewer)
        db_session.add(target)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.delete(f"/api/users/{target.id}/vpn-link")
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
        db_session.add(VpnProfileLink(user_id=target.id, vpn_client_name="protected-cert", link_source="migration_exact_match", protected_from_auto_revoke=True))
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
