"""Tests for the OpenVPN Install page's access controls (see
routes/openvpn_install.py's module docstring):
  1. Bootstrap-admin-only, layered on top of the ordinary openvpn_install/
     execute RBAC check -- even another Admin-role account is refused.
  2. Step-up re-auth ("elevated" session flag) -- being the bootstrap admin
     isn't enough on its own; /api/openvpn/* requires a fresh password
     confirmation via /api/openvpn/verify-access first.
Uses the shared app_client fixture (see conftest.py) -- host_executor itself
is never exercised here (HOST_SSH_TARGET stays unset), these tests only
cover what happens before a real SSH call would be attempted.
"""

from vpnadmin.auth import hash_password
from vpnadmin.models import RoleDef, User

from .conftest import login


def _make_admin(db_session, username, *, is_bootstrap_admin, password="somepass123"):
    role = db_session.query(RoleDef).filter_by(slug="admin").first()
    user = User(
        username=username,
        password_hash=hash_password(password),
        role_id=role.id,
        is_bootstrap_admin=is_bootstrap_admin,
    )
    db_session.add(user)
    db_session.commit()
    return user


class TestBootstrapAdminOnly:
    def test_non_bootstrap_admin_gets_403_on_page(self, app_client, db_session):
        _make_admin(db_session, "regular_admin", is_bootstrap_admin=False)
        login(app_client, "regular_admin", "somepass123")
        resp = app_client.get("/openvpn-install", follow_redirects=False)
        assert resp.status_code == 303  # redirected home -- not the bootstrap admin

    def test_non_bootstrap_admin_gets_403_on_api(self, app_client, db_session):
        _make_admin(db_session, "regular_admin2", is_bootstrap_admin=False)
        login(app_client, "regular_admin2", "somepass123")
        resp = app_client.get("/api/openvpn/status")
        assert resp.status_code == 403
        assert "bootstrap admin" in resp.json()["detail"].lower()

    def test_bootstrap_admin_can_reach_page(self, app_client, db_session):
        _make_admin(db_session, "boot_admin", is_bootstrap_admin=True)
        login(app_client, "boot_admin", "somepass123")
        resp = app_client.get("/openvpn-install")
        assert resp.status_code == 200


class TestStepUpReauth:
    def test_bootstrap_admin_not_yet_elevated_gets_403_on_api(self, app_client, db_session):
        _make_admin(db_session, "boot_admin2", is_bootstrap_admin=True)
        login(app_client, "boot_admin2", "somepass123")
        resp = app_client.get("/api/openvpn/status")
        assert resp.status_code == 403
        assert "re-enter your password" in resp.json()["detail"].lower()

    def test_verify_access_wrong_password_rejected(self, app_client, db_session):
        _make_admin(db_session, "boot_admin3", is_bootstrap_admin=True)
        login(app_client, "boot_admin3", "somepass123")
        resp = app_client.post("/api/openvpn/verify-access", json={"password": "wrongpassword"})
        assert resp.status_code == 401

    def test_verify_access_correct_password_elevates(self, app_client, db_session):
        _make_admin(db_session, "boot_admin4", is_bootstrap_admin=True)
        login(app_client, "boot_admin4", "somepass123")
        resp = app_client.post("/api/openvpn/verify-access", json={"password": "somepass123"})
        assert resp.status_code == 200
        assert resp.json()["elevated"] is True

        # Now elevated -- host executor still isn't configured in tests, but
        # that's a 400 from _host_executor_config, not the 403 the
        # elevation gate itself would raise -- proves the gate passed.
        status_resp = app_client.get("/api/openvpn/status")
        assert status_resp.json() == {"configured": False}

    def test_non_bootstrap_admin_cannot_verify_access(self, app_client, db_session):
        _make_admin(db_session, "regular_admin3", is_bootstrap_admin=False)
        login(app_client, "regular_admin3", "somepass123")
        resp = app_client.post("/api/openvpn/verify-access", json={"password": "somepass123"})
        assert resp.status_code == 403


class TestInstallFirstClientOptional:
    """First client is now optional (task feedback: "OpenVPN installation
    can proceed without creating an initial client") -- see
    routes/openvpn_install.py's post_install. mac/client_name are only
    cross-required of each other, never unconditionally required."""

    def _elevated_client(self, app_client, db_session, username="boot_admin5"):
        _make_admin(db_session, username, is_bootstrap_admin=True)
        login(app_client, username, "somepass123")
        assert app_client.post("/api/openvpn/verify-access", json={"password": "somepass123"}).status_code == 200
        return app_client

    def test_install_with_no_client_fields_passes_validation(self, app_client, db_session):
        # No mac/client_name at all -- valid (no first client requested).
        # HOST_SSH_TARGET is unset in tests, so this reaches (and stops at)
        # the host-executor-not-configured 400, proving mac/client_name
        # validation itself didn't reject the request.
        client = self._elevated_client(app_client, db_session)
        resp = client.post("/api/openvpn/install")
        assert resp.status_code == 400
        assert "host executor is not configured" in resp.json()["detail"].lower()

    def test_client_name_without_mac_is_400(self, app_client, db_session):
        client = self._elevated_client(app_client, db_session, "boot_admin6")
        resp = client.post("/api/openvpn/install?client_name=client")
        assert resp.status_code == 400
        assert "mac address is required" in resp.json()["detail"].lower()

    def test_blank_mac_with_client_name_is_400(self, app_client, db_session):
        client = self._elevated_client(app_client, db_session, "boot_admin6b")
        resp = client.post("/api/openvpn/install?client_name=client&mac=%20%20")
        assert resp.status_code == 400
        assert "mac address is required" in resp.json()["detail"].lower()

    def test_mac_without_client_name_is_400(self, app_client, db_session):
        client = self._elevated_client(app_client, db_session, "boot_admin7")
        resp = client.post("/api/openvpn/install?mac=aa:bb:cc:dd:ee:ff")
        assert resp.status_code == 400
        assert "client name is required" in resp.json()["detail"].lower()

    def test_invalid_mac_format_with_client_name_is_400(self, app_client, db_session):
        client = self._elevated_client(app_client, db_session, "boot_admin8")
        resp = client.post("/api/openvpn/install?client_name=client&mac=not-a-mac")
        assert resp.status_code == 400
        assert "invalid mac address" in resp.json()["detail"].lower()
