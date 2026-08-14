"""Covers this round's additions: password complexity policy (min length +
uppercase + digit + special character, enforced on create/reset/change) and
MAC address format validation (routes/users.py's/routes/clients.py's shared
_valid_mac_format, both backed by services.openvpn.validator.normalize_mac)."""

from vpnadmin.models import User

from .conftest import login


class TestPasswordComplexityPolicy:
    def test_create_user_rejects_password_missing_uppercase(self, app_client, monkeypatch):
        from vpnadmin.routes import users as users_mod

        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "weakpwuser",
                "password": "lowercase123!",
                "first_name": "Weak",
                "email": "weakpwuser@example.com",
                "mac": "aa:bb:cc:dd:ee:01",
            },
        )
        assert r.status_code == 422
        assert "uppercase" in str(r.json()).lower()

    def test_create_user_rejects_password_missing_special_char(self, app_client, monkeypatch):
        from vpnadmin.routes import users as users_mod

        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "nospecialuser",
                "password": "Lowercase123",
                "first_name": "NoSpecial",
                "email": "nospecialuser@example.com",
                "mac": "aa:bb:cc:dd:ee:02",
            },
        )
        assert r.status_code == 422
        assert "special character" in str(r.json()).lower()

    def test_create_user_rejects_password_missing_digit(self, app_client, monkeypatch):
        from vpnadmin.routes import users as users_mod

        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "nodigituser",
                "password": "Nodigitpass!",
                "first_name": "NoDigit",
                "email": "nodigituser@example.com",
                "mac": "aa:bb:cc:dd:ee:03",
            },
        )
        assert r.status_code == 422
        assert "number" in str(r.json()).lower()

    def test_create_user_accepts_compliant_password(self, app_client, monkeypatch):
        from vpnadmin.routes import users as users_mod

        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "goodpwuser",
                "password": "Goodpass123!",
                "first_name": "Good",
                "email": "goodpwuser@example.com",
                "mac": "aa:bb:cc:dd:ee:04",
            },
        )
        assert r.status_code == 201

    def test_admin_reset_rejects_noncompliant_password(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        viewer_id = db_session.query(User).filter(User.username == "viewer").one().id
        r = app_client.patch(f"/api/users/{viewer_id}", json={"password": "allweak"})
        assert r.status_code == 422

    def test_self_service_password_change_rejects_noncompliant_password(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.patch(
            "/api/users/me",
            json={
                "current_password": "viewerpass123",
                "new_password": "allweak",
            },
        )
        assert r.status_code == 422


class TestMacFormatValidation:
    def test_create_user_rejects_malformed_mac(self, app_client, monkeypatch):
        from vpnadmin.routes import users as users_mod

        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "badmacuser",
                "password": "Goodpass123!",
                "first_name": "BadMac",
                "email": "badmacuser@example.com",
                "mac": "not-a-mac-address",
            },
        )
        assert r.status_code == 422
        assert "mac address" in str(r.json()).lower()

    def test_create_user_normalizes_mac_with_mixed_separators(self, app_client, monkeypatch):
        from vpnadmin.routes import users as users_mod

        captured = {}
        monkeypatch.setattr(users_mod.cli, "add_client", lambda name, mac: captured.setdefault("mac", mac) or f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/users",
            json={
                "username": "normmacuser",
                "password": "Goodpass123!",
                "first_name": "Norm",
                "email": "normmacuser@example.com",
                "mac": "AA-BB-CC-DD-EE-FF",
            },
        )
        assert r.status_code == 201
        assert captured["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_add_client_mac_endpoint_rejects_malformed_mac(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/someclient/macs", json={"mac": "zz:zz:zz:zz:zz:zz"})
        assert r.status_code == 422
