"""Tests for the .ovpn view/copy and email-delivery client actions."""
import vpnadmin.routes.clients as clients_mod

from .conftest import login


class TestClientsPageRenders:
    """Catches Jinja/markup errors in clients.html -- e.g. the Email
    Profile dialog's user-picker section and the detail panel's Close
    button, both added without their own template-render test elsewhere."""

    def test_admin_view(self, app_client, monkeypatch):
        monkeypatch.setattr(clients_mod.cli, "get_clients_snapshot", lambda: [])
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/clients")
        assert r.status_code == 200
        assert "email-user-picker" in r.text

    def test_viewer_view(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/clients")
        assert r.status_code == 200
        # Admin-only dialog MARKUP (email/policy/ovpn) isn't rendered for
        # a viewer at all -- see clients.html's {% if can_manage_clients %}
        # around the <dialog> elements themselves. The JS that operates
        # them, further down in the same file's {% block scripts %}, ships
        # in every page's payload regardless of role either way (same
        # pre-existing shape as showOvpn/openPolicyDialog -- this app
        # doesn't split its JS bundle per role, only the DOM elements
        # those functions target), so it isn't what this test checks.
        assert 'id="email-dialog"' not in r.text


class TestShowOvpn:
    def test_admin_can_fetch_ovpn_content(self, app_client, monkeypatch):
        monkeypatch.setattr(clients_mod.cli, "show_ovpn", lambda name: "client\ndev tun\n...")
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/clients/alice/ovpn")
        assert r.status_code == 200
        assert "client" in r.json()["ovpn"]

    def test_viewer_cannot_fetch_ovpn_content(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/clients/alice/ovpn")
        assert r.status_code == 403

    def test_invalid_name_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/clients/bad%20name/ovpn")
        assert r.status_code == 400


class TestEmailOvpn:
    def test_not_configured_returns_400(self, app_client, monkeypatch):
        monkeypatch.setattr(clients_mod.cli, "show_ovpn", lambda name: "content")
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/alice/email-ovpn", json={"email": "user@example.com"})
        assert r.status_code == 400
        assert "no outbound email provider" in r.json()["detail"].lower()

    def test_invalid_email_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/alice/email-ovpn", json={"email": "not-an-email"})
        assert r.status_code == 422

    def test_success_path_sends_mail(self, app_client, monkeypatch):
        # is_configured(db) is now a live EmailProvider-table check (see
        # mailer._resolve_default_provider) rather than a runtime.smtp_host
        # read -- bypassed directly here, same "replace the function under
        # test" pattern already used for send_ovpn_profile below, rather
        # than creating a real EmailProvider row this test doesn't
        # otherwise need.
        monkeypatch.setattr(clients_mod.mailer, "is_configured", lambda db: True)
        monkeypatch.setattr(clients_mod.cli, "show_ovpn", lambda name: "content")

        sent = {}

        def fake_send(*, db, to_address, client_name, ovpn_content):
            sent["to"] = to_address
            sent["name"] = client_name

        monkeypatch.setattr(clients_mod.mailer, "send_ovpn_profile", fake_send)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/alice/email-ovpn", json={"email": "user@example.com"})
        assert r.status_code == 200
        assert sent == {"to": "user@example.com", "name": "alice"}

    def test_viewer_cannot_email_ovpn(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/clients/alice/email-ovpn", json={"email": "user@example.com"})
        assert r.status_code == 403


class TestRevokedCleanup:
    def test_bulk_purge_reports_per_item_results(self, app_client, monkeypatch):
        def fake_purge(name):
            if name == "bad":
                from vpnadmin.cli_wrapper import ScriptError
                raise ScriptError("not a revoked client")
            return f"{name}: purged."

        monkeypatch.setattr(clients_mod.cli, "purge_revoked", fake_purge)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/revoked/purge", json={"names": ["alice", "bad"]})
        assert r.status_code == 200
        results = {row["name"]: row["ok"] for row in r.json()["results"]}
        assert results == {"alice": True, "bad": False}

    def test_viewer_cannot_purge(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/clients/revoked/purge", json={"names": ["alice"]})
        assert r.status_code == 403

    def test_restore_client(self, app_client, monkeypatch):
        monkeypatch.setattr(clients_mod.cli, "restore_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/revoked/alice/restore", json={"mac": "aa:bb:cc:dd:ee:ff"})
        assert r.status_code == 200

    def test_viewer_cannot_restore(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post("/api/clients/revoked/alice/restore", json={"mac": "aa:bb:cc:dd:ee:ff"})
        assert r.status_code == 403
