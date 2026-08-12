"""Tests for the new bulk-policies endpoint (GET /api/clients/policies,
added to power the All Clients table's per-row restriction badges) and for
the sequenced create-then-set-policy flow the Add Client form's new
collapsible "Add restrictions" panel drives client-side.

The actual sequencing (POST /api/clients, then conditionally PUT
.../policy) lives in templates/clients.html's submit handler -- there is no
new server-side behavior tying the two together. What's testable here is
that both existing endpoints keep behaving correctly when called
back-to-back for the same freshly-created client, exactly as the form now
does, and that the bulk endpoint reflects the result afterward.
"""
import pytest

import vpnadmin.routes.clients as clients_mod
from vpnadmin.config import settings

from .conftest import login


@pytest.fixture(autouse=True)
def _tmp_policy_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
    monkeypatch.setattr(settings, "CLIENT_USAGE_FILE", str(tmp_path / "client_usage.json"))


class TestBulkPolicies:
    def test_empty_by_default(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/clients/policies")
        assert r.status_code == 200
        assert r.json() == {"policies": {}, "usage": {}}

    def test_viewer_forbidden(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/clients/policies")
        assert r.status_code == 403

    def test_reflects_set_policy(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.put("/api/clients/zz-bulktest/policy", json={"allowed_countries": ["PK"]})
        assert r.status_code == 200
        r2 = app_client.get("/api/clients/policies")
        assert r2.status_code == 200
        assert r2.json()["policies"] == {"zz-bulktest": {"allowed_countries": ["PK"]}}

    def test_only_clients_with_a_restriction_appear(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.put("/api/clients/zz-restricted/policy", json={"bandwidth_monthly_gb": 5})
        r = app_client.get("/api/clients/policies")
        assert list(r.json()["policies"].keys()) == ["zz-restricted"]


class TestCreateThenPolicySequencing:
    """Mirrors what the Add form now does client-side after a successful
    create: PUT the same policy endpoint the "Manage Restrictions" dialog
    already uses, for the client that was just created."""

    def test_create_then_set_policy_round_trip(self, app_client, monkeypatch):
        monkeypatch.setattr(clients_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")

        r1 = app_client.post("/api/clients", json={"name": "zz-newclient", "mac": "aa:bb:cc:dd:ee:ff"})
        assert r1.status_code == 201

        r2 = app_client.put(
            "/api/clients/zz-newclient/policy",
            json={"allowed_countries": ["PK"], "allowed_os": ["windows", "linux"], "bandwidth_monthly_gb": 5},
        )
        assert r2.status_code == 200
        assert r2.json()["policy"] == {
            "allowed_countries": ["PK"],
            "allowed_os": ["linux", "windows"],
            "bandwidth_monthly_gb": 5.0,
        }

        r3 = app_client.get("/api/clients/zz-newclient/policy")
        assert r3.status_code == 200
        assert r3.json()["policy"]["allowed_countries"] == ["PK"]

    def test_policy_put_failure_does_not_undo_the_create(self, app_client, monkeypatch):
        """If the follow-up policy PUT fails (e.g. bad input), the client
        itself must remain created -- this is the API-level guarantee the
        client-side "Client created, but restrictions couldn't be saved..."
        toast message relies on rather than rolling anything back."""
        monkeypatch.setattr(clients_mod.cli, "add_client", lambda name, mac: f"{name} added.")
        login(app_client, "admin", "adminpass123")

        r1 = app_client.post("/api/clients", json={"name": "zz-badpolicy", "mac": "aa:bb:cc:dd:ee:ff"})
        assert r1.status_code == 201

        # 422, not 400: unlike the old `country` field (validated only
        # deep inside policy_store.set_policy), allowed_countries is now
        # validated at the Pydantic layer too (PolicyRequest's own
        # field_validator, same geo_validators.py rules) -- same 422
        # convention every other Pydantic-validated field in this app uses
        # (see test_password_policy_and_mac_validation.py).
        r2 = app_client.put("/api/clients/zz-badpolicy/policy", json={"allowed_countries": ["INVALID"]})
        assert r2.status_code == 422

        # No restriction was actually persisted for this client.
        r3 = app_client.get("/api/clients/zz-badpolicy/policy")
        assert r3.json()["policy"] == {}

    def test_viewer_cannot_do_either_step(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r1 = app_client.post("/api/clients", json={"name": "zz-viewer", "mac": "aa:bb:cc:dd:ee:ff"})
        assert r1.status_code == 403
        r2 = app_client.put("/api/clients/zz-viewer/policy", json={"allowed_countries": ["PK"]})
        assert r2.status_code == 403
