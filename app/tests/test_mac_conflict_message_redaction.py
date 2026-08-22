"""A cross-client MAC conflict (openvpn-install.sh's do_add_mac, via
cli.add_mac's ScriptError) names the OTHER client that already holds the
MAC -- useful for an admin, but a privacy leak if a self-service "User"
role sees another account's VPN client name just by guessing at MAC
addresses. routes/me_vpn.py's add_my_mac redacts that name from the HTTP
response (never from the audit log, which stays admin-facing);
routes/clients.py's admin-only add_client_mac must keep the full detail
unchanged."""
from vpnadmin import cli_wrapper as cli
from vpnadmin.auth import hash_password
from vpnadmin.cli_wrapper import ScriptError
from vpnadmin.models import AuditLog, Group, RoleDef, User, VpnProfileLink

from .conftest import login


def _make_self_service_user(db_session, username, *, vpn_client_name=None, password="somepass123"):
    # Group-only permissions: a role only grants anything via group
    # membership now (see permissions.py's effective_role_ids).
    role = db_session.query(RoleDef).filter_by(slug="user").first()
    group = Group(name=f"{username}-user-group")
    group.role_defs.append(role)
    db_session.add(group)
    db_session.flush()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id)
    user.groups.append(group)
    db_session.add(user)
    db_session.commit()
    if vpn_client_name:
        db_session.add(VpnProfileLink(user_id=user.id, vpn_client_name=vpn_client_name, link_source="created_with_profile"))
        db_session.commit()
    return user


def _fail_with_conflict(name, mac):
    raise ScriptError(f"MAC address {mac} is already assigned to client 'bob'.")


class TestSelfServiceMacConflictRedaction:
    def test_cross_client_conflict_hides_other_clients_name(self, app_client, db_session, monkeypatch):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        monkeypatch.setattr(cli, "add_mac", _fail_with_conflict)
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/vpn-profile/macs", json={"mac": "AA:BB:CC:DD:EE:FF"})
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert "bob" not in detail
        assert "another account" in detail
        assert "aa:bb:cc:dd:ee:ff" in detail or "AA:BB:CC:DD:EE:FF" in detail

    def test_audit_log_still_records_the_full_detail(self, app_client, db_session, monkeypatch):
        # The redaction is HTTP-response-only -- an admin reviewing the
        # audit trail (Users Activity) must still see which other client's
        # MAC actually collided.
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        monkeypatch.setattr(cli, "add_mac", _fail_with_conflict)
        login(app_client, "alice", "somepass123")
        app_client.post("/api/me/vpn-profile/macs", json={"mac": "AA:BB:CC:DD:EE:FF"})
        entry = db_session.query(AuditLog).filter_by(action="self_add_mac", success=False).first()
        assert entry is not None
        assert "bob" in entry.detail

    def test_non_conflict_errors_are_left_untouched(self, app_client, db_session, monkeypatch):
        # Only the specific "already assigned to client '<name>'" shape is
        # redacted -- an invalid-format or self-conflict message names
        # nothing but the caller's own input/profile and must pass through
        # verbatim, unmodified.
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")

        def _fail_invalid(name, mac):
            raise ScriptError(f"Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff), got '{mac}'.")

        monkeypatch.setattr(cli, "add_mac", _fail_invalid)
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/vpn-profile/macs", json={"mac": "AA:BB:CC:DD:EE:FF"})
        assert r.status_code == 400
        assert r.json()["detail"] == "Invalid MAC address: expected 12 hex characters (e.g. aa:bb:cc:dd:ee:ff), got 'AA:BB:CC:DD:EE:FF'."


class TestAdminMacConflictMessageUnchanged:
    def test_admin_endpoint_still_sees_the_other_clients_name(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(cli, "add_mac", _fail_with_conflict)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/alice/macs", json={"mac": "AA:BB:CC:DD:EE:FF"})
        assert r.status_code == 400
        assert "bob" in r.json()["detail"]
