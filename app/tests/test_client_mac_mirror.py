"""Tests for models.ClientMac -- the queryable DB mirror of openvpn_db.txt
(client_mac_mirror.py), and the new registered_mac_at_time field on
models.ConnectionRejectionLog / the host ingestion endpoint. The mirror is
never the connect-time enforcement source (that stays the flat file, read
directly by host-scripts/openvpn-mac-addr-check.py) -- these tests only
cover the app-side write/resync paths."""
from vpnadmin import cli_wrapper as cli
from vpnadmin.auth import hash_password
from vpnadmin.client_mac_mirror import record_mac_added, record_mac_removed, resync_client_macs
from vpnadmin.config import settings
from vpnadmin.models import ClientMac, ConnectionRejectionLog, Group, RoleDef, User, VpnProfileLink

from .conftest import login


def _make_self_service_user(db_session, username, *, vpn_client_name=None, password="somepass123"):
    # Group-only permissions: a role only grants anything via group
    # membership now (see permissions.py's effective_role_ids).
    role = db_session.query(RoleDef).filter_by(slug="user").first()
    group = Group(name=f"{username}-user-group", role_id=role.id)
    db_session.add(group)
    db_session.flush()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id, group_id=group.id)
    db_session.add(user)
    db_session.commit()
    if vpn_client_name:
        db_session.add(VpnProfileLink(user_id=user.id, vpn_client_name=vpn_client_name, link_source="created_with_profile"))
        db_session.commit()
    return user


class TestRecordMacHelpers:
    def test_record_mac_added_inserts_row(self, db_session):
        record_mac_added(db_session, "alice", "AA:BB:CC:DD:EE:FF")
        rows = db_session.query(ClientMac).all()
        assert len(rows) == 1
        assert rows[0].vpn_client_name == "alice"
        assert rows[0].mac == "aa:bb:cc:dd:ee:ff"  # normalized lowercase

    def test_record_mac_added_is_idempotent(self, db_session):
        record_mac_added(db_session, "alice", "AA:BB:CC:DD:EE:FF")
        record_mac_added(db_session, "alice", "aa:bb:cc:dd:ee:ff")  # same MAC, different case
        assert db_session.query(ClientMac).count() == 1

    def test_record_mac_removed_deletes_row(self, db_session):
        record_mac_added(db_session, "alice", "AA:BB:CC:DD:EE:FF")
        record_mac_removed(db_session, "alice", "aa:bb:cc:dd:ee:ff")
        assert db_session.query(ClientMac).count() == 0

    def test_record_mac_removed_only_affects_matching_row(self, db_session):
        record_mac_added(db_session, "alice", "AA:BB:CC:DD:EE:FF")
        record_mac_added(db_session, "bob", "11:22:33:44:55:66")
        record_mac_removed(db_session, "alice", "aa:bb:cc:dd:ee:ff")
        remaining = db_session.query(ClientMac).all()
        assert len(remaining) == 1
        assert remaining[0].vpn_client_name == "bob"


class TestResyncClientMacs:
    def test_backfills_from_empty(self, db_session):
        resync_client_macs(db_session, {"alice": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"], "bob": ["77:88:99:aa:bb:cc"]})
        rows = {(r.vpn_client_name, r.mac) for r in db_session.query(ClientMac).all()}
        assert rows == {
            ("alice", "aa:bb:cc:dd:ee:ff"),
            ("alice", "11:22:33:44:55:66"),
            ("bob", "77:88:99:aa:bb:cc"),
        }

    def test_deletes_rows_no_longer_in_file(self, db_session):
        record_mac_added(db_session, "alice", "aa:bb:cc:dd:ee:ff")
        record_mac_added(db_session, "bob", "11:22:33:44:55:66")
        resync_client_macs(db_session, {"alice": ["aa:bb:cc:dd:ee:ff"]})  # bob's MAC hand-removed from the file
        rows = {(r.vpn_client_name, r.mac) for r in db_session.query(ClientMac).all()}
        assert rows == {("alice", "aa:bb:cc:dd:ee:ff")}

    def test_inserts_rows_added_outside_the_app(self, db_session):
        # Simulates the file being hand-edited (SSH, setup.sh) -- the
        # mirror must pick up entries it never wrote itself.
        resync_client_macs(db_session, {"carol": ["de:ad:be:ef:00:01"]})
        rows = db_session.query(ClientMac).all()
        assert len(rows) == 1
        assert rows[0].vpn_client_name == "carol"

    def test_empty_file_clears_the_mirror(self, db_session):
        record_mac_added(db_session, "alice", "aa:bb:cc:dd:ee:ff")
        resync_client_macs(db_session, {})
        assert db_session.query(ClientMac).count() == 0


class TestAdminAddRemoveMacMirrors:
    def test_add_client_mac_writes_mirror_row(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(cli, "add_mac", lambda name, mac: "added")
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/alice/macs", json={"mac": "AA:BB:CC:DD:EE:FF"})
        assert r.status_code == 201
        rows = db_session.query(ClientMac).all()
        assert len(rows) == 1
        assert rows[0].vpn_client_name == "alice"
        assert rows[0].mac == "aa:bb:cc:dd:ee:ff"

    def test_add_client_mac_failure_does_not_write_mirror_row(self, app_client, db_session, monkeypatch):
        from vpnadmin.cli_wrapper import ScriptError

        def _fail(name, mac):
            raise ScriptError("nope")
        monkeypatch.setattr(cli, "add_mac", _fail)
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/clients/alice/macs", json={"mac": "AA:BB:CC:DD:EE:FF"})
        assert r.status_code == 400
        assert db_session.query(ClientMac).count() == 0

    def test_remove_client_mac_deletes_mirror_row(self, app_client, db_session, monkeypatch):
        record_mac_added(db_session, "alice", "aa:bb:cc:dd:ee:ff")
        monkeypatch.setattr(cli, "remove_mac", lambda name, mac: "removed")
        login(app_client, "admin", "adminpass123")
        r = app_client.delete("/api/clients/alice/macs/aa:bb:cc:dd:ee:ff")
        assert r.status_code == 200
        assert db_session.query(ClientMac).count() == 0


class TestSelfServiceAddRemoveMacMirrors:
    def test_add_my_mac_writes_mirror_row(self, app_client, db_session, monkeypatch):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        monkeypatch.setattr(cli, "add_mac", lambda name, mac: "added")
        login(app_client, "alice", "somepass123")
        r = app_client.post("/api/me/vpn-profile/macs", json={"mac": "AA:BB:CC:DD:EE:FF"})
        assert r.status_code == 201
        rows = db_session.query(ClientMac).all()
        assert len(rows) == 1
        assert rows[0].vpn_client_name == "alice"

    def test_remove_my_mac_deletes_mirror_row(self, app_client, db_session, monkeypatch):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        record_mac_added(db_session, "alice", "aa:bb:cc:dd:ee:ff")
        monkeypatch.setattr(cli, "remove_mac", lambda name, mac: "removed")
        login(app_client, "alice", "somepass123")
        r = app_client.delete("/api/me/vpn-profile/macs/aa:bb:cc:dd:ee:ff")
        assert r.status_code == 200
        assert db_session.query(ClientMac).count() == 0


class TestRegisteredMacAtTimeIngestion:
    def test_ingest_persists_registered_mac_at_time(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(settings, "HOST_INGEST_TOKEN", "correct-token")
        r = app_client.post(
            "/internal/connection-rejections",
            json={
                "vpn_client_name": "alice",
                "reason": "mac_mismatch",
                "detected_mac": "AA:BB:CC:DD:EE:FF",
                "registered_mac": "11:22:33:44:55:66",
            },
            headers={"Authorization": "Bearer correct-token"},
        )
        assert r.status_code == 201
        row = db_session.query(ConnectionRejectionLog).first()
        assert row.registered_mac_at_time == "11:22:33:44:55:66"

    def test_ingest_without_registered_mac_is_null(self, app_client, db_session, monkeypatch):
        monkeypatch.setattr(settings, "HOST_INGEST_TOKEN", "correct-token")
        r = app_client.post(
            "/internal/connection-rejections",
            json={"vpn_client_name": "alice", "reason": "country_not_allowed"},
            headers={"Authorization": "Bearer correct-token"},
        )
        assert r.status_code == 201
        row = db_session.query(ConnectionRejectionLog).first()
        assert row.registered_mac_at_time is None

    def test_registered_mac_at_time_surfaced_in_my_connection_issues(self, app_client, db_session, monkeypatch):
        _make_self_service_user(db_session, "alice", vpn_client_name="alice")
        db_session.add(ConnectionRejectionLog(vpn_client_name="alice", reason="mac_mismatch",
                                               detected_mac="aa:bb:cc:dd:ee:ff", registered_mac_at_time="not registered"))
        db_session.commit()
        login(app_client, "alice", "somepass123")
        data = app_client.get("/api/me/connection-issues").json()
        assert data["history"][0]["registered_mac_at_time"] == "not registered"
