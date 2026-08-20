"""
Tests for vpn-status.py's rejected-connection log parsing -- specifically
the "reason" field added alongside the per-client restriction feature (see
host-scripts/openvpn-mac-addr-check.py). Imports vpn-status.py (a
hyphenated filename, not a normal importable module) directly from the
repo root via importlib.

These are pure parsing-logic tests against synthetic log text -- no real
OpenVPN install, root access, or subprocess involved.
"""
import importlib.util
import os
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_VPN_STATUS_PATH = os.path.join(_REPO_ROOT, "vpn-status.py")


def _load_vpn_status():
    spec = importlib.util.spec_from_file_location("vpn_status_under_test", _VPN_STATUS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def vpn_status(tmp_path, monkeypatch):
    mod = _load_vpn_status()
    # Point every path this module reads at an empty tmp location so
    # nothing here ever touches a real host file.
    mod.CONN_LOG = str(tmp_path / "openvpn.log")
    mod.STATUS_LOG = str(tmp_path / "openvpn-status.log")
    mod.DB_FILE = str(tmp_path / "openvpn_db.txt")
    return mod


OLD_FORMAT_MAC_MISMATCH_BLOCK = """---------------------------------------
2026-01-01T00:00:00
---------------------------------------
common_name: alice
IV_HWADDR: aa:bb:cc:dd:ee:ff
IV_PLAT: linux
trusted_ip: 203.0.113.5
time_unix: 1767225600

The MAC address of the client machine could not be found in the database

"""

NEW_FORMAT_OS_REJECTION_BLOCK = """---------------------------------------
2026-01-02T00:00:00
---------------------------------------
common_name: bob
IV_HWADDR: 11:22:33:44:55:66
IV_PLAT: mac
trusted_ip: 203.0.113.6
time_unix: 1767312000
reason: os_not_allowed

OpenVPN connection rejected: client OS 'mac' is not in bob's allowed OS list (linux, windows)

"""

MATCHED_BLOCK = """---------------------------------------
2026-01-03T00:00:00
---------------------------------------
common_name: carol
IV_HWADDR: 77:88:99:aa:bb:cc
IV_PLAT: windows
trusted_ip: 203.0.113.7
time_unix: 1767398400

The MAC address of the client machine has been successfully matched to the database

"""


def _write_log(vpn_status, content):
    with open(vpn_status.CONN_LOG, "w") as f:
        f.write(content)


class TestIterEnvBlocks:
    def test_old_format_block_has_no_reason_key(self, vpn_status):
        _write_log(vpn_status, OLD_FORMAT_MAC_MISMATCH_BLOCK)
        blocks = list(vpn_status.iter_env_blocks())
        assert len(blocks) == 1
        assert blocks[0]["matched"] is False
        assert "reason" not in blocks[0]

    def test_new_format_block_captures_reason(self, vpn_status):
        _write_log(vpn_status, NEW_FORMAT_OS_REJECTION_BLOCK)
        blocks = list(vpn_status.iter_env_blocks())
        assert len(blocks) == 1
        assert blocks[0]["matched"] is False
        assert blocks[0]["reason"] == "os_not_allowed"

    def test_matched_block_is_not_flagged_as_rejected(self, vpn_status):
        _write_log(vpn_status, MATCHED_BLOCK)
        blocks = list(vpn_status.iter_env_blocks())
        assert len(blocks) == 1
        assert blocks[0]["matched"] is True

    def test_mixed_log_parses_all_three(self, vpn_status):
        _write_log(vpn_status, OLD_FORMAT_MAC_MISMATCH_BLOCK + NEW_FORMAT_OS_REJECTION_BLOCK + MATCHED_BLOCK)
        blocks = list(vpn_status.iter_env_blocks())
        assert len(blocks) == 3
        assert [b["matched"] for b in blocks] == [False, False, True]


class TestCmdRejectedReasonDefault:
    def test_missing_reason_defaults_to_mac_mismatch(self, vpn_status, capsys):
        _write_log(vpn_status, OLD_FORMAT_MAC_MISMATCH_BLOCK)
        vpn_status.cmd_rejected(20, as_json=True)
        import json
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1
        assert rows[0]["reason"] == "mac_mismatch"

    def test_new_reason_is_passed_through(self, vpn_status, capsys):
        _write_log(vpn_status, NEW_FORMAT_OS_REJECTION_BLOCK)
        vpn_status.cmd_rejected(20, as_json=True)
        import json
        rows = json.loads(capsys.readouterr().out)
        assert len(rows) == 1
        assert rows[0]["reason"] == "os_not_allowed"


FROZEN_MAC_MISMATCH_BLOCK = """---------------------------------------
2026-01-04T00:00:00
---------------------------------------
common_name: dave
IV_HWADDR: aa:bb:cc:dd:ee:ff
IV_PLAT: linux
trusted_ip: 203.0.113.8
time_unix: 1767484800
reason: mac_mismatch
registered_mac_at_time: none

The MAC address of the client machine could not be found in the database

"""


class TestCmdRejectedMacRegistered:
    """Regression guard for the "now matches -- likely fixed" fix -- see
    models.ConnectionRejectionLog.registered_mac_at_time's docstring and
    diagnostics.html's rendering logic."""

    def test_old_format_row_falls_back_to_live_lookup(self, vpn_status, capsys):
        # No registered_mac_at_time line at all (predates the feature) --
        # must fall back to a live lookup against DB_FILE, flagged as such.
        _write_log(vpn_status, OLD_FORMAT_MAC_MISMATCH_BLOCK)
        with open(vpn_status.DB_FILE, "w") as f:
            f.write("alice=aa:bb:cc:dd:ee:ff\n")  # registered AFTER the fact
        vpn_status.cmd_rejected(20, as_json=True)
        import json
        rows = json.loads(capsys.readouterr().out)
        assert rows[0]["mac_registered"] == "aa:bb:cc:dd:ee:ff"
        assert rows[0]["mac_registered_is_live"] is True

    def test_new_format_row_uses_frozen_value_not_live_file(self, vpn_status, capsys):
        # The file NOW has this MAC registered, but the row was frozen at
        # rejection time as "none" -- the historical fact must win, not a
        # live re-check that would make it look retroactively "fixed".
        _write_log(vpn_status, FROZEN_MAC_MISMATCH_BLOCK)
        with open(vpn_status.DB_FILE, "w") as f:
            f.write("dave=aa:bb:cc:dd:ee:ff\n")
        vpn_status.cmd_rejected(20, as_json=True)
        import json
        rows = json.loads(capsys.readouterr().out)
        assert rows[0]["mac_registered"] == "not registered"
        assert rows[0]["mac_registered_is_live"] is False

    def test_frozen_value_reflects_what_was_actually_registered(self, vpn_status, capsys):
        block = FROZEN_MAC_MISMATCH_BLOCK.replace(
            "registered_mac_at_time: none", "registered_mac_at_time: 11:22:33:44:55:66")
        _write_log(vpn_status, block)
        vpn_status.cmd_rejected(20, as_json=True)
        import json
        rows = json.loads(capsys.readouterr().out)
        assert rows[0]["mac_registered"] == "11:22:33:44:55:66"
        assert rows[0]["mac_registered_is_live"] is False


def _write_status(vpn_status, real_address, name="alice"):
    content = (
        "TITLE,OpenVPN 2.7.0\n"
        "TIME,2026-08-20 16:00:00,1787241600\n"
        "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,"
        "Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\n"
        f"CLIENT_LIST,{name},{real_address},10.8.0.4,,88200,65200,"
        "2026-08-20 16:06:00,1787242560,UNDEF,1,1,AES-256-GCM\n"
        "END\n"
    )
    with open(vpn_status.STATUS_LOG, "w") as f:
        f.write(content)


class TestParseRealAddressIp:
    """Regression guard for the Source IP showing the literal string
    "udp4" bug -- CLIENT_LIST's Real Address field is "proto:ip:port" on
    this OpenVPN version, not plain "ip:port". See
    app/services/openvpn/management_client.py's parse_source_ip(), the
    app-side counterpart to this same fix."""

    def test_ipv4_with_proto_prefix(self, vpn_status):
        assert vpn_status.parse_real_address_ip("udp4:182.185.203.112:53266") == "182.185.203.112"

    def test_tcp_prefix(self, vpn_status):
        assert vpn_status.parse_real_address_ip("tcp4:203.0.113.5:1194") == "203.0.113.5"

    def test_bracketed_ipv6_with_proto_prefix(self, vpn_status):
        assert vpn_status.parse_real_address_ip("tcp6:[2001:db8::1]:1194") == "2001:db8::1"

    def test_plain_ip_port_no_proto_prefix(self, vpn_status):
        # Defensive: older OpenVPN versions/status-log formats that never
        # had the proto prefix at all must keep working unchanged.
        assert vpn_status.parse_real_address_ip("203.0.113.5:1194") == "203.0.113.5"

    def test_get_connected_reports_real_ip_not_protocol(self, vpn_status):
        _write_status(vpn_status, "udp4:182.185.203.112:53266")
        rows = vpn_status.get_connected()
        assert len(rows) == 1
        assert rows[0]["source_ip"] == "182.185.203.112"
        assert rows[0]["source_ip"] != "udp4"

    def test_cmd_connected_json_reports_real_ip(self, vpn_status, capsys):
        _write_status(vpn_status, "udp4:182.185.203.112:53266")
        vpn_status.cmd_connected(as_json=True)
        import json
        rows = json.loads(capsys.readouterr().out)
        assert rows[0]["source_ip"] == "182.185.203.112"

    def test_cmd_all_json_reports_real_ip_for_online_client(self, vpn_status, capsys):
        with open(vpn_status.DB_FILE, "w") as f:
            f.write("alice=aa:bb:cc:dd:ee:ff\n")
        _write_status(vpn_status, "udp4:182.185.203.112:53266")
        vpn_status.cmd_all(as_json=True)
        import json
        rows = json.loads(capsys.readouterr().out)
        online = next(r for r in rows if r["name"] == "alice")
        assert online["status"] == "online"
        assert online["source_ip"] == "182.185.203.112"
