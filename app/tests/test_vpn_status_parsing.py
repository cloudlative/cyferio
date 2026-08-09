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
