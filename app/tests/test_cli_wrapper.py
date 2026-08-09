"""
Tests for the subprocess wrapper around the two CLI tools. No real script is
invoked -- subprocess.run itself is monkeypatched, and every test asserts on
the exact argument list constructed, since that's the actual security
boundary (list args, never shell=True/string interpolation).
"""
import subprocess

import pytest

from vpnadmin import cli_wrapper as cw
from vpnadmin.config import settings


@pytest.fixture(autouse=True)
def _fixed_paths(monkeypatch):
    monkeypatch.setattr(settings, "USE_SUDO", True)
    monkeypatch.setattr(settings, "OPENVPN_INSTALL_SCRIPT", "/fake/openvpn-install.sh")
    monkeypatch.setattr(settings, "VPN_STATUS_SCRIPT", "/fake/vpn-status.py")


def _completed(args, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)


class TestArgumentConstruction:
    def test_list_clients_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            assert isinstance(args, list)
            assert kwargs.get("shell", False) is False
            return _completed(args, 0, "[]")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.list_clients()
        assert seen["args"] == ["sudo", "-n", "bash", "/fake/openvpn-install.sh", "--list-users", "--json"]

    def test_add_client_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "alice added.")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.add_client("alice", "aa:bb:cc:dd:ee:ff")
        assert seen["args"] == [
            "sudo", "-n", "bash", "/fake/openvpn-install.sh", "--add-user", "alice", "aa:bb:cc:dd:ee:ff",
        ]

    def test_status_rejected_args_include_limit(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "[]")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.status_rejected(limit=42)
        assert seen["args"] == [
            "sudo", "-n", "python3", "/fake/vpn-status.py", "--rejected-connections", "42", "--json",
        ]

    def test_no_sudo_when_use_sudo_false(self, monkeypatch):
        settings.USE_SUDO = False
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "[]")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.list_clients()
        assert seen["args"][0] != "sudo"
        settings.USE_SUDO = True  # restore for other tests in this module

    def test_add_mac_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "Added MAC for alice.")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.add_mac("alice", "aa:bb:cc:dd:ee:ff")
        assert seen["args"] == [
            "sudo", "-n", "bash", "/fake/openvpn-install.sh", "--add-mac", "alice", "aa:bb:cc:dd:ee:ff",
        ]

    def test_remove_mac_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "Removed MAC for alice.")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.remove_mac("alice", "aa:bb:cc:dd:ee:ff")
        assert seen["args"] == [
            "sudo", "-n", "bash", "/fake/openvpn-install.sh", "--remove-mac", "alice", "aa:bb:cc:dd:ee:ff",
        ]

    def test_show_ovpn_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "<ovpn file contents>")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = cw.show_ovpn("alice")
        assert seen["args"] == ["sudo", "-n", "bash", "/fake/openvpn-install.sh", "--show-ovpn", "alice"]
        assert result == "<ovpn file contents>"

    def test_purge_revoked_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "alice: purged.")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.purge_revoked("alice")
        assert seen["args"] == ["sudo", "-n", "bash", "/fake/openvpn-install.sh", "--purge-revoked", "alice"]

    def test_restore_client_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "alice added.")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.restore_client("alice", "aa:bb:cc:dd:ee:ff")
        assert seen["args"] == [
            "sudo", "-n", "bash", "/fake/openvpn-install.sh", "--restore", "alice", "aa:bb:cc:dd:ee:ff",
        ]

    def test_show_ovpn_failure_raises(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run",
            lambda args, **kw: _completed(args, 1, "", "alice: no .ovpn file found"),
        )
        with pytest.raises(cw.ScriptError, match="no .ovpn file found"):
            cw.show_ovpn("alice")

    def test_purge_revoked_failure_raises(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run",
            lambda args, **kw: _completed(args, 1, "", "alice: not a revoked client"),
        )
        with pytest.raises(cw.ScriptError, match="not a revoked client"):
            cw.purge_revoked("alice")

    def test_add_mac_failure_raises(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run",
            lambda args, **kw: _completed(args, 1, "", "alice is already registered with MAC aa:bb:cc:dd:ee:ff."),
        )
        with pytest.raises(cw.ScriptError, match="already registered"):
            cw.add_mac("alice", "aa:bb:cc:dd:ee:ff")

    def test_add_client_duplicate_mac_across_clients_raises_with_owner_name(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run",
            lambda args, **kw: _completed(
                args, 1, "", "MAC address aa:bb:cc:dd:ee:ff is already assigned to client 'bob'.",
            ),
        )
        with pytest.raises(cw.ScriptError, match="already assigned to client 'bob'"):
            cw.add_client("alice", "aa:bb:cc:dd:ee:ff")

    def test_add_mac_duplicate_across_clients_raises_with_owner_name(self, monkeypatch):
        # openvpn-install.sh's do_add_mac (and do_add_client) now reject a
        # MAC already assigned to a DIFFERENT client -- see find_mac_owner.
        # The script's exact wording is what routes/clients.py surfaces
        # verbatim as the toast message, so it's worth pinning here.
        monkeypatch.setattr(
            subprocess, "run",
            lambda args, **kw: _completed(
                args, 1, "", "MAC address aa:bb:cc:dd:ee:ff is already assigned to client 'bob'.",
            ),
        )
        with pytest.raises(cw.ScriptError, match="already assigned to client 'bob'"):
            cw.add_mac("alice", "aa:bb:cc:dd:ee:ff")


class TestCaching:
    def test_repeated_read_call_hits_cache_not_subprocess(self, monkeypatch):
        calls = {"n": 0}

        def fake_run(args, **kwargs):
            calls["n"] += 1
            return _completed(args, 0, "[]")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.list_clients()
        cw.list_clients()
        cw.list_clients()
        assert calls["n"] == 1

    def test_mutating_call_invalidates_related_cache(self, monkeypatch):
        calls = {"n": 0}

        def fake_run(args, **kwargs):
            calls["n"] += 1
            if "--add-user" in args:
                return _completed(args, 0, "alice added.")
            return _completed(args, 0, "[]")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.list_clients()  # cached now
        cw.add_client("alice", "aa:bb:cc:dd:ee:ff")  # should invalidate list_clients cache
        cw.list_clients()  # must re-spawn, not reuse the pre-add cached result
        assert calls["n"] == 3  # list, add, list again


class TestInjectionSafety:
    def test_malicious_looking_name_passed_as_single_inert_arg(self, monkeypatch):
        malicious = "name; rm -rf / #"

        def fake_run(args, **kwargs):
            assert malicious in args, "malicious string must arrive as one intact list element"
            assert kwargs.get("shell", False) is False
            return _completed(args, 1, "", "Invalid client name")

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(cw.ScriptError):
            cw.add_client(malicious, "aa:bb:cc:dd:ee:ff")


class TestErrorHandling:
    def test_nonzero_exit_raises_script_error(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda args, **kw: _completed(args, 1, "", "sudo: a password is required"))
        with pytest.raises(cw.ScriptError, match="password is required"):
            cw.list_clients()

    def test_invalid_json_raises_script_error(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda args, **kw: _completed(args, 0, "not json"))
        with pytest.raises(cw.ScriptError, match="valid JSON"):
            cw.list_clients()

    def test_timeout_raises_script_error(self, monkeypatch):
        def fake_run(args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args, timeout=30)
        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(cw.ScriptError, match="timed out"):
            cw.list_clients()

    def test_missing_binary_raises_script_error(self, monkeypatch):
        def fake_run(args, **kwargs):
            raise FileNotFoundError()
        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(cw.ScriptError, match="not found"):
            cw.list_clients()

    def test_macs_allows_nonzero_when_client_has_none(self, monkeypatch):
        # --macs exits 1 with valid JSON when a client has zero registered
        # MACs -- informative, not a failure.
        monkeypatch.setattr(
            subprocess, "run",
            lambda args, **kw: _completed(args, 1, '{"name":"bob","count":0,"macs":[]}'),
        )
        result = cw.list_macs("bob")
        assert result == {"name": "bob", "count": 0, "macs": []}

    def test_check_allows_nonzero_when_issues_found(self, monkeypatch):
        monkeypatch.setattr(
            subprocess, "run",
            lambda args, **kw: _completed(args, 1, '{"clean":false,"orphan_pki":["x"],"orphan_db":[]}'),
        )
        result = cw.check_consistency()
        assert result["clean"] is False
