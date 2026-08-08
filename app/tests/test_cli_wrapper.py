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
        assert seen["args"] == ["sudo", "-n", "bash", "/fake/openvpn-install.sh", "--list", "--json"]

    def test_add_client_args(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "alice added.")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.add_client("alice", "aa:bb:cc:dd:ee:ff")
        assert seen["args"] == [
            "sudo", "-n", "bash", "/fake/openvpn-install.sh", "--add", "alice", "aa:bb:cc:dd:ee:ff",
        ]

    def test_status_rejected_args_include_limit(self, monkeypatch):
        seen = {}

        def fake_run(args, **kwargs):
            seen["args"] = args
            return _completed(args, 0, "[]")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cw.status_rejected(limit=42)
        assert seen["args"] == [
            "sudo", "-n", "python3", "/fake/vpn-status.py", "--rejected", "42", "--json",
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
