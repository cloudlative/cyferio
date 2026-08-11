"""Tests that cli/openvpn_admin.py's `install` action registers the first
client's MAC right after install -- closing services/openvpn/installer.py's
own documented gap (its docstring: the bash-script-parity behavior where the
first client's cert is created but never registered in DB_FILE, so it can't
pass the MAC check until a separate add_mac/restore call). See
routes/openvpn_install.py's post_install, which now requires a mac and
passes it through as --client-mac."""
import json

import pytest

from cli import openvpn_admin


class _FakeInstallResult:
    def __init__(self):
        self.client_name = "client"
        self.ovpn_path = "/tmp/client.ovpn"
        self.port = 1194
        self.protocol = "udp"


def test_install_action_requires_client_mac_flag():
    parser = openvpn_admin.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["install", "--client-name=client"])  # no --client-mac


def test_install_action_calls_add_mac_after_install(monkeypatch, capsys):
    calls = {}

    def fake_resolve_install_ip(ip):
        return "203.0.113.10"  # a public-looking IP -- no auto-detect side effect to worry about here

    def fake_install(paths, opts, client_name, install_packages=True):
        calls["install"] = (client_name, install_packages)
        return _FakeInstallResult()

    def fake_add_mac(paths, name, mac):
        calls["add_mac"] = (name, mac)
        return "aa:bb:cc:dd:ee:ff"

    monkeypatch.setattr(openvpn_admin.network_manager, "resolve_install_ip", fake_resolve_install_ip)
    monkeypatch.setattr(openvpn_admin.installer, "install", fake_install)
    monkeypatch.setattr(openvpn_admin.client_manager, "add_mac", fake_add_mac)

    rc = openvpn_admin.main([
        "--openvpn-dir=/tmp/scratch-openvpn",
        "install", "--client-name=client", "--client-mac=aa:bb:cc:dd:ee:ff", "--no-packages",
    ])
    assert rc == 0
    assert calls["install"] == ("client", False)
    assert calls["add_mac"] == ("client", "aa:bb:cc:dd:ee:ff")

    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["data"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert out["data"]["client_name"] == "client"


class TestPublicIpAutoDetect:
    """Covers cli/openvpn_admin.py's install action auto-detecting the
    public IP when the resolved local IP is private and no --public-ip was
    given -- closes the gap that produced `remote 10.138.0.2 1194` in a
    generated client-common.txt on the 34.182.51.24 test box (2026-08-11):
    a NAT'd cloud VM's local interface never sees its own public IP."""

    def _install(self, monkeypatch, *, local_ip, explicit_public_ip=None, detected_public_ip="198.51.100.7"):
        captured_opts = {}

        monkeypatch.setattr(openvpn_admin.network_manager, "resolve_install_ip", lambda ip: local_ip)
        monkeypatch.setattr(openvpn_admin.network_manager, "detect_public_ip", lambda: detected_public_ip)

        def fake_install(paths, opts, client_name, install_packages=True):
            captured_opts["public_ip"] = opts.public_ip
            return _FakeInstallResult()

        monkeypatch.setattr(openvpn_admin.installer, "install", fake_install)
        monkeypatch.setattr(openvpn_admin.client_manager, "add_mac", lambda paths, name, mac: mac)

        args = [
            "--openvpn-dir=/tmp/scratch-openvpn",
            "install", "--client-name=client", "--client-mac=aa:bb:cc:dd:ee:ff", "--no-packages",
        ]
        if explicit_public_ip:
            args.append(f"--public-ip={explicit_public_ip}")
        rc = openvpn_admin.main(args)
        assert rc == 0
        return captured_opts["public_ip"]

    def test_private_local_ip_with_no_override_auto_detects(self, monkeypatch):
        assert self._install(monkeypatch, local_ip="10.138.0.2") == "198.51.100.7"

    def test_public_local_ip_skips_auto_detect(self, monkeypatch):
        # Not private -- no NAT gap to correct for, auto-detect must not run.
        assert self._install(monkeypatch, local_ip="203.0.113.10") is None

    def test_explicit_public_ip_overrides_auto_detect(self, monkeypatch):
        assert self._install(monkeypatch, local_ip="10.138.0.2", explicit_public_ip="192.0.2.55") == "192.0.2.55"
