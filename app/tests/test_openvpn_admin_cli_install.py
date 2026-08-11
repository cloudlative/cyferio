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
        return "10.0.0.1"

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
