import pytest

from services.openvpn import certificate_manager, config_manager
from services.openvpn.config_manager import InstallOptions
from services.openvpn.exceptions import CertificateError, ValidationError


def test_render_server_conf_udp_no_ip6():
    opts = InstallOptions(ip="203.0.113.10", port=1194, protocol="udp", dns=1, group_name="nogroup")
    from services.openvpn.paths import OpenVPNPaths

    conf = config_manager.render_server_conf(OpenVPNPaths(), opts)
    assert "local 203.0.113.10" in conf
    assert "port 1194" in conf
    assert "proto udp" in conf
    assert 'push "redirect-gateway def1 bypass-dhcp"' in conf
    assert "server-ipv6" not in conf
    assert "explicit-exit-notify" in conf  # only for udp
    assert "crl-verify crl.pem" in conf


def test_render_server_conf_omits_legacy_cipher_directive():
    """No hardcoded `cipher AES-256-CBC` -- see the long comment in
    render_server_conf: that legacy directive breaks NCP data-channel
    negotiation entirely when the server's kernel DCO fast-path is active
    (reproduced live on the 34.182.51.24 test box on 2026-08-11)."""
    from services.openvpn.paths import OpenVPNPaths

    opts = InstallOptions(ip="203.0.113.10", port=1194, protocol="udp", dns=1, group_name="nogroup")
    conf = config_manager.render_server_conf(OpenVPNPaths(), opts)
    assert "cipher AES-256-CBC" not in conf


def test_render_client_common_omits_legacy_cipher_directive():
    opts = InstallOptions(ip="203.0.113.10", port=1194, protocol="udp")
    content = config_manager.render_client_common(opts)
    assert "cipher AES-256-CBC" not in content


def test_render_server_conf_tcp_has_no_explicit_exit_notify():
    from services.openvpn.paths import OpenVPNPaths

    opts = InstallOptions(ip="203.0.113.10", port=443, protocol="tcp", dns=2, group_name="nogroup")
    conf = config_manager.render_server_conf(OpenVPNPaths(), opts)
    assert "proto tcp" in conf
    assert "explicit-exit-notify" not in conf
    assert 'push "dhcp-option DNS 8.8.8.8"' in conf
    assert 'push "dhcp-option DNS 8.8.4.4"' in conf


def test_render_server_conf_with_ip6():
    from services.openvpn.paths import OpenVPNPaths

    opts = InstallOptions(ip="203.0.113.10", ip6="2001:db8::1", port=1194, protocol="udp", dns=1, group_name="nogroup")
    conf = config_manager.render_server_conf(OpenVPNPaths(), opts)
    assert "server-ipv6 fddd:1194:1194:1194::/64" in conf
    assert 'push "redirect-gateway def1 ipv6 bypass-dhcp"' in conf


def test_render_client_common_uses_public_ip_when_set():
    opts = InstallOptions(ip="10.0.0.5", public_ip="203.0.113.10", port=1194, protocol="udp")
    content = config_manager.render_client_common(opts)
    assert "remote 203.0.113.10 1194" in content
    assert "remote 10.0.0.5" not in content


def test_render_client_common_uses_ip_when_no_public_ip():
    opts = InstallOptions(ip="203.0.113.10", port=1194, protocol="udp")
    content = config_manager.render_client_common(opts)
    assert "remote 203.0.113.10 1194" in content


def test_install_options_rejects_bad_port():
    with pytest.raises(ValidationError):
        InstallOptions(ip="1.2.3.4", port=99999)


def test_generate_ovpn_assembles_all_blocks(paths):
    certificate_manager.build_client_cert(paths, "alice")
    content = config_manager.generate_ovpn(paths, "alice")
    for tag in ("<ca>", "</ca>", "<cert>", "</cert>", "<key>", "</key>", "<tls-crypt>", "</tls-crypt>"):
        assert tag in content
    assert "-----BEGIN CERTIFICATE-----" in content
    assert "-----BEGIN PRIVATE KEY-----" in content or "-----BEGIN EC PRIVATE KEY-----" in content
    assert "-----BEGIN OpenVPN Static key" in content
    # Sanity: the client-common.txt content should be present verbatim at
    # the top (client/dev tun/proto/etc lines from the fixture).
    assert "remote 203.0.113.10 1194" in content


def test_generate_ovpn_missing_client_raises(paths):
    with pytest.raises(CertificateError):
        config_manager.generate_ovpn(paths, "nonexistent")
