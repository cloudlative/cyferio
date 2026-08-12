"""Unit tests for management_client.py -- exercised against real OpenVPN
`status 3` CSV shapes (see this file's module docstring), with the socket
layer monkeypatched (_send/_read_until_end) rather than opening a real
Unix socket."""
import pytest

from services.openvpn.management_client import ManagementClient, parse_source_ip


class TestParseSourceIp:
    def test_ipv4(self):
        # The actual bug this was written to fix: vpn-status.py's own
        # `real_addr.split(":")[0]` on this exact string returns "udp4",
        # not the IP.
        assert parse_source_ip("udp4:182.185.203.112:53266") == "182.185.203.112"

    def test_tcp(self):
        assert parse_source_ip("tcp4:203.0.113.5:1194") == "203.0.113.5"

    def test_ipv6_bracketed(self):
        assert parse_source_ip("tcp6:[2001:db8::1]:1194") == "2001:db8::1"
        assert parse_source_ip("udp6:[::1]:53266") == "::1"

    def test_no_proto_prefix(self):
        # Defensive: if OpenVPN ever emits a bare "ip:port" with no proto
        # prefix, still returns just the IP rather than mis-slicing.
        assert parse_source_ip("192.0.2.1:1194") == "192.0.2.1"

    def test_empty(self):
        assert parse_source_ip("") == ""


class TestListSessions:
    def _mc(self, monkeypatch, status_lines):
        mc = ManagementClient("/tmp/fake.sock")
        monkeypatch.setattr(mc, "_send", lambda line: None)
        monkeypatch.setattr(mc, "_read_until_end", lambda: status_lines)
        return mc

    def test_parses_real_client_list_shape(self, monkeypatch):
        # Matches this deployment's actual OpenVPN 2.7.0 `status 3` output.
        lines = [
            "TITLE,OpenVPN 2.7.0 x86_64-pc-linux-gnu",
            "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,"
            "Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,"
            "Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher",
            "CLIENT_LIST,test,udp4:182.185.203.112:63223,10.8.0.3,,129722,96623,"
            "2026-08-12 12:18:53,1786537133,UNDEF,128,1,AES-256-GCM",
            "HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)",
            "GLOBAL_STATS,Max bcast/mcast queue length,1",
        ]
        mc = self._mc(monkeypatch, lines)
        sessions = mc.list_sessions()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.common_name == "test"
        assert s.real_address == "udp4:182.185.203.112:63223"
        assert s.source_ip == "182.185.203.112"  # not "udp4"
        assert s.virtual_address == "10.8.0.3"
        assert s.bytes_received == 129722
        assert s.bytes_sent == 96623
        assert s.connected_since == "2026-08-12 12:18:53"
        assert s.connected_since_epoch == 1786537133

    def test_no_sessions(self, monkeypatch):
        lines = [
            "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,"
            "Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,"
            "Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher",
        ]
        mc = self._mc(monkeypatch, lines)
        assert mc.list_sessions() == []
