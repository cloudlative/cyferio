"""Unit tests for vpnadmin/client_ip.py's get_client_ip() -- header-selection
and rightmost-hop logic, independent of the full app/DB fixtures (this
module only needs a Request with headers, not a running app)."""

from fastapi import Request

from vpnadmin import config
from vpnadmin.client_ip import get_client_ip, ip_matches_allowlist


def _make_request(headers: dict[str, str], client_host: str | None = "9.9.9.9") -> Request:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {
        "type": "http",
        "headers": raw_headers,
        "client": (client_host, 12345) if client_host else None,
    }
    return Request(scope)


class TestAutoMode:
    def test_prefers_cf_connecting_ip(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "")
        req = _make_request(
            {
                "cf-connecting-ip": "203.0.113.5",
                "x-forwarded-for": "198.51.100.1, 203.0.113.9",
            }
        )
        assert get_client_ip(req) == "203.0.113.5"

    def test_falls_back_to_xff_rightmost(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "")
        req = _make_request({"x-forwarded-for": "198.51.100.1, 203.0.113.9"})
        assert get_client_ip(req) == "203.0.113.9"

    def test_falls_back_to_socket(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "")
        req = _make_request({}, client_host="9.9.9.9")
        assert get_client_ip(req) == "9.9.9.9"

    def test_no_socket_returns_none(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "")
        req = _make_request({}, client_host=None)
        assert get_client_ip(req) is None


class TestExplicitCloudflare:
    def test_uses_cf_header(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "CF-Connecting-IP")
        req = _make_request({"cf-connecting-ip": "203.0.113.5"})
        assert get_client_ip(req) == "203.0.113.5"

    def test_missing_header_falls_back(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "CF-Connecting-IP")
        req = _make_request({"x-forwarded-for": "198.51.100.1, 203.0.113.9"})
        assert get_client_ip(req) == "203.0.113.9"


class TestExplicitXForwardedFor:
    def test_takes_rightmost_hop_not_leftmost(self, monkeypatch):
        # This is the actual bug fix: the leftmost entry is whatever the
        # client itself claimed (attacker-controlled); the rightmost is what
        # Traefik -- the trusted, single hop -- actually appended.
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "X-Forwarded-For")
        req = _make_request({"x-forwarded-for": "1.2.3.4, 5.6.7.8, 203.0.113.9"})
        assert get_client_ip(req) == "203.0.113.9"

    def test_single_hop(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "X-Forwarded-For")
        req = _make_request({"x-forwarded-for": "203.0.113.9"})
        assert get_client_ip(req) == "203.0.113.9"

    def test_ignores_cf_header_when_pinned_to_xff(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "X-Forwarded-For")
        req = _make_request(
            {
                "cf-connecting-ip": "9.9.9.9",
                "x-forwarded-for": "203.0.113.9",
            }
        )
        assert get_client_ip(req) == "203.0.113.9"


class TestExplicitXRealIp:
    def test_uses_x_real_ip(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "X-Real-IP")
        req = _make_request({"x-real-ip": "203.0.113.9"})
        assert get_client_ip(req) == "203.0.113.9"


class TestExplicitForwarded:
    def test_takes_last_for_param(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "Forwarded")
        req = _make_request({"forwarded": "for=1.2.3.4;proto=https, for=203.0.113.9"})
        assert get_client_ip(req) == "203.0.113.9"

    def test_strips_ipv6_brackets_and_port(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "Forwarded")
        req = _make_request({"forwarded": 'for="[2001:db8::1]:4711"'})
        assert get_client_ip(req) == "2001:db8::1"

    def test_strips_ipv4_port(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "Forwarded")
        req = _make_request({"forwarded": "for=203.0.113.9:4711"})
        assert get_client_ip(req) == "203.0.113.9"


class TestUnrecognizedValue:
    def test_falls_back_to_auto(self, monkeypatch):
        monkeypatch.setattr(config.settings, "CLIENT_IP_HEADER", "Bogus-Header")
        req = _make_request({"cf-connecting-ip": "203.0.113.5"})
        assert get_client_ip(req) == "203.0.113.5"


class TestIpMatchesAllowlist:
    def test_exact_match(self):
        assert ip_matches_allowlist("203.0.113.5", ["203.0.113.5"]) is True

    def test_cidr_match(self):
        assert ip_matches_allowlist("10.0.0.5", ["10.0.0.0/24"]) is True

    def test_no_match(self):
        assert ip_matches_allowlist("203.0.113.5", ["10.0.0.0/24"]) is False

    def test_malformed_ip_fails_closed(self):
        assert ip_matches_allowlist("not-an-ip", ["10.0.0.0/24"]) is False

    def test_malformed_allowlist_entry_skipped_not_fatal(self):
        assert ip_matches_allowlist("203.0.113.5", ["not-an-entry", "203.0.113.5"]) is True

    def test_empty_ip_or_allowlist(self):
        assert ip_matches_allowlist(None, ["10.0.0.0/24"]) is False
        assert ip_matches_allowlist("203.0.113.5", []) is False
