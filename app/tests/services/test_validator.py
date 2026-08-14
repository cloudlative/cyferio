import pytest

from services.openvpn.exceptions import ValidationError
from services.openvpn.validator import (
    normalize_mac,
    sanitize_client_name,
    validate_dns_choice,
    validate_port,
    validate_protocol,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("alice", "alice"),
        ("Alice Smith!", "Alice_Smith_"),
        ("a.b@c#d", "a_b_c_d"),
        # Non-ASCII input is intentionally not asserted here -- bash's sed
        # substitution is locale/byte-encoding dependent for multi-byte
        # characters, so there's no single "correct" parity target; real client
        # names are expected to be ASCII in practice.
    ],
)
def test_sanitize_client_name(raw, expected):
    assert sanitize_client_name(raw) == expected


def test_sanitize_client_name_empty_raises():
    # Only a genuinely empty input raises -- every invalid character is
    # *substituted* with '_' (never removed), matching bash's sed at :258,
    # so e.g. "!!!" sanitizes to "___" (non-empty), not an error.
    with pytest.raises(ValidationError):
        sanitize_client_name("")


def test_sanitize_client_name_all_invalid_chars_becomes_underscores_not_empty():
    assert sanitize_client_name("!!!") == "___"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        ("AABB.CCDD.EEFF", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize("raw", ["", "not-a-mac", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff"])
def test_normalize_mac_invalid(raw):
    with pytest.raises(ValidationError):
        normalize_mac(raw)


def test_validate_port():
    assert validate_port("1194") == 1194
    assert validate_port(443) == 443
    for bad in ("0", "65536", "-1", "abc", None):
        with pytest.raises(ValidationError):
            validate_port(bad)


def test_validate_protocol():
    assert validate_protocol("") == "udp"
    assert validate_protocol(None) == "udp"
    assert validate_protocol(1) == "udp"
    assert validate_protocol("1") == "udp"
    assert validate_protocol(2) == "tcp"
    assert validate_protocol("tcp") == "tcp"
    with pytest.raises(ValidationError):
        validate_protocol("sctp")


def test_validate_dns_choice():
    assert validate_dns_choice("") == 1
    assert validate_dns_choice(None) == 1
    assert validate_dns_choice(3) == 3
    with pytest.raises(ValidationError):
        validate_dns_choice(7)
    with pytest.raises(ValidationError):
        validate_dns_choice("x")
