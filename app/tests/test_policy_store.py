"""
Tests for vpnadmin/policy_store.py -- the app's direct (non-subprocess)
read/write access to client_policy.json and client_usage.json. Uses real
temp files (atomic-write correctness is the point being tested), never the
real /etc/openvpn paths.
"""

import json
from datetime import date

import pytest

from vpnadmin import policy_store
from vpnadmin.config import settings


@pytest.fixture(autouse=True)
def _tmp_policy_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CLIENT_POLICY_FILE", str(tmp_path / "client_policy.json"))
    monkeypatch.setattr(settings, "CLIENT_USAGE_FILE", str(tmp_path / "client_usage.json"))
    yield


class TestPolicyRoundTrip:
    def test_unrestricted_client_returns_empty_policy(self):
        assert policy_store.get_policy("alice") == {}

    def test_set_and_get_country(self):
        policy_store.set_policy("alice", allowed_countries=["PK"])
        assert policy_store.get_policy("alice") == {"allowed_countries": ["PK"]}

    def test_set_and_clear_country(self):
        policy_store.set_policy("alice", allowed_countries=["PK"])
        policy_store.set_policy("alice", allowed_countries=None)
        assert policy_store.get_policy("alice") == {}

    def test_set_allowed_os_normalizes_and_sorts(self):
        policy_store.set_policy("bob", allowed_os=["Mac", "windows", "windows"])
        assert policy_store.get_policy("bob") == {"allowed_os": ["mac", "windows"]}

    def test_empty_os_list_clears_restriction(self):
        policy_store.set_policy("bob", allowed_os=["linux"])
        policy_store.set_policy("bob", allowed_os=[])
        assert policy_store.get_policy("bob") == {}

    def test_invalid_os_name_rejected(self):
        with pytest.raises(policy_store.PolicyValidationError):
            policy_store.set_policy("bob", allowed_os=["amiga"])

    def test_invalid_country_code_rejected(self):
        with pytest.raises(policy_store.PolicyValidationError):
            policy_store.set_policy("bob", allowed_countries=["PAK"])

    def test_bandwidth_quota_round_trip(self):
        policy_store.set_policy("carol", bandwidth_monthly_gb=5)
        assert policy_store.get_policy("carol") == {"bandwidth_monthly_gb": 5.0}

    def test_zero_or_negative_bandwidth_rejected(self):
        with pytest.raises(policy_store.PolicyValidationError):
            policy_store.set_policy("carol", bandwidth_monthly_gb=0)
        with pytest.raises(policy_store.PolicyValidationError):
            policy_store.set_policy("carol", bandwidth_monthly_gb=-5)

    def test_partial_update_leaves_other_fields_untouched(self):
        policy_store.set_policy("dave", allowed_countries=["PK"], allowed_os=["linux"], bandwidth_monthly_gb=10)
        policy_store.set_policy("dave", bandwidth_monthly_gb=20)
        assert policy_store.get_policy("dave") == {
            "allowed_countries": ["PK"],
            "allowed_os": ["linux"],
            "bandwidth_monthly_gb": 20.0,
        }

    def test_clearing_every_field_removes_the_entry_entirely(self):
        policy_store.set_policy("erin", allowed_countries=["PK"])
        policy_store.set_policy("erin", allowed_countries=None)
        all_policies = policy_store.get_all_policies()
        assert "erin" not in all_policies

    def test_remove_policy(self):
        policy_store.set_policy("frank", bandwidth_monthly_gb=1)
        policy_store.remove_policy("frank")
        assert policy_store.get_policy("frank") == {}

    def test_written_file_is_valid_json_on_disk(self):
        policy_store.set_policy("grace", allowed_countries=["PK"])
        with open(settings.CLIENT_POLICY_FILE) as f:
            data = json.load(f)
        assert data == {"grace": {"allowed_countries": ["PK"]}}

    def test_legacy_single_country_entry_normalizes_on_read(self):
        """An entry written before the Location & Network Restrictions
        sync (a bare `country` string, no allowed_countries list) is lifted
        onto the new shape on every read -- see policy_store.py's
        _normalize_policy_shape -- without needing a rewrite first."""
        with open(settings.CLIENT_POLICY_FILE, "w") as f:
            json.dump({"henry": {"country": "AE"}}, f)
        assert policy_store.get_policy("henry") == {"allowed_countries": ["AE"]}
        assert policy_store.get_all_policies() == {"henry": {"allowed_countries": ["AE"]}}

    def test_city_asn_ip_round_trip(self):
        policy_store.set_policy(
            "ivan",
            allowed_cities=["Karachi"],
            allowed_asns=["AS15169"],
            allowed_ips=["203.0.113.5", "10.0.0.0/24"],
        )
        assert policy_store.get_policy("ivan") == {
            "allowed_cities": ["Karachi"],
            "allowed_asns": ["AS15169"],
            "allowed_ips": ["203.0.113.5", "10.0.0.0/24"],
        }


class TestUsage:
    def test_no_usage_row_reads_as_zero(self):
        usage = policy_store.get_usage("nobody-yet")
        assert usage["bytes_used"] == 0

    def test_stale_period_reads_as_zero(self):
        # A date guaranteed to fall in a different calendar month from
        # today, regardless of what day of the month "today" happens to be.
        stale_month = date(2020, 1, 1).isoformat()
        with open(settings.CLIENT_USAGE_FILE, "w") as f:
            json.dump({"alice": {"period_start": stale_month, "bytes_used": 999999}}, f)
        usage = policy_store.get_usage("alice")
        assert usage["bytes_used"] == 0

    def test_current_month_usage_is_read_correctly(self):
        this_month_start = date.today().replace(day=1).isoformat()
        with open(settings.CLIENT_USAGE_FILE, "w") as f:
            json.dump({"alice": {"period_start": this_month_start, "bytes_used": 12345}}, f)
        usage = policy_store.get_usage("alice")
        assert usage["bytes_used"] == 12345
        assert usage["period_start"] == this_month_start

    def test_get_all_usage_applies_rollover_per_client(self):
        this_month_start = date.today().replace(day=1).isoformat()
        stale_month = date(2020, 1, 1).isoformat()
        with open(settings.CLIENT_USAGE_FILE, "w") as f:
            json.dump(
                {
                    "current": {"period_start": this_month_start, "bytes_used": 500},
                    "stale": {"period_start": stale_month, "bytes_used": 999999},
                },
                f,
            )
        all_usage = policy_store.get_all_usage()
        assert all_usage["current"]["bytes_used"] == 500
        assert all_usage["stale"]["bytes_used"] == 0
