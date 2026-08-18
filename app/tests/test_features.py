"""Unit + integration tests for features.py -- the generic optional-
integration registry gating GeoIP/CAPTCHA (see that module's docstring)."""
from vpnadmin import app_settings, features

from .conftest import login


class TestGeoipEnabled:
    def test_false_when_toggle_off(self, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "geoip_enabled", False)
        assert features.geoip_enabled() is False

    def test_false_when_toggle_on_but_db_missing(self, monkeypatch, tmp_path):
        from vpnadmin.config import settings as env_settings

        monkeypatch.setattr(app_settings.runtime, "geoip_enabled", True)
        monkeypatch.setattr(env_settings, "GEOIP_DB_PATH", str(tmp_path / "does-not-exist.mmdb"))
        assert features.geoip_enabled() is False

    def test_true_when_toggle_on_and_db_present(self, monkeypatch, tmp_path):
        from vpnadmin.config import settings as env_settings

        db_path = tmp_path / "GeoLite2-Country.mmdb"
        db_path.write_bytes(b"not a real mmdb, just needs to exist")
        monkeypatch.setattr(app_settings.runtime, "geoip_enabled", True)
        monkeypatch.setattr(env_settings, "GEOIP_DB_PATH", str(db_path))
        assert features.geoip_enabled() is True


class TestCaptchaEnabledDelegation:
    def test_delegates_to_captcha_is_configured(self, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", None)
        assert features.captcha_enabled() is False
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")
        assert features.captcha_enabled() is True


class TestIsEnabled:
    def test_unknown_key_is_false_not_an_error(self):
        assert features.is_enabled("some-integration-that-does-not-exist") is False

    def test_dispatches_to_registered_check(self, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "geoip_enabled", False)
        assert features.is_enabled("geoip") is False


class TestGeoApiGating:
    """Direct-API-call behavior -- see features.require_feature's own
    docstring for why this is 404, not 403: a disabled optional feature
    should look like the endpoint doesn't exist at all."""

    def test_geo_endpoints_404_when_disabled(self, app_client, monkeypatch):
        monkeypatch.setattr(app_settings.runtime, "geoip_enabled", False)
        login(app_client, "admin", "adminpass123")
        for path in ("/api/geo/status", "/api/geo/countries-with-cities", "/api/geo/countries-with-asns",
                     "/api/geo/cities?country=US", "/api/geo/asns"):
            r = app_client.get(path)
            assert r.status_code == 404, path

    def test_geo_endpoints_reachable_when_enabled(self, app_client, monkeypatch, tmp_path):
        from vpnadmin.config import settings as env_settings

        db_path = tmp_path / "GeoLite2-Country.mmdb"
        db_path.write_bytes(b"placeholder")
        monkeypatch.setattr(app_settings.runtime, "geoip_enabled", True)
        monkeypatch.setattr(env_settings, "GEOIP_DB_PATH", str(db_path))
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/geo/status")
        assert r.status_code == 200

    def test_unauthenticated_gets_401_not_404(self, app_client, monkeypatch):
        # require_feature builds on require_user -- an unauthenticated
        # caller should still see the normal auth failure, not a 404 that
        # would leak "this route doesn't require auth to know it's gated".
        monkeypatch.setattr(app_settings.runtime, "geoip_enabled", False)
        r = app_client.get("/api/geo/status")
        assert r.status_code == 401
