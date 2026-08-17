"""Unit tests for captcha.py's provider-agnostic Turnstile/reCAPTCHA
verification -- no app/DB fixtures needed, just config.settings
monkeypatching (mirrors test_clients_ovpn.py's _reset_smtp fixture shape
for the same reason: this module reads a module-level settings object,
not something injected per-call)."""
import json
import urllib.error

from vpnadmin import captcha
from vpnadmin.config import settings


def _clear_captcha_settings(monkeypatch):
    monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "")
    monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", None)
    monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", None)
    monkeypatch.setattr(settings, "RECAPTCHA_SITE_KEY", None)
    monkeypatch.setattr(settings, "RECAPTCHA_SECRET_KEY", None)


class TestIsConfigured:
    def test_false_when_provider_unset(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.is_configured() is False

    def test_false_when_provider_set_but_keys_missing(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        assert captcha.is_configured() is False

    def test_true_for_turnstile_with_both_keys(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", "site")
        monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", "secret")
        assert captcha.is_configured() is True

    def test_true_for_recaptcha_with_both_keys(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "recaptcha")
        monkeypatch.setattr(settings, "RECAPTCHA_SITE_KEY", "site")
        monkeypatch.setattr(settings, "RECAPTCHA_SECRET_KEY", "secret")
        assert captcha.is_configured() is True

    def test_turnstile_keys_dont_leak_into_recaptcha_provider(self, monkeypatch):
        # A deployment that once set Turnstile keys, then switched
        # CAPTCHA_PROVIDER to "recaptcha" without also setting reCAPTCHA's
        # own keys, must not silently stay "configured" using the wrong
        # provider's leftover keys.
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "recaptcha")
        monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", "site")
        monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", "secret")
        assert captcha.is_configured() is False


class TestWidgetContext:
    def test_none_when_unconfigured(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.widget_context() is None

    def test_turnstile_shape(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", "the-site-key")
        monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", "secret")
        ctx = captcha.widget_context()
        assert ctx["site_key"] == "the-site-key"
        assert ctx["widget_class"] == "cf-turnstile"
        assert "challenges.cloudflare.com" in ctx["widget_js"]

    def test_recaptcha_shape(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "recaptcha")
        monkeypatch.setattr(settings, "RECAPTCHA_SITE_KEY", "the-site-key")
        monkeypatch.setattr(settings, "RECAPTCHA_SECRET_KEY", "secret")
        ctx = captcha.widget_context()
        assert ctx["site_key"] == "the-site-key"
        assert ctx["widget_class"] == "g-recaptcha"
        assert "google.com" in ctx["widget_js"]


class TestExtractToken:
    def test_turnstile_field_name(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        assert captcha.extract_token({"cf-turnstile-response": "tok123"}) == "tok123"
        assert captcha.extract_token({"g-recaptcha-response": "tok123"}) == ""

    def test_recaptcha_field_name(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "recaptcha")
        assert captcha.extract_token({"g-recaptcha-response": "tok123"}) == "tok123"
        assert captcha.extract_token({"cf-turnstile-response": "tok123"}) == ""

    def test_unconfigured_returns_empty(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.extract_token({"cf-turnstile-response": "tok123"}) == ""


class TestVerify:
    def test_empty_token_fails_closed_without_network_call(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", "site")
        monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", "secret")
        assert captcha.verify("") is False

    def test_unconfigured_fails_closed(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.verify("some-token") is False

    def test_success_response(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", "site")
        monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", "secret")

        class FakeResponse:
            def read(self):
                return json.dumps({"success": True}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(captcha.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        assert captcha.verify("real-token") is True

    def test_failure_response(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", "site")
        monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", "secret")

        class FakeResponse:
            def read(self):
                return json.dumps({"success": False, "error-codes": ["invalid-input-response"]}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(captcha.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        assert captcha.verify("bad-token") is False

    def test_network_error_fails_closed(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(settings, "CAPTCHA_PROVIDER", "turnstile")
        monkeypatch.setattr(settings, "TURNSTILE_SITE_KEY", "site")
        monkeypatch.setattr(settings, "TURNSTILE_SECRET_KEY", "secret")

        def boom(req, timeout=10):
            raise urllib.error.URLError("no network")

        monkeypatch.setattr(captcha.urllib.request, "urlopen", boom)
        assert captcha.verify("real-token") is False
