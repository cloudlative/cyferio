"""Unit tests for captcha.py's provider-agnostic Turnstile/reCAPTCHA
verification -- no app/DB fixtures needed, just app_settings.runtime
monkeypatching (mirrors test_clients_ovpn.py's _reset_smtp fixture shape
for the same reason: this module reads a module-level runtime object, not
something injected per-call).

Monkeypatches app_settings.runtime, NOT config.settings, since
captcha._active_provider()/_active_keys() now read the DB-overridable
runtime cache first (see routes/settings.py's Settings-page CAPTCHA card),
falling back to config.settings only when runtime's own value is None --
exactly the same layering every other AppSettings-backed field already
has. runtime.captcha_provider etc. are themselves seeded from
config.settings at process start (see app_settings.py's
_RuntimeSettings.__init__), so patching runtime directly is the correct
level to test against, matching what routes/auth.py's real request path
actually reads."""
import json
import urllib.error

from vpnadmin import app_settings, captcha


def _clear_captcha_settings(monkeypatch):
    monkeypatch.setattr(app_settings.runtime, "captcha_provider", None)
    monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", None)
    monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", None)
    monkeypatch.setattr(app_settings.runtime, "recaptcha_site_key", None)
    monkeypatch.setattr(app_settings.runtime, "recaptcha_secret_key", None)


class TestIsConfigured:
    def test_false_when_provider_unset(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.is_configured() is False

    def test_false_when_provider_set_but_keys_missing(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        assert captcha.is_configured() is False

    def test_true_for_turnstile_with_both_keys(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")
        assert captcha.is_configured() is True

    def test_true_for_recaptcha_with_both_keys(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "recaptcha")
        monkeypatch.setattr(app_settings.runtime, "recaptcha_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "recaptcha_secret_key", "secret")
        assert captcha.is_configured() is True

    def test_turnstile_keys_dont_leak_into_recaptcha_provider(self, monkeypatch):
        # A deployment that once set Turnstile keys, then switched
        # captcha_provider to "recaptcha" without also setting reCAPTCHA's
        # own keys, must not silently stay "configured" using the wrong
        # provider's leftover keys.
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "recaptcha")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")
        assert captcha.is_configured() is False

    def test_db_override_takes_precedence_over_env_var(self, monkeypatch):
        # The whole point of routes/settings.py's CAPTCHA card: a
        # Settings-page-saved provider/key pair must win over whatever
        # CAPTCHA_PROVIDER/TURNSTILE_* the environment has, without
        # needing a restart. runtime IS that DB-backed override (env vars
        # only seed its initial value at process start) -- this asserts
        # the read path routes/auth.py actually uses honors it.
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "db-site-key")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "db-secret-key")
        site_key, secret_key = captcha._active_keys()
        assert (site_key, secret_key) == ("db-site-key", "db-secret-key")


class TestWidgetContext:
    def test_none_when_unconfigured(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.widget_context() is None

    def test_turnstile_shape(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "the-site-key")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")
        ctx = captcha.widget_context()
        assert ctx["site_key"] == "the-site-key"
        assert ctx["widget_class"] == "cf-turnstile"
        assert "challenges.cloudflare.com" in ctx["widget_js"]

    def test_recaptcha_shape(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "recaptcha")
        monkeypatch.setattr(app_settings.runtime, "recaptcha_site_key", "the-site-key")
        monkeypatch.setattr(app_settings.runtime, "recaptcha_secret_key", "secret")
        ctx = captcha.widget_context()
        assert ctx["site_key"] == "the-site-key"
        assert ctx["widget_class"] == "g-recaptcha"
        assert "google.com" in ctx["widget_js"]


class TestExtractToken:
    def test_turnstile_field_name(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        assert captcha.extract_token({"cf-turnstile-response": "tok123"}) == "tok123"
        assert captcha.extract_token({"g-recaptcha-response": "tok123"}) == ""

    def test_recaptcha_field_name(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "recaptcha")
        assert captcha.extract_token({"g-recaptcha-response": "tok123"}) == "tok123"
        assert captcha.extract_token({"cf-turnstile-response": "tok123"}) == ""

    def test_unconfigured_returns_empty(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.extract_token({"cf-turnstile-response": "tok123"}) == ""


class TestVerify:
    def test_empty_token_fails_closed_without_network_call(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")
        assert captcha.verify("") is False

    def test_unconfigured_fails_closed(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        assert captcha.verify("some-token") is False

    def test_success_response(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")

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
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")

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
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")

        def boom(req, timeout=10):
            raise urllib.error.URLError("no network")

        monkeypatch.setattr(captcha.urllib.request, "urlopen", boom)
        assert captcha.verify("real-token") is False


class TestDiagnosticCheck:
    def test_unconfigured(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        result = captcha.diagnostic_check()
        assert result["reachable"] is False
        assert result["error"]

    def test_reachable_even_when_token_rejected(self, monkeypatch):
        # The core distinction this function exists for: a normal 200+JSON
        # "token rejected" response (exactly what a deliberately-bogus
        # test token produces) must count as "reachable", unlike verify()'s
        # own True/False, which collapses this into the same False as a
        # real network failure.
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")

        class FakeResponse:
            status = 200

            def read(self):
                return json.dumps({"success": False, "error-codes": ["invalid-input-response"]}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(captcha.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())
        result = captcha.diagnostic_check()
        assert result["reachable"] is True
        assert result["error"] is None

    def test_bad_secret_key_reported_as_unreachable(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "wrong-secret")

        def boom(req, timeout=10):
            raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, None)

        monkeypatch.setattr(captcha.urllib.request, "urlopen", boom)
        result = captcha.diagnostic_check()
        assert result["reachable"] is False
        assert result["error"]

    def test_network_error_reported_distinctly(self, monkeypatch):
        _clear_captcha_settings(monkeypatch)
        monkeypatch.setattr(app_settings.runtime, "captcha_provider", "turnstile")
        monkeypatch.setattr(app_settings.runtime, "turnstile_site_key", "site")
        monkeypatch.setattr(app_settings.runtime, "turnstile_secret_key", "secret")

        def boom(req, timeout=10):
            raise urllib.error.URLError("no network")

        monkeypatch.setattr(captcha.urllib.request, "urlopen", boom)
        result = captcha.diagnostic_check()
        assert result["reachable"] is False
        assert "reach" in result["error"].lower()
