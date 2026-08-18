"""
Provider-agnostic CAPTCHA verification -- gates /login, /forgot-password,
and /reset-password (see routes/auth.py) against automated/scripted
submissions.

Deliberately not hardcoded to Cloudflare Turnstile: this is a self-hosted,
open-source app (see README's "nothing here hardcodes any specific
country, deployment, or organization" stance), and a community running
their own instance may not use Cloudflare at all, or may simply already
have a Google reCAPTCHA account and prefer to reuse it. config.py's
CAPTCHA_PROVIDER picks which one is active; both providers speak nearly
identical siteverify protocols (POST secret+response[+remoteip], get back
JSON with a "success" boolean), so one small module covers both rather
than two near-duplicate ones.

Stdlib-only (urllib), same "no new pip dependency for a small, well-
trodden piece of functionality" reasoning as mailer.py.
"""
import json
import urllib.error
import urllib.parse
import urllib.request

# (widget script URL, siteverify URL) per provider -- everything both
# providers need beyond the site/secret key pair itself.
_PROVIDERS = {
    "turnstile": {
        "widget_js": "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "siteverify_url": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        "widget_class": "cf-turnstile",
    },
    "recaptcha": {
        # v2 checkbox, not v3 -- v3's score-based model needs a
        # site-specific threshold decision this app can't make on a
        # community deployment's behalf; v2's "solved" boolean matches
        # Turnstile's own success/fail shape exactly, so the rest of this
        # module (and routes/auth.py's call sites) doesn't need to
        # special-case either provider beyond widget markup.
        "widget_js": "https://www.google.com/recaptcha/api.js",
        "siteverify_url": "https://www.google.com/recaptcha/api/siteverify",
        "widget_class": "g-recaptcha",
    },
}


def _active_provider() -> str:
    """Settings-page override (app_settings.runtime.captcha_provider) wins
    over the CAPTCHA_PROVIDER env var, same DB-overrides-env layering as
    every other AppSettings-backed value (see app_settings.py's
    refresh_runtime_cache). Imported lazily to avoid a circular import at
    module load time (app_settings imports from this package's models,
    this module is imported early by routes/auth.py)."""
    from . import app_settings
    return app_settings.runtime.captcha_provider


def _active_keys() -> tuple[str | None, str | None]:
    from . import app_settings

    provider = _active_provider()
    if provider == "turnstile":
        return app_settings.runtime.turnstile_site_key, app_settings.runtime.turnstile_secret_key
    if provider == "recaptcha":
        return app_settings.runtime.recaptcha_site_key, app_settings.runtime.recaptcha_secret_key
    return None, None


def is_configured() -> bool:
    site_key, secret_key = _active_keys()
    return bool(site_key and secret_key)


def widget_context() -> dict | None:
    """Template context for the active provider's widget, or None if
    CAPTCHA isn't configured -- routes/auth.py spreads this straight into
    every TemplateResponse context that needs to render a CAPTCHA, and
    the shared login.html/forgot_password.html/reset_password.html markup
    branches on `captcha` being truthy rather than needing to know which
    provider it is."""
    if not is_configured():
        return None
    site_key, _ = _active_keys()
    p = _PROVIDERS[_active_provider()]
    return {"site_key": site_key, "widget_js": p["widget_js"], "widget_class": p["widget_class"]}


def verify(token: str, *, remote_ip: str | None = None) -> bool:
    """Calls the active provider's siteverify endpoint with the token the
    widget handed the browser (form field name differs by provider --
    `cf-turnstile-response` for Turnstile, `g-recaptcha-response` for
    reCAPTCHA; routes/auth.py reads whichever one is actually present).
    Returns False -- never raises -- for every failure mode (missing/empty
    token, no provider configured, a network error, a non-200 response, or
    the provider saying the token itself is invalid/expired/already-used):
    every one of those means "don't trust this submission", and the
    caller's job either way is just to reject the request with the same
    generic error a real bot would see, not to distinguish why. Fails
    CLOSED (returns False) rather than open specifically because the whole
    point of calling this is to block automated submissions -- a network
    hiccup silently waving every request through would defeat that."""
    site_key, secret_key = _active_keys()
    if not token or not secret_key:
        return False
    siteverify_url = _PROVIDERS[_active_provider()]["siteverify_url"]
    body = urllib.parse.urlencode(
        {"secret": secret_key, "response": token, **({"remoteip": remote_ip} if remote_ip else {})}
    ).encode("ascii")
    req = urllib.request.Request(siteverify_url, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False
    return bool(result.get("success"))


def diagnostic_check(*, provider: str, secret_key: str | None) -> dict:
    """Settings-page "Test" button support (routes/settings.py's
    POST /api/settings/captcha/test). Deliberately NOT built on top of
    verify() above, because verify() collapses "the provider correctly
    rejected an invalid token" and "a network error/wrong secret key
    happened" into the same `False` on purpose (see its own docstring --
    that's the right behavior for the real login-gating path, but it's
    exactly the distinction a diagnostic check needs to surface).

    Takes `provider`/`secret_key` as explicit arguments rather than
    reading the ambient app_settings.runtime config -- mirrors
    mailer.send_test_email_via_config's "test the exact values passed in,
    not necessarily the saved/active config" precedent. Found live: this
    used to always resolve _active_provider()/_active_keys() (the
    already-SAVED config, falling back to env vars if nothing's been
    saved yet), so typing a dummy value into an unsaved/inactive
    provider's field and clicking Test silently re-tested whatever was
    already active instead -- on a box with working Turnstile env-var
    credentials, an admin testing a fabricated reCAPTCHA secret got back
    "turnstile is reachable and the secret key is accepted", which is
    true but has nothing to do with what they typed. The caller
    (routes/settings.py) is responsible for resolving what "the current
    value" means (a SECRET_PLACEHOLDER-masked field means "whatever's
    already saved for THIS specific provider", not the active one).

    IMPORTANT reCAPTCHA caveat, confirmed live against Google's real API
    (not assumed from docs): unlike Turnstile -- which returns a distinct
    HTTP 400 invalid-input-secret error for a bad secret key, letting this
    check actually confirm secret validity -- reCAPTCHA's siteverify
    validates the RESPONSE TOKEN first and short-circuits to
    error-codes: ["invalid-input-response"] before ever reaching secret
    validation, for an empty, garbage, or entirely fabricated secret
    alike, since this diagnostic has no real solved challenge to submit.
    So for reCAPTCHA this can only ever confirm "Google's API is
    reachable", never "this specific secret key is valid" -- surfaced via
    the `secret_verifiable` field rather than silently claiming more than
    was actually checked."""
    if provider not in _PROVIDERS:
        return {"reachable": False, "secret_verifiable": False, "error": "Unknown CAPTCHA provider."}
    if not secret_key:
        return {"reachable": False, "secret_verifiable": False, "error": "No secret key to test -- enter one first."}
    siteverify_url = _PROVIDERS[provider]["siteverify_url"]
    body = urllib.parse.urlencode({"secret": secret_key, "response": "test-invalid-token-000000"}).encode("ascii")
    req = urllib.request.Request(siteverify_url, data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"reachable": False, "secret_verifiable": True, "error": f"Provider returned HTTP {e.code} -- check the secret key."}
    except (urllib.error.URLError, TimeoutError):
        return {"reachable": False, "secret_verifiable": False, "error": "Could not reach the provider -- check network connectivity."}
    except ValueError:
        return {"reachable": False, "secret_verifiable": False, "error": "Provider response was not valid JSON."}
    # A well-formed response at all (regardless of success/failure on this
    # deliberately-bogus token) means the provider is reachable -- both
    # providers respond 200 with a JSON body even when rejecting the token
    # itself. Whether that ALSO proves the secret key is valid differs by
    # provider -- see the docstring's reCAPTCHA caveat: only Turnstile's
    # bad-secret case is distinguishable, via the HTTPError branch above,
    # so simply reaching this line already implies a Turnstile secret was
    # accepted, but proves nothing about a reCAPTCHA one.
    reachable = status == 200 and isinstance(result, dict) and "success" in result
    return {"reachable": reachable, "secret_verifiable": provider == "turnstile", "error": None}


def extract_token(form: dict) -> str:
    """Reads whichever field name the active provider's widget actually
    submits -- `cf-turnstile-response` (Turnstile) or `g-recaptcha-response`
    (reCAPTCHA) -- out of a form dict (request.form())/Form(...)-parsed
    body. Returns "" if unconfigured or the field is absent, same
    fail-closed shape as verify() itself."""
    provider = _active_provider()
    if provider == "turnstile":
        return (form.get("cf-turnstile-response") or "").strip()
    if provider == "recaptcha":
        return (form.get("g-recaptcha-response") or "").strip()
    return ""
