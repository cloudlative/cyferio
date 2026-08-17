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

from .config import settings

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


def _active_keys() -> tuple[str | None, str | None]:
    if settings.CAPTCHA_PROVIDER == "turnstile":
        return settings.TURNSTILE_SITE_KEY, settings.TURNSTILE_SECRET_KEY
    if settings.CAPTCHA_PROVIDER == "recaptcha":
        return settings.RECAPTCHA_SITE_KEY, settings.RECAPTCHA_SECRET_KEY
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
    p = _PROVIDERS[settings.CAPTCHA_PROVIDER]
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
    siteverify_url = _PROVIDERS[settings.CAPTCHA_PROVIDER]["siteverify_url"]
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


def extract_token(form: dict) -> str:
    """Reads whichever field name the active provider's widget actually
    submits -- `cf-turnstile-response` (Turnstile) or `g-recaptcha-response`
    (reCAPTCHA) -- out of a form dict (request.form())/Form(...)-parsed
    body. Returns "" if unconfigured or the field is absent, same
    fail-closed shape as verify() itself."""
    if settings.CAPTCHA_PROVIDER == "turnstile":
        return (form.get("cf-turnstile-response") or "").strip()
    if settings.CAPTCHA_PROVIDER == "recaptcha":
        return (form.get("g-recaptcha-response") or "").strip()
    return ""
