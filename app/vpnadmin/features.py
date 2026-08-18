"""
Generic optional-integration feature registry -- MaxMind GeoIP and CAPTCHA
today, the vehicle for any future optional service (SMTP already has its
own multi-provider system, see email_providers.py, and isn't gated through
here; a future notification/DNS/analytics integration would be).

Deliberately thin, not a heavy plugin framework: this app already has every
piece a "feature" needs (runtime-editable config via AppSettings/
app_settings.runtime, a provider-agnostic is_configured() for CAPTCHA, and
file-presence checks for GeoIP) -- this module's only job is to give every
caller (templates, routes, permission checks) ONE place to ask "is this
optional thing actually usable right now" instead of each one reimplementing
its own ad hoc check, which is exactly how GeoIP's "empty picker instead of
a hidden section" and "no consistent gate on /api/geo/*" gaps happened.

Two things intentionally live OUTSIDE this module and are only read by it:
  - Whether an admin has toggled a feature on (app_settings.runtime) --
    that's config, this module doesn't own it.
  - Whether the underlying data/credential is actually usable (a .mmdb file
    existing on disk, captcha.is_configured()'s key-pair check) -- that's
    each integration's own concern, this module just asks it the question.
"""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FeatureDef:
    key: str
    label: str
    description: str


FEATURES: dict[str, FeatureDef] = {
    "geoip": FeatureDef(
        key="geoip",
        label="Geo/IP (MaxMind)",
        description="Country/city/ASN/IP-based VPN and portal-login restrictions, geo reports, and diagnostics.",
    ),
    "captcha": FeatureDef(
        key="captcha",
        label="CAPTCHA",
        description="Bot-mitigation challenge on login, forgot-password, and reset-password.",
    ),
}


def geoip_enabled() -> bool:
    """True only if BOTH an admin has turned it on (app_settings.runtime.
    geoip_enabled) AND the Country GeoLite2 database actually exists on
    disk. The second check is defense in depth, not paranoia: an admin can
    flip the Settings toggle on before the first download finishes (or
    before geoip-update.sh has ever successfully run at all on a fresh
    install), and this module's whole point is "don't show a feature that
    doesn't actually work yet". City/ASN each degrade independently of
    this and of each other exactly as geoip.py's _get_reader already does
    (a missing City/ASN db just means those specific lookups return None)
    -- that per-edition fail-soft behavior is unchanged; this flag only
    gates the country-restriction-and-above UI/API surface, which is the
    only edition every geo feature in this app depends on existing."""
    from . import app_settings
    from .config import settings

    if not app_settings.runtime.geoip_enabled:
        return False
    return Path(settings.GEOIP_DB_PATH).is_file()


def captcha_enabled() -> bool:
    """Re-exported through this registry so callers have one place to ask
    "is this optional feature on", even though the real logic already
    lives in captcha.is_configured() (provider + site/secret key pair
    present) -- unchanged by this module, just given a second name here
    for symmetry with geoip_enabled()."""
    from . import captcha

    return captcha.is_configured()


_CHECKS = {
    "geoip": geoip_enabled,
    "captcha": captcha_enabled,
}


def is_enabled(key: str) -> bool:
    """The one function everything else should call. Unknown key -> False
    (fail closed, same posture as permissions.py's _has_permission on a
    missing row) rather than raising, since a template evaluating
    `features.unknown_key` should just render nothing, not 500."""
    check = _CHECKS.get(key)
    return bool(check()) if check else False


def all_states() -> dict[str, dict]:
    """Every registered feature's current enabled/disabled state, keyed by
    feature key -- used by the Settings page to render the framework's own
    "Integrations" overview list (label + description + live state) rather
    than the page hardcoding a list that could drift from FEATURES."""
    return {
        key: {"label": f.label, "description": f.description, "enabled": is_enabled(key)}
        for key, f in FEATURES.items()
    }


def require_feature(key: str):
    """FastAPI dependency factory, same shape as permissions.require_permission
    -- but raises 404, not 403. A disabled/unconfigured optional feature
    should look to a direct API caller exactly like a route that was never
    registered at all (per the "platform should behave as if Geo
    functionality does not exist" requirement), not like an authorization
    failure, which would confirm the endpoint exists and just isn't
    allowed for this caller."""
    from fastapi import Depends, HTTPException, status

    from .auth import require_user
    from .models import User

    def _dep(user: User = Depends(require_user)) -> User:
        if not is_enabled(key):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
        return user

    return _dep
