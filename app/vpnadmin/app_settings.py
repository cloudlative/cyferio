"""
Runtime-editable application settings (Settings page, admin-only -- see
routes/settings.py), layered on top of the env-var defaults in config.py:

    env var (config.py)  --seeds-->  DB row (AppSettings, all-nullable)
                                          |
                                          v
                              in-process cache (`runtime`, this module)
                                          |
                                          v
                       Jinja templates / mailer.py / auth.py read `runtime`

The DB row is the persistent source of truth once anything's been changed
via the Settings page; env vars remain the fallback for anything left NULL
there (including on a fresh install where nobody's touched the page yet).

Templates and other modules read the in-process `runtime` object instead of
hitting the DB on every request/render: it's refreshed once at startup and
again immediately after every successful settings save (see
routes/settings.py), so changes take effect immediately without an app
restart, without paying a DB round-trip per page view. This is safe for
this app's single-process deployment (see docker-compose.yml); a
multi-worker deployment would need a shared cache instead (documented as a
known limitation, not silently wrong -- a stale worker still falls back to
correct-but-outdated values, never garbage).
"""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from . import policy_store
from .config import settings as env_settings
from .models import AppSettings

_STATIC_DIR = Path(__file__).parent / "static"


def _compute_static_version() -> str:
    """Short content hash of the static/ dir, computed once at import time
    (not per-request -- the image is immutable once built, so the content
    can't change without a restart anyway). Used as a `?v=` cache-busting
    query string on <link>/<script> tags in base.html.

    Needed because this app sits behind Cloudflare, which caches /static/*
    at the edge for hours regardless of what the origin actually serves
    (a plain path with no querystring is one cache key forever) -- a CSS/JS
    fix can be live in the running container and still invisible to every
    visitor until the edge cache happens to expire. A version query string
    changes the cache key on every release that touches a static file, so
    Cloudflare treats it as a new object instead of serving the stale HIT.
    """
    h = hashlib.sha1()
    for path in sorted(_STATIC_DIR.rglob("*")):
        if path.is_file():
            h.update(path.read_bytes())
    return h.hexdigest()[:10]


static_version = _compute_static_version()

# The placeholder returned in place of a real SMTP password by GET
# /api/settings -- never round-trip the actual secret to the browser. The
# PATCH endpoint treats this exact string as "unchanged, don't touch it".
SMTP_PASSWORD_PLACEHOLDER = "••••••••"

# The 6 named login/app themes, in rotation order -- must match the ids
# used in static/style.css's `[data-theme="..."]` rules and
# templates/partials/theme_bg_*.html. "auto" (rotation) is a settings value,
# not itself a theme id, so it's intentionally excluded from this tuple.
ACTIVE_THEME_IDS = ("constellation", "contour", "ingress", "cipher", "perimeter", "horizon")

# What the Settings page dropdown offers, in display order -- id, label, and
# a short one-line rationale (reused verbatim from the approved preview) so
# an admin isn't picking blind between six similar-sounding names.
THEME_CHOICES = [
    {"id": "auto", "label": "Auto-rotate (every 2 hours, 6 themes)",
     "description": "Cycles through all 6 themes below on a fixed schedule -- each active for two 2-hour slots per day."},
    {"id": "constellation", "label": "Constellation",
     "description": "A mesh of nodes, quietly drifting, occasionally trading a packet along an edge. Indigo/violet/cyan."},
    {"id": "contour", "label": "Signal Contour",
     "description": "Faint oscilloscope-like waveform lines drifting sideways. Sky-blue into teal."},
    {"id": "ingress", "label": "Ingress Field",
     "description": "A deep starfield with rare bright streaks crossing the frame. Deep blue into cyan."},
    {"id": "cipher", "label": "Cipher Rain",
     "description": "Thin columns of hex digits drifting downward, low opacity. Emerald/teal on near-black."},
    {"id": "perimeter", "label": "Perimeter Grid",
     "description": "A faint grid with a slow radar-style sweep. Amber into gold."},
    {"id": "horizon", "label": "Data Horizon",
     "description": "Straight horizontal lines drifting past a soft horizon glow. Violet into rose."},
]


def resolve_active_theme(login_theme_setting: str | None, now: datetime | None = None) -> str:
    """Resolves the *effective* theme id for right now.

    An admin's pinned choice (anything other than "auto"/None) always wins,
    no rotation logic involved. "auto" (or an unset/unrecognized value)
    rotates through the 6 themes in ACTIVE_THEME_IDS on a fixed schedule:
    2 hours each, so each theme is active for exactly 2 of the 12 two-hour
    slots in a day (twice per 24h) -- `hour // 2 % 6` picks the slot. Uses
    local server time (matches the schedule as shown/confirmed in the
    approved preview, which likewise used the browser's local hour).

    Deliberately NOT cached on the module-level `runtime` object -- that
    cache is only refreshed at startup and after settings saves, but this
    needs to change over the course of a day with no settings change at
    all. Call this fresh on every render instead (it's cheap: no I/O)."""
    if login_theme_setting and login_theme_setting != "auto":
        return login_theme_setting
    if now is None:
        now = datetime.now()
    slot = (now.hour // 2) % len(ACTIVE_THEME_IDS)
    return ACTIVE_THEME_IDS[slot]


class _RuntimeSettings:
    """Plain attribute bag holding the currently-effective settings. A
    single shared instance (`runtime` below) is what templates/mailer.py/
    auth.py actually read -- see this module's docstring for why."""

    def __init__(self):
        # Fixed brand identity -- not settings-backed, never reassigned
        # anywhere else (see refresh_runtime_cache(), which no longer
        # touches this). Kept as an attribute on `runtime` rather than a
        # module-level constant purely so templates/mailer.py don't need to
        # change: they already read `app_settings.app_name` everywhere.
        self.app_name = "Cyferio"
        self.portal_url = f"https://{env_settings.APP_DOMAIN}" if env_settings.APP_DOMAIN else None
        self.smtp_host = env_settings.SMTP_HOST
        self.smtp_port = env_settings.SMTP_PORT
        self.smtp_username = env_settings.SMTP_USERNAME
        self.smtp_password = env_settings.SMTP_PASSWORD
        self.smtp_from = env_settings.SMTP_FROM
        self.smtp_use_tls = env_settings.SMTP_USE_TLS
        self.min_password_length = 8
        self.session_timeout_minutes = max(1, env_settings.SESSION_MAX_AGE_SECONDS // 60)
        self.account_lockout_threshold = 0  # 0 = disabled
        self.account_lockout_minutes = 15
        self.audit_retention_days = None  # None/0 = keep forever
        self.log_failed_login_attempts = True
        self.default_new_user_role = "user"
        self.default_bandwidth_monthly_gb = None  # None = unlimited
        self.default_quota_enforcement_policy = "soft"  # pre-existing, only-ever behavior until Phase 2's hard mode
        self.admin_notification_email = None
        self.notify_admin_on_user_created = False
        self.notify_admin_on_client_revoked = False
        self.quota_notify_warning_pct = 80
        self.quota_notify_critical_pct = 95
        self.notify_admin_on_quota_critical = False
        self.reports_default_range_days = 7
        self.db_snapshot_retention_days = 90  # None/0 (if explicitly set) = keep forever
        self.maintenance_mode = False
        self.maintenance_message = None
        self.notification_duration_ms = 1000  # 1 second default, admin-configurable (Settings -> Notifications)
        self.login_theme = env_settings.LOGIN_THEME
        self.timezone = env_settings.APP_TIMEZONE
        self.time_format = env_settings.APP_TIME_FORMAT


runtime = _RuntimeSettings()


def get_settings_row(db: Session) -> AppSettings:
    """Fetches the singleton settings row, creating it (all-NULL, i.e. pure
    env-var fallback) on first access. There should only ever be one row --
    nothing else in this app writes to this table."""
    row = db.query(AppSettings).first()
    if row is None:
        row = AppSettings()
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def refresh_runtime_cache(db: Session) -> None:
    """Re-derives `runtime` from the DB row (falling back to env-var
    defaults for anything left NULL). Called once at startup and again
    after every settings save."""
    row = get_settings_row(db)
    runtime.portal_url = row.portal_url or (f"https://{env_settings.APP_DOMAIN}" if env_settings.APP_DOMAIN else None)
    runtime.smtp_host = row.smtp_host if row.smtp_host is not None else env_settings.SMTP_HOST
    runtime.smtp_port = row.smtp_port if row.smtp_port is not None else env_settings.SMTP_PORT
    runtime.smtp_username = row.smtp_username if row.smtp_username is not None else env_settings.SMTP_USERNAME
    runtime.smtp_password = row.smtp_password if row.smtp_password is not None else env_settings.SMTP_PASSWORD
    runtime.smtp_from = row.smtp_from if row.smtp_from is not None else env_settings.SMTP_FROM
    runtime.smtp_use_tls = row.smtp_use_tls if row.smtp_use_tls is not None else env_settings.SMTP_USE_TLS
    runtime.min_password_length = row.min_password_length or 8
    runtime.session_timeout_minutes = row.session_timeout_minutes or max(1, env_settings.SESSION_MAX_AGE_SECONDS // 60)
    runtime.account_lockout_threshold = row.account_lockout_threshold or 0
    runtime.account_lockout_minutes = row.account_lockout_minutes or 15
    runtime.audit_retention_days = row.audit_retention_days
    runtime.log_failed_login_attempts = row.log_failed_login_attempts if row.log_failed_login_attempts is not None else True
    runtime.default_new_user_role = row.default_new_user_role or "user"
    runtime.default_bandwidth_monthly_gb = row.default_bandwidth_monthly_gb
    runtime.default_quota_enforcement_policy = row.default_quota_enforcement_policy or "soft"
    runtime.admin_notification_email = row.admin_notification_email
    runtime.notify_admin_on_user_created = bool(row.notify_admin_on_user_created)
    runtime.notify_admin_on_client_revoked = bool(row.notify_admin_on_client_revoked)
    runtime.quota_notify_warning_pct = row.quota_notify_warning_pct if row.quota_notify_warning_pct is not None else 80
    runtime.quota_notify_critical_pct = row.quota_notify_critical_pct if row.quota_notify_critical_pct is not None else 95
    runtime.notify_admin_on_quota_critical = bool(row.notify_admin_on_quota_critical)
    runtime.reports_default_range_days = row.reports_default_range_days if row.reports_default_range_days is not None else 7
    # Unlike audit_retention_days above (default = keep forever), this
    # defaults to 90 days when never explicitly set -- a continuously-
    # growing time-series table is more likely to need a retention bound
    # out of the box than the audit log is. An admin can still explicitly
    # set 0 for "keep forever", same as audit_retention_days.
    runtime.db_snapshot_retention_days = row.db_snapshot_retention_days if row.db_snapshot_retention_days is not None else 90
    runtime.maintenance_mode = bool(row.maintenance_mode)
    runtime.maintenance_message = row.maintenance_message
    runtime.notification_duration_ms = row.notification_duration_ms or 1000
    runtime.login_theme = row.login_theme or env_settings.LOGIN_THEME
    runtime.timezone = row.timezone or env_settings.APP_TIMEZONE
    runtime.time_format = row.time_format or env_settings.APP_TIME_FORMAT

    # Mirrors the one setting host-scripts/quota_enforcer.py needs but has
    # no DB access to read directly -- see policy_store.write_global_defaults
    # and config.py's GLOBAL_DEFAULTS_FILE docstring.
    policy_store.write_global_defaults(quota_enforcement_policy=runtime.default_quota_enforcement_policy)


def apply_settings_globals(templates) -> None:
    """Registers the live `runtime` object (not a snapshot of its current
    values) as a Jinja2 global -- there are two separate Jinja2Templates
    instances in this app (routes/pages.py and routes/auth.py each create
    their own), so both need this applied. Templates read e.g.
    `{{ app_settings.app_name }}`; because
    `runtime` is a mutable object referenced by the globals dict (not a
    copied string), later changes to its attributes are visible on the
    very next render with no extra wiring."""
    templates.env.globals["app_settings"] = runtime
    templates.env.globals["static_version"] = static_version
    # Registered as a callable, not a precomputed value -- `runtime.login_theme`
    # only changes on settings-save, but the *resolved* active theme must
    # change over the course of a day purely from the clock when the setting
    # is "auto". Templates call it fresh on every render: {{ active_theme() }}.
    templates.env.globals["active_theme"] = lambda: resolve_active_theme(runtime.login_theme)


def prune_audit_log(db: Session) -> int:
    """Deletes AuditLog entries older than `runtime.audit_retention_days`,
    if a retention period is configured (None/0 = keep forever, no-op).
    Called once at startup, after the cache is refreshed -- simple and
    predictable (retention takes effect on next restart/deploy, same cadence
    as most of this app's other startup-time reconciliation, e.g.
    db._sync_missing_columns()), no separate scheduler/cron dependency."""
    from datetime import timedelta

    from .models import AuditLog

    if not runtime.audit_retention_days:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=runtime.audit_retention_days)
    deleted = db.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete(synchronize_session=False)
    db.commit()
    return deleted


def prune_db_stat_snapshots(db: Session) -> int:
    """Same shape as prune_audit_log() above, against DbStatSnapshot
    instead -- see runtime.db_snapshot_retention_days' own comment in
    refresh_runtime_cache() for why this one defaults to 90 days rather
    than "keep forever" when never explicitly set."""
    from datetime import timedelta

    from .models import DbStatSnapshot

    if not runtime.db_snapshot_retention_days:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=runtime.db_snapshot_retention_days)
    deleted = db.query(DbStatSnapshot).filter(DbStatSnapshot.timestamp < cutoff).delete(synchronize_session=False)
    db.commit()
    return deleted
