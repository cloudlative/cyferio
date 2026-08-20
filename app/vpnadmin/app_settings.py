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

# Same masking convention, reused verbatim, for the MaxMind license key and
# both CAPTCHA providers' secret keys (turnstile_secret_key/
# recaptcha_secret_key) -- see routes/settings.py's _serialize()/
# update_settings(). Site keys (Turnstile/reCAPTCHA) are NOT masked: they're
# public by design (shipped straight into the login page's HTML for every
# visitor), so round-tripping them to the Settings page is no different
# from any other non-secret field.
SECRET_PLACEHOLDER = "••••••••"

# The 10 named login/app themes, in rotation order -- must match the ids
# used in static/style.css's `[data-theme="..."]` rules and
# templates/login.html's per-theme background blocks. "auto" (rotation) is
# a settings value, not itself a theme id, so it's intentionally excluded
# from this tuple. The last 4 (lattice/flux/pulse/relay) were added
# 2026-08-19 alongside the original approved 6 -- same design language
# (a quiet, low-opacity animated backdrop, not a showcase piece), each
# picking a hue family none of the original 6 already used.
ACTIVE_THEME_IDS = (
    "constellation", "contour", "ingress", "cipher", "perimeter", "horizon",
    "lattice", "flux", "pulse", "relay",
)

# What the Settings page dropdown offers, in display order -- id, label, and
# a short one-line rationale (reused verbatim from the approved preview) so
# an admin isn't picking blind between ten similar-sounding names.
THEME_CHOICES = [
    {"id": "auto", "label": "Auto-rotate (every 2 hours, 10 themes)",
     "description": "Cycles through all 10 themes below on a fixed schedule -- each active for one or two 2-hour slots per day."},
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
    {"id": "lattice", "label": "Threat Lattice",
     "description": "A faint hex grid where cells occasionally flare like a live heatmap. Crimson on near-black."},
    {"id": "flux", "label": "Quantum Flux",
     "description": "Soft glowing orbs drifting and slowly pulsing past each other, no connecting lines. Fuchsia into indigo."},
    {"id": "pulse", "label": "Uplink Pulse",
     "description": "Sonar-style rings expanding outward from random points and fading. Lime into chartreuse."},
    {"id": "relay", "label": "Glass Relay",
     "description": "Large soft-edged hexagons drifting slowly past each other, frosted-glass style. Slate into cyan."},
]


def resolve_active_theme(login_theme_setting: str | None, now: datetime | None = None) -> str:
    """Resolves the *effective* theme id for right now.

    An admin's pinned choice (anything other than "auto"/None) always wins,
    no rotation logic involved. "auto" (or an unset/unrecognized value)
    rotates through the 10 themes in ACTIVE_THEME_IDS on a fixed schedule:
    2 hours each, so each theme gets 1 or 2 of the 12 two-hour slots in a
    day (12 slots don't divide evenly across 10 themes -- the last 2 slots
    of each day simply wrap back to the first 2 themes, giving those two
    a slightly larger share; not worth complicating the schedule to avoid)
    -- `hour // 2 % 10` picks the slot. Uses local server time (matches
    the schedule as shown/confirmed in the approved preview, which
    likewise used the browser's local hour).

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
        self.password_history_count = 3  # 0 = disabled (no reuse check)
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

        # Optional integrations (see features.py). geoip_enabled defaults
        # to True (not False/NULL) here specifically because GeoIP was
        # NEVER previously gated by any "enabled" flag -- it just worked
        # whenever the .mmdb files happened to exist. An already-working
        # deployment upgrading to this version must keep working exactly
        # as before with zero admin action (see the plan's "Migration &
        # rollout" section); defaulting True (ANDed with the actual file-
        # presence check in features.geoip_enabled()) preserves that,
        # while a genuinely fresh install with no .mmdb yet still
        # correctly shows nothing until an admin configures it, since the
        # file-presence half of that AND is what's actually false there.
        self.geoip_enabled = True
        self.maxmind_license_key = None  # no prior env var for this -- app never stored it before this feature
        self.captcha_provider = env_settings.CAPTCHA_PROVIDER
        self.turnstile_site_key = env_settings.TURNSTILE_SITE_KEY
        self.turnstile_secret_key = env_settings.TURNSTILE_SECRET_KEY
        self.recaptcha_site_key = env_settings.RECAPTCHA_SITE_KEY
        self.recaptcha_secret_key = env_settings.RECAPTCHA_SECRET_KEY
        self.connection_issue_retention_days = 60  # None/0 (if explicitly set) = keep forever
        self.allow_duplicate_macs = False  # default = strict, matches openvpn-install.sh's original always-on behavior

        # Support Ticketing System -- see AppSettings' own columns for why
        # these are admin-tweakable rather than hardcoded.
        self.support_ticket_rate_limit_count = 5
        self.support_ticket_rate_limit_window_minutes = 60
        self.support_max_attachment_size_mb = 10
        self.support_max_attachments_per_message = 5
        self.notify_admin_on_ticket_created = False


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
    runtime.password_history_count = row.password_history_count if row.password_history_count is not None else 3
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

    # See _RuntimeSettings.__init__'s comment on why geoip_enabled defaults
    # True, not False, when never explicitly set.
    runtime.geoip_enabled = row.geoip_enabled if row.geoip_enabled is not None else True
    runtime.maxmind_license_key = row.maxmind_license_key
    runtime.captcha_provider = row.captcha_provider if row.captcha_provider is not None else env_settings.CAPTCHA_PROVIDER
    runtime.turnstile_site_key = row.turnstile_site_key if row.turnstile_site_key is not None else env_settings.TURNSTILE_SITE_KEY
    runtime.turnstile_secret_key = row.turnstile_secret_key if row.turnstile_secret_key is not None else env_settings.TURNSTILE_SECRET_KEY
    runtime.recaptcha_site_key = row.recaptcha_site_key if row.recaptcha_site_key is not None else env_settings.RECAPTCHA_SITE_KEY
    runtime.recaptcha_secret_key = row.recaptcha_secret_key if row.recaptcha_secret_key is not None else env_settings.RECAPTCHA_SECRET_KEY
    # My Connection Issues: same "default to a bounded window, admin can
    # still explicitly set 0 for forever" stance as db_snapshot_retention_days.
    runtime.connection_issue_retention_days = row.connection_issue_retention_days if row.connection_issue_retention_days is not None else 60
    runtime.allow_duplicate_macs = bool(row.allow_duplicate_macs)

    runtime.support_ticket_rate_limit_count = row.support_ticket_rate_limit_count if row.support_ticket_rate_limit_count is not None else 5
    runtime.support_ticket_rate_limit_window_minutes = (
        row.support_ticket_rate_limit_window_minutes if row.support_ticket_rate_limit_window_minutes is not None else 60
    )
    runtime.support_max_attachment_size_mb = row.support_max_attachment_size_mb if row.support_max_attachment_size_mb is not None else 10
    runtime.support_max_attachments_per_message = (
        row.support_max_attachments_per_message if row.support_max_attachments_per_message is not None else 5
    )
    runtime.notify_admin_on_ticket_created = bool(row.notify_admin_on_ticket_created)

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


def migrate_legacy_smtp_provider(db: Session) -> None:
    """One-time backfill for the multi-provider Outbound Email system
    (models.EmailProvider, email_providers.py, routes/email_providers.py):
    if no EmailProvider row exists yet but legacy SMTP settings ARE
    configured (either already saved to AppSettings via the old Settings
    form, or only ever set via SMTP_* env vars on a fresh install that's
    never touched Settings at all), create a "Primary SMTP" provider
    profile from them and mark it the default -- so an existing
    deployment keeps sending exactly the same way after upgrading to this
    version, with zero manual reconfiguration (see this task's own
    "Migration & Backward Compatibility" requirement).

    No-op once ANY EmailProvider row exists (whether created by this
    migration on a previous startup, or an admin adding one directly),
    so this is safe to call on every startup, not just the first --
    same idempotent-migration shape as auth.ensure_bootstrap_admin_flag.
    Also a no-op if nothing was ever configured (a genuinely fresh
    install with no SMTP_HOST env var and nothing saved) -- there's
    nothing to migrate, an admin sets up their first provider from
    scratch via Settings."""
    import json

    from .email_providers import PROVIDERS
    from .models import EmailProvider

    if db.query(EmailProvider).first() is not None:
        return
    row = get_settings_row(db)
    host = row.smtp_host if row.smtp_host is not None else env_settings.SMTP_HOST
    if not host:
        return
    port = row.smtp_port if row.smtp_port is not None else env_settings.SMTP_PORT
    username = row.smtp_username if row.smtp_username is not None else env_settings.SMTP_USERNAME
    password = row.smtp_password if row.smtp_password is not None else env_settings.SMTP_PASSWORD
    from_email = row.smtp_from if row.smtp_from is not None else env_settings.SMTP_FROM
    use_tls = row.smtp_use_tls if row.smtp_use_tls is not None else env_settings.SMTP_USE_TLS
    config = {
        "host": host,
        "port": port,
        "username": username or "",
        "password": password or "",
        # The old single boolean only ever meant STARTTLS-or-plaintext --
        # see email_providers.SMTPEmailProvider's own comment on why this
        # is now a real 3-state choice going forward.
        "encryption": "starttls" if use_tls else "none",
        "from_email": from_email or username or "",
        "from_name": "",
    }
    # validate_config() isn't called here deliberately -- a legacy config
    # that was good enough to actually send mail with before this
    # migration should keep working exactly as-is even if it wouldn't
    # pass a freshly-tightened validation rule; the SMTP provider's own
    # PROVIDERS entry both defines the field shape and IS what mailer.py
    # will send through going forward, so importing it here (rather than
    # hardcoding "smtp" as a bare string) keeps this migration and the
    # provider registry from ever silently drifting apart.
    smtp_type_key = PROVIDERS["smtp"].type_key
    provider = EmailProvider(name="Primary SMTP", provider_type=smtp_type_key, is_active=True, is_default=True, config=json.dumps(config))
    db.add(provider)
    db.commit()


def migrate_decouple_portal_and_vpn_restrictions(db: Session) -> None:
    """One-time backfill for separating Portal Login Restrictions
    (User.restrict_login_by_country/city/asn/ip, enforced only by
    routes/auth.py's login check) from VPN Access Restrictions
    (policy_store's per-client allowed_countries/cities/asns/ips,
    enforced only by host-scripts/openvpn-mac-addr-check.py).

    Before this change, routes/users.py's create_user/update_user pushed
    a User's Portal restriction values straight into that same user's
    linked VPN profile's policy on every save -- the two systems were
    reading independent storage (User columns vs. client_policy.json) but
    always held the SAME values, because one write path kept overwriting
    the other. That sync is now removed (see users.py), so the two are
    free to diverge going forward -- but on an *existing* deployment,
    stopping the sync cold would silently make VPN connections
    UNRESTRICTED for anyone who only ever set a "restrict by X" toggle
    through the (now VPN-blind) Portal Restrictions UI, without them ever
    touching the Clients page's independent Manage Restrictions dialog.
    That's a real security regression, not just a UX one.

    So: for every user with any restrict_login_by_* flag on and a linked
    VPN profile, copy that value into the profile's policy ONCE -- a
    resulting VPN Access Restriction that exactly mirrors what the old
    coupled behavior already enforced, preserving current behavior. Only
    ever fills in a restriction that's actively toggled on; a restriction
    left off is not touched (nothing to preserve). From that point on,
    admins/users are free to edit Portal and VPN restrictions
    independently and they'll never be silently re-synced.

    Needs a REAL one-time marker (AppSettings.restrictions_decoupled_at),
    unlike most of this app's startup migrations, which are safely
    re-runnable because they check "does the target data already exist"
    (see migrate_legacy_smtp_provider above). Here, "the VPN policy
    doesn't have this restriction" is not a proxy for "hasn't been
    migrated yet" -- it's also exactly what "an admin/user deliberately
    cleared the VPN-side restriction after migrating, keeping the
    Portal-side one" looks like. Re-running on every startup would
    silently re-impose a VPN restriction someone intentionally removed.
    A persisted timestamp is the only way to tell those apart."""
    from . import policy_store
    from .models import User

    row = get_settings_row(db)
    if row.restrictions_decoupled_at is not None:
        return

    users = db.query(User).filter(
        User.restrict_login_by_country.is_(True) | User.restrict_login_by_city.is_(True)
        | User.restrict_login_by_asn.is_(True) | User.restrict_login_by_ip.is_(True)
    ).all()
    for user in users:
        if user.vpn_profile_link is None:
            continue
        import json as _json
        try:
            policy_store.set_policy(
                user.vpn_profile_link.vpn_client_name,
                allowed_countries=_json.loads(user.allowed_login_countries or "[]") if user.restrict_login_by_country else ...,
                allowed_cities=_json.loads(user.allowed_login_cities or "[]") if user.restrict_login_by_city else ...,
                allowed_asns=_json.loads(user.allowed_login_asns or "[]") if user.restrict_login_by_asn else ...,
                allowed_ips=_json.loads(user.allowed_login_ips or "[]") if user.restrict_login_by_ip else ...,
            )
        except (policy_store.PolicyValidationError, OSError):
            # Best-effort, matching every other startup migration's
            # posture -- a malformed legacy value or filesystem hiccup for
            # one user must never block the whole app from starting, or
            # from finishing this pass for every other user.
            continue

    row.restrictions_decoupled_at = datetime.now(timezone.utc)
    db.commit()


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


def prune_connection_rejections(db: Session) -> int:
    """Same shape as prune_audit_log()/prune_db_stat_snapshots() above,
    against ConnectionRejectionLog instead -- see
    runtime.connection_issue_retention_days' own comment in
    refresh_runtime_cache()."""
    from datetime import timedelta

    from .models import ConnectionRejectionLog

    if not runtime.connection_issue_retention_days:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=runtime.connection_issue_retention_days)
    deleted = db.query(ConnectionRejectionLog).filter(ConnectionRejectionLog.timestamp < cutoff).delete(synchronize_session=False)
    db.commit()
    return deleted
