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
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .config import settings as env_settings
from .models import AppSettings

# The placeholder returned in place of a real SMTP password by GET
# /api/settings -- never round-trip the actual secret to the browser. The
# PATCH endpoint treats this exact string as "unchanged, don't touch it".
SMTP_PASSWORD_PLACEHOLDER = "••••••••"


class _RuntimeSettings:
    """Plain attribute bag holding the currently-effective settings. A
    single shared instance (`runtime` below) is what templates/mailer.py/
    auth.py actually read -- see this module's docstring for why."""

    def __init__(self):
        self.app_name = env_settings.APP_NAME
        self.app_tagline = env_settings.APP_TAGLINE
        self.app_footer_credit = env_settings.APP_FOOTER_CREDIT
        self.smtp_host = env_settings.SMTP_HOST
        self.smtp_port = env_settings.SMTP_PORT
        self.smtp_username = env_settings.SMTP_USERNAME
        self.smtp_password = env_settings.SMTP_PASSWORD
        self.smtp_from = env_settings.SMTP_FROM
        self.smtp_use_tls = env_settings.SMTP_USE_TLS
        self.min_password_length = 8
        self.session_timeout_minutes = max(1, env_settings.SESSION_MAX_AGE_SECONDS // 60)
        self.audit_retention_days = None  # None/0 = keep forever


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
    runtime.app_name = row.app_name or env_settings.APP_NAME
    runtime.app_tagline = row.app_tagline or env_settings.APP_TAGLINE
    runtime.app_footer_credit = row.app_footer_credit if row.app_footer_credit is not None else env_settings.APP_FOOTER_CREDIT
    runtime.smtp_host = row.smtp_host if row.smtp_host is not None else env_settings.SMTP_HOST
    runtime.smtp_port = row.smtp_port if row.smtp_port is not None else env_settings.SMTP_PORT
    runtime.smtp_username = row.smtp_username if row.smtp_username is not None else env_settings.SMTP_USERNAME
    runtime.smtp_password = row.smtp_password if row.smtp_password is not None else env_settings.SMTP_PASSWORD
    runtime.smtp_from = row.smtp_from if row.smtp_from is not None else env_settings.SMTP_FROM
    runtime.smtp_use_tls = row.smtp_use_tls if row.smtp_use_tls is not None else env_settings.SMTP_USE_TLS
    runtime.min_password_length = row.min_password_length or 8
    runtime.session_timeout_minutes = row.session_timeout_minutes or max(1, env_settings.SESSION_MAX_AGE_SECONDS // 60)
    runtime.audit_retention_days = row.audit_retention_days


def apply_settings_globals(templates) -> None:
    """Registers the live `runtime` object (not a snapshot of its current
    values) as a Jinja2 global -- there are two separate Jinja2Templates
    instances in this app (routes/pages.py and routes/auth.py each create
    their own), so both need this applied, same as the branding globals it
    replaces. Templates read e.g. `{{ app_settings.app_name }}`; because
    `runtime` is a mutable object referenced by the globals dict (not a
    copied string), later changes to its attributes are visible on the
    very next render with no extra wiring."""
    templates.env.globals["app_settings"] = runtime


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
