import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator, model_validator
from sqlalchemy.orm import Session

from .. import mailer, policy_store
from ..app_settings import ACTIVE_THEME_IDS, THEME_CHOICES, get_settings_row, refresh_runtime_cache, runtime
from ..audit import log_action
from ..db import get_db
from ..models import RoleDef, User
from ..permissions import require_permission

router = APIRouter(prefix="/api/settings", tags=["settings"])

require_admin = require_permission("settings", "manage")  # former auth.require_admin, see permissions.py


class UpdateSettingsRequest(BaseModel):
    """Admin-only. Every field is optional -- omit anything you don't want
    to touch (see model_fields_set usage in the route below); this is a
    partial update, not a full replace. An explicit null clears that field
    back to its environment-variable default (see app_settings.py)."""
    portal_url: str | None = None

    min_password_length: int | None = None
    session_timeout_minutes: int | None = None
    account_lockout_threshold: int | None = None
    account_lockout_minutes: int | None = None
    audit_retention_days: int | None = None
    log_failed_login_attempts: bool | None = None
    notification_duration_ms: int | None = None

    default_new_user_role: str | None = None
    default_bandwidth_monthly_gb: float | None = None
    default_quota_enforcement_policy: str | None = None

    admin_notification_email: str | None = None
    notify_admin_on_user_created: bool | None = None
    notify_admin_on_client_revoked: bool | None = None

    quota_notify_warning_pct: int | None = None
    quota_notify_critical_pct: int | None = None
    notify_admin_on_quota_critical: bool | None = None

    reports_default_range_days: int | None = None
    db_snapshot_retention_days: int | None = None

    maintenance_mode: bool | None = None
    maintenance_message: str | None = None

    login_theme: str | None = None

    timezone: str | None = None
    time_format: str | None = None

    @field_validator("portal_url")
    @classmethod
    def _portal_url_format(cls, v: str | None) -> str | None:
        v = (v or "").strip() or None
        if v and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Portal URL must start with http:// or https://.")
        return v.rstrip("/") if v else v

    @field_validator("min_password_length")
    @classmethod
    def _min_pw_len(cls, v):
        if v is not None and not (6 <= v <= 128):
            raise ValueError("Minimum password length must be between 6 and 128.")
        return v

    @field_validator("session_timeout_minutes")
    @classmethod
    def _session_timeout(cls, v):
        if v is not None and v < 1:
            raise ValueError("Session timeout must be at least 1 minute.")
        return v

    @field_validator("audit_retention_days")
    @classmethod
    def _retention(cls, v):
        if v is not None and v < 0:
            raise ValueError("Audit log retention can't be negative.")
        return v

    @field_validator("notification_duration_ms")
    @classmethod
    def _notification_duration(cls, v):
        # Lower bound keeps a toast from flashing by too fast to read;
        # upper bound is a sanity cap, not a real design limit -- 30s is
        # already far longer than anyone would reasonably want a popup to
        # sit on screen.
        if v is not None and not (200 <= v <= 30000):
            raise ValueError("Notification duration must be between 200 and 30000 milliseconds.")
        return v

    @field_validator("account_lockout_threshold")
    @classmethod
    def _lockout_threshold(cls, v):
        # 0 is a valid, meaningful value (disables lockout entirely) --
        # only negative numbers are rejected.
        if v is not None and v < 0:
            raise ValueError("Account lockout threshold can't be negative.")
        return v

    @field_validator("account_lockout_minutes")
    @classmethod
    def _lockout_minutes(cls, v):
        if v is not None and v < 1:
            raise ValueError("Account lockout duration must be at least 1 minute.")
        return v

    @field_validator("default_bandwidth_monthly_gb")
    @classmethod
    def _default_bandwidth(cls, v):
        # Same minimum as the per-user quota field (policy_store.set_policy) --
        # anything smaller than 100MB isn't a meaningful monthly allowance.
        if v is not None and v < 0.1:
            raise ValueError("Default monthly bandwidth quota must be at least 0.1 GB, or left blank for unlimited.")
        return v

    @field_validator("default_quota_enforcement_policy")
    @classmethod
    def _default_quota_policy(cls, v: str | None) -> str | None:
        if v is not None and v not in policy_store.VALID_QUOTA_ENFORCEMENT_POLICIES:
            raise ValueError(f"Quota enforcement policy must be one of: {', '.join(sorted(policy_store.VALID_QUOTA_ENFORCEMENT_POLICIES))}.")
        return v

    @field_validator("admin_notification_email")
    @classmethod
    def _admin_email(cls, v: str | None) -> str | None:
        if v and not mailer.is_valid_email(v):
            raise ValueError("Admin notification email must be a valid email address.")
        return v

    @field_validator("quota_notify_warning_pct", "quota_notify_critical_pct")
    @classmethod
    def _quota_notify_pct_range(cls, v):
        if v is not None and not (1 <= v <= 99):
            raise ValueError("Quota notification thresholds must be between 1 and 99 percent.")
        return v

    @model_validator(mode="after")
    def _warning_below_critical(self):
        # Only checked when BOTH are present in this request -- a partial
        # update touching just one of the two can't validate a relationship
        # between values it doesn't have; update_settings() below re-checks
        # the resulting merged state for the same reason the SMTP/admin-email
        # cross-field checks there do.
        if self.quota_notify_warning_pct is not None and self.quota_notify_critical_pct is not None:
            if self.quota_notify_warning_pct >= self.quota_notify_critical_pct:
                raise ValueError("The warning threshold must be lower than the critical threshold.")
        return self

    @field_validator("reports_default_range_days")
    @classmethod
    def _reports_range(cls, v):
        # 0 = "All history" (see dashboard.html's Usage Analytics range
        # select, whose own options are 7/14/30/60/90/all).
        if v is not None and v not in (0, 7, 14, 30, 60, 90):
            raise ValueError("Default report range must be 0 (all history), 7, 14, 30, 60, or 90 days.")
        return v

    @field_validator("db_snapshot_retention_days")
    @classmethod
    def _db_snapshot_retention(cls, v):
        # Same "0/None = keep forever" convention as audit_retention_days
        # above -- no fixed enum of allowed values (unlike
        # reports_default_range_days, which mirrors a fixed <select>),
        # just a plain non-negative day count.
        if v is not None and v < 0:
            raise ValueError("Database snapshot retention can't be negative.")
        return v

    @field_validator("maintenance_message")
    @classmethod
    def _maintenance_msg(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 512:
            raise ValueError("Maintenance message must be 512 characters or fewer.")
        return v

    @field_validator("login_theme")
    @classmethod
    def _valid_theme(cls, v: str | None) -> str | None:
        if v is not None and v != "auto" and v not in ACTIVE_THEME_IDS:
            raise ValueError(f"Unknown theme '{v}'.")
        return v

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, v: str | None) -> str | None:
        # Format-only validation (not a whitelist against the IANA
        # database) -- the actual display conversion happens client-side
        # via Intl.DateTimeFormat's `timeZone` option (see static/app.js's
        # fmtTimestamp), against the BROWSER's own tz database, which is
        # both more complete and more current than anything this server
        # could ship (no OS tzdata package installed here -- see
        # config.py's APP_TIMEZONE docstring). "UTC" or "Region/City"
        # (optionally with a second "/Subcity", e.g. "America/Argentina/
        # Buenos_Aires") covers every real IANA zone name.
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("Timezone cannot be blank.")
        if v != "UTC" and not re.match(r"^[A-Za-z_]+(/[A-Za-z_+-]+){1,2}$", v):
            raise ValueError(f"'{v}' doesn't look like a valid IANA timezone name (e.g. 'UTC' or 'Asia/Karachi').")
        return v

    @field_validator("time_format")
    @classmethod
    def _valid_time_format(cls, v: str | None) -> str | None:
        if v is not None and v not in ("24h", "12h"):
            raise ValueError("Time format must be '24h' or '12h'.")
        return v


def _serialize() -> dict:
    s = runtime
    return {
        "portal_url": s.portal_url,
        "min_password_length": s.min_password_length,
        "session_timeout_minutes": s.session_timeout_minutes,
        "account_lockout_threshold": s.account_lockout_threshold,
        "account_lockout_minutes": s.account_lockout_minutes,
        "audit_retention_days": s.audit_retention_days,
        "log_failed_login_attempts": s.log_failed_login_attempts,
        "default_new_user_role": s.default_new_user_role,
        "default_bandwidth_monthly_gb": s.default_bandwidth_monthly_gb,
        "default_quota_enforcement_policy": s.default_quota_enforcement_policy,
        "admin_notification_email": s.admin_notification_email,
        "notify_admin_on_user_created": s.notify_admin_on_user_created,
        "notify_admin_on_client_revoked": s.notify_admin_on_client_revoked,
        "quota_notify_warning_pct": s.quota_notify_warning_pct,
        "quota_notify_critical_pct": s.quota_notify_critical_pct,
        "notify_admin_on_quota_critical": s.notify_admin_on_quota_critical,
        "reports_default_range_days": s.reports_default_range_days,
        "db_snapshot_retention_days": s.db_snapshot_retention_days,
        "maintenance_mode": s.maintenance_mode,
        "maintenance_message": s.maintenance_message,
        "notification_duration_ms": s.notification_duration_ms,
        "login_theme": s.login_theme or "auto",
        "timezone": s.timezone,
        "time_format": s.time_format,
    }


@router.get("")
def get_settings(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    body = _serialize()
    body["theme_choices"] = THEME_CHOICES
    # Role choices for the "Default Role for New Users" dropdown (User
    # Management card) -- same RoleDef rows the Add User form itself
    # offers, so an admin can only ever pick a role that actually exists.
    # Excludes super_admin for the same reason create_user() already
    # forbids assigning it (see routes/users.py's _resolve_creatable_role).
    body["role_choices"] = [
        {"slug": r.slug, "name": r.name}
        for r in db.query(RoleDef).filter(RoleDef.slug != "super_admin").order_by(RoleDef.name).all()
    ]
    return body


@router.patch("")
def update_settings(body: UpdateSettingsRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if body.default_new_user_role is not None:
        if not db.query(RoleDef).filter(RoleDef.slug == body.default_new_user_role).first():
            raise HTTPException(status_code=400, detail=f"No such role: '{body.default_new_user_role}'.")
    row = get_settings_row(db)
    fields_set = body.model_fields_set
    changes = []

    for field in ("portal_url", "min_password_length",
                   "session_timeout_minutes", "account_lockout_threshold", "account_lockout_minutes",
                   "audit_retention_days", "log_failed_login_attempts", "default_new_user_role",
                   "default_bandwidth_monthly_gb", "default_quota_enforcement_policy", "admin_notification_email",
                   "notify_admin_on_user_created", "notify_admin_on_client_revoked",
                   "quota_notify_warning_pct", "quota_notify_critical_pct", "notify_admin_on_quota_critical",
                   "reports_default_range_days", "db_snapshot_retention_days", "maintenance_mode", "maintenance_message",
                   "notification_duration_ms", "login_theme", "timezone", "time_format"):
        if field in fields_set:
            value = getattr(body, field)
            if value != getattr(row, field):
                setattr(row, field, value)
                changes.append(field)

    if (row.notify_admin_on_user_created or row.notify_admin_on_client_revoked or row.notify_admin_on_quota_critical) and not row.admin_notification_email:
        raise HTTPException(status_code=400, detail="An admin notification email is required to enable event notifications.")

    # Same "check the resulting merged state, not just this request's own
    # fields" reasoning as the SMTP/admin-email checks above -- a request
    # that only touches one of the two threshold fields still needs this
    # checked against whatever the OTHER one ends up being (already-saved
    # or just-defaulted), not skipped just because this particular request
    # didn't mention it.
    effective_warning = row.quota_notify_warning_pct if row.quota_notify_warning_pct is not None else 80
    effective_critical = row.quota_notify_critical_pct if row.quota_notify_critical_pct is not None else 95
    if effective_warning >= effective_critical:
        raise HTTPException(status_code=400, detail="The warning threshold must be lower than the critical threshold.")

    if changes:
        row.updated_at = datetime.now(timezone.utc)
        row.updated_by = admin.username
        db.commit()
        refresh_runtime_cache(db)
        log_action(db, admin, "update_settings", detail="; ".join(changes))
    return _serialize()


# Outbound email provider configuration/testing (SMTP, Resend, ...) moved
# to routes/email_providers.py's own router -- see that module's docstring.
# The single-SMTP-block /api/settings/smtp/test endpoint that used to live
# here is gone; its equivalent is now /api/email-providers/{id}/test,
# scoped to one profile among potentially several.
