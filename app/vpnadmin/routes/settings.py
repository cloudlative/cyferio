import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import mailer, policy_store
from ..app_settings import ACTIVE_THEME_IDS, SMTP_PASSWORD_PLACEHOLDER, THEME_CHOICES, get_settings_row, refresh_runtime_cache, runtime
from ..audit import log_action
from ..db import get_db
from ..models import RoleDef, User
from ..permissions import require_permission

router = APIRouter(prefix="/api/settings", tags=["settings"])

require_admin = require_permission("settings", "manage")  # former auth.require_admin, see permissions.py


def _valid_port(v: int | None) -> int | None:
    if v is not None and not (1 <= v <= 65535):
        raise ValueError("Port must be between 1 and 65535.")
    return v


class UpdateSettingsRequest(BaseModel):
    """Admin-only. Every field is optional -- omit anything you don't want
    to touch (see model_fields_set usage in the route below); this is a
    partial update, not a full replace. An explicit null clears that field
    back to its environment-variable default (see app_settings.py)."""
    app_name: str | None = None
    app_tagline: str | None = None
    app_footer_credit: str | None = None

    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None  # SMTP_PASSWORD_PLACEHOLDER = leave unchanged
    smtp_from: str | None = None
    smtp_use_tls: bool | None = None

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

    reports_default_range_days: int | None = None

    maintenance_mode: bool | None = None
    maintenance_message: str | None = None

    login_theme: str | None = None

    timezone: str | None = None
    time_format: str | None = None

    @field_validator("smtp_port")
    @classmethod
    def _port_range(cls, v):
        return _valid_port(v)

    @field_validator("smtp_from")
    @classmethod
    def _from_format(cls, v: str | None) -> str | None:
        if v and not mailer.is_valid_email(v):
            raise ValueError("From-address must be a valid email address.")
        return v

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

    @field_validator("reports_default_range_days")
    @classmethod
    def _reports_range(cls, v):
        # 0 = "All history" (see dashboard.html's Usage Analytics range
        # select, whose own options are 7/14/30/60/90/all).
        if v is not None and v not in (0, 7, 14, 30, 60, 90):
            raise ValueError("Default report range must be 0 (all history), 7, 14, 30, 60, or 90 days.")
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
        "app_name": s.app_name,
        "app_tagline": s.app_tagline,
        "app_footer_credit": s.app_footer_credit,
        "smtp_host": s.smtp_host,
        "smtp_port": s.smtp_port,
        "smtp_username": s.smtp_username,
        # Never round-trip the real secret to the browser.
        "smtp_password": SMTP_PASSWORD_PLACEHOLDER if s.smtp_password else "",
        "smtp_from": s.smtp_from,
        "smtp_use_tls": s.smtp_use_tls,
        "smtp_configured": bool(s.smtp_host),
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
        "reports_default_range_days": s.reports_default_range_days,
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

    for field in ("app_name", "app_tagline", "app_footer_credit", "smtp_host", "smtp_port",
                   "smtp_username", "smtp_from", "smtp_use_tls", "min_password_length",
                   "session_timeout_minutes", "account_lockout_threshold", "account_lockout_minutes",
                   "audit_retention_days", "log_failed_login_attempts", "default_new_user_role",
                   "default_bandwidth_monthly_gb", "default_quota_enforcement_policy", "admin_notification_email",
                   "notify_admin_on_user_created", "notify_admin_on_client_revoked",
                   "reports_default_range_days", "maintenance_mode", "maintenance_message",
                   "notification_duration_ms", "login_theme", "timezone", "time_format"):
        if field in fields_set:
            value = getattr(body, field)
            if value != getattr(row, field):
                setattr(row, field, value)
                changes.append(field)

    if "smtp_password" in fields_set:
        new_password = body.smtp_password
        if new_password != SMTP_PASSWORD_PLACEHOLDER and new_password != row.smtp_password:
            row.smtp_password = new_password
            changes.append("smtp_password")

    # Cross-field check on the RESULTING (post-merge) state, not just this
    # request's own fields -- a username/password set with no host at all
    # (whether from this request or already-saved) can never actually
    # authenticate anywhere.
    if (row.smtp_username or row.smtp_password) and not row.smtp_host:
        raise HTTPException(status_code=400, detail="SMTP host is required when a username or password is set.")

    if (row.notify_admin_on_user_created or row.notify_admin_on_client_revoked) and not row.admin_notification_email:
        raise HTTPException(status_code=400, detail="An admin notification email is required to enable event notifications.")

    if changes:
        row.updated_at = datetime.now(timezone.utc)
        row.updated_by = admin.username
        db.commit()
        refresh_runtime_cache(db)
        log_action(db, admin, "update_settings", detail="; ".join(changes))
    return _serialize()


class TestSmtpRequest(BaseModel):
    """Tests whatever SMTP values are currently in the Settings-page form --
    not necessarily what's already saved -- against a destination address,
    without persisting anything."""
    email: str
    smtp_host: str
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True

    @field_validator("email")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        v = v.strip()
        if not mailer.is_valid_email(v):
            raise ValueError("Please enter a valid destination email address.")
        return v

    @field_validator("smtp_host")
    @classmethod
    def _host_required(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("SMTP host is required to send a test email.")
        return v

    @field_validator("smtp_port")
    @classmethod
    def _port_range(cls, v):
        return _valid_port(v)


@router.post("/smtp/test")
def test_smtp(body: TestSmtpRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    password = body.smtp_password
    if password == SMTP_PASSWORD_PLACEHOLDER:
        # The form field still shows the masked placeholder because the
        # admin hasn't changed it -- test with the currently-effective
        # saved password, not the literal placeholder string.
        password = runtime.smtp_password

    try:
        mailer.send_test_email(
            to_address=body.email,
            host=body.smtp_host,
            port=body.smtp_port,
            username=body.smtp_username,
            password=password,
            from_address=body.smtp_from,
            use_tls=body.smtp_use_tls,
        )
    except Exception as e:
        log_action(db, admin, "test_smtp_settings", target=body.email, detail=f"failed: {e}", success=False)
        raise HTTPException(status_code=502, detail=f"Failed to send test email: {e}")

    log_action(db, admin, "test_smtp_settings", target=body.email, detail="sent successfully", success=True)
    return {"message": f"Test email sent to {body.email}."}
