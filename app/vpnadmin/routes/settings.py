import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator, model_validator
from sqlalchemy.orm import Session

from .. import captcha, mailer, policy_store
from ..app_settings import ACTIVE_THEME_IDS, SECRET_PLACEHOLDER, THEME_CHOICES, get_settings_row, refresh_runtime_cache, runtime
from ..audit import log_action
from ..config import settings as env_settings
from ..db import get_db
from ..models import RoleDef, User
from ..permissions import require_permission

router = APIRouter(prefix="/api/settings", tags=["settings"])

require_admin = require_permission("settings", "manage")  # former auth.require_admin, see permissions.py

_CAPTCHA_PROVIDERS = ("turnstile", "recaptcha")


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
    password_history_count: int | None = None
    audit_retention_days: int | None = None
    connection_issue_retention_days: int | None = None
    log_failed_login_attempts: bool | None = None
    notification_duration_ms: int | None = None

    default_new_user_role: str | None = None
    default_bandwidth_monthly_gb: float | None = None
    default_quota_enforcement_policy: str | None = None
    allow_duplicate_macs: bool | None = None
    min_session_duration_seconds: int | None = None

    # Support Ticketing System -- admin-tweakable preferences, see
    # AppSettings' own columns for why these aren't hardcoded constants.
    support_ticket_rate_limit_count: int | None = None
    support_ticket_rate_limit_window_minutes: int | None = None
    support_max_attachment_size_mb: int | None = None
    support_max_attachments_per_message: int | None = None
    notify_admin_on_ticket_created: bool | None = None

    # Multi-Factor Authentication (TOTP) -- see mfa.py's effective_policy /
    # models.py's AppSettings columns for the full precedence design.
    mfa_mode: str | None = None
    mfa_role_requirements: dict[str, str] | None = None
    mfa_remember_device_days: int | None = None
    notify_admin_on_mfa_disabled: bool | None = None

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

    # Optional integrations (see features.py) -- MaxMind GeoIP.
    geoip_enabled: bool | None = None
    maxmind_license_key: str | None = None

    # Optional integrations -- CAPTCHA. captcha_provider "" (empty string,
    # distinct from None/omitted) explicitly disables CAPTCHA -- see its
    # own validator below for why that distinction matters for a PATCH
    # endpoint where "field omitted" already means something else (leave
    # unchanged).
    captcha_provider: str | None = None
    turnstile_site_key: str | None = None
    turnstile_secret_key: str | None = None
    recaptcha_site_key: str | None = None
    recaptcha_secret_key: str | None = None

    @field_validator("maxmind_license_key")
    @classmethod
    def _maxmind_key_format(cls, v: str | None) -> str | None:
        # Same sanity-only format check as setup.sh's --maxmind-key and
        # cli/openvpn_admin.py's _upsert_maxmind_key -- an obvious paste
        # error caught here, before ever reaching the host action. Real
        # validation against MaxMind's own service happens via the
        # separate POST /api/settings/geoip/validate endpoint below, which
        # the Settings page calls before Save, not as part of this schema.
        v = (v or "").strip() or None
        if v == SECRET_PLACEHOLDER:
            return v  # "unchanged" sentinel, handled in update_settings() below
        if v and not re.match(r"^[A-Za-z0-9_-]{10,}$", v):
            raise ValueError("Doesn't look like a valid MaxMind license key (expected 10+ alphanumeric/_/- characters).")
        return v

    @field_validator("captcha_provider")
    @classmethod
    def _captcha_provider_choice(cls, v: str | None) -> str | None:
        # "" is a real, meaningful value here ("explicitly disabled"), NOT
        # normalized to None the way most other optional string fields on
        # this schema are -- None means "field omitted, don't touch",
        # blank-string None-coalescing would make "disable CAPTCHA" and
        # "leave CAPTCHA alone" indistinguishable over this PATCH endpoint.
        if v is not None and v != "" and v not in _CAPTCHA_PROVIDERS:
            raise ValueError(f"CAPTCHA provider must be blank (disabled), or one of: {', '.join(_CAPTCHA_PROVIDERS)}.")
        return v

    @field_validator("turnstile_site_key", "turnstile_secret_key", "recaptcha_site_key", "recaptcha_secret_key")
    @classmethod
    def _captcha_key_strip(cls, v: str | None) -> str | None:
        return (v or "").strip() or None

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

    @field_validator("password_history_count")
    @classmethod
    def _password_history_count(cls, v):
        if v is not None and not (0 <= v <= 50):
            raise ValueError("Password history count must be between 0 (disabled) and 50.")
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

    @field_validator("connection_issue_retention_days")
    @classmethod
    def _connection_issue_retention(cls, v):
        if v is not None and v < 0:
            raise ValueError("Connection issue log retention can't be negative.")
        return v

    @field_validator("min_session_duration_seconds")
    @classmethod
    def _min_session_duration(cls, v):
        # Upper bound is a sanity cap (10 minutes) -- this setting is meant
        # to filter out near-instant network blips, not to reclassify
        # genuinely short-but-real sessions as noise.
        if v is not None and not (0 <= v <= 600):
            raise ValueError("Minimum session duration must be between 0 and 600 seconds.")
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

    @field_validator("support_ticket_rate_limit_count", "support_ticket_rate_limit_window_minutes",
                      "support_max_attachment_size_mb", "support_max_attachments_per_message")
    @classmethod
    def _support_tunable_positive(cls, v):
        if v is not None and v < 1:
            raise ValueError("Support ticketing limits must be at least 1.")
        return v

    @field_validator("mfa_mode")
    @classmethod
    def _mfa_mode_choice(cls, v: str | None) -> str | None:
        if v is not None and v not in ("disabled", "optional", "required"):
            raise ValueError("MFA mode must be 'disabled', 'optional', or 'required'.")
        return v

    @field_validator("mfa_role_requirements")
    @classmethod
    def _mfa_role_requirements_values(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        # Role SLUGS themselves are validated against the live RoleDef
        # table in update_settings() below (needs a DB session, not
        # available in a plain field validator) -- this only checks the
        # per-role VALUE is one of the three real policies, same set
        # mfa.VALID_POLICY_OVERRIDES / User.mfa_policy_override accept.
        if v is None:
            return v
        from ..mfa import VALID_POLICY_OVERRIDES
        for slug, policy in v.items():
            if policy not in VALID_POLICY_OVERRIDES:
                raise ValueError(f"MFA requirement for role '{slug}' must be one of: {', '.join(VALID_POLICY_OVERRIDES)}.")
        return v

    @field_validator("mfa_remember_device_days")
    @classmethod
    def _mfa_remember_device_days_range(cls, v):
        # 0 = disabled (the default) -- only negative/absurdly-large values
        # are rejected; the Settings UI offers 7/14/30/Custom but any
        # positive day count is a legitimate "Custom" entry.
        if v is not None and not (0 <= v <= 365):
            raise ValueError("Remember-device duration must be between 0 (disabled) and 365 days.")
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
        "password_history_count": s.password_history_count,
        "audit_retention_days": s.audit_retention_days,
        "connection_issue_retention_days": s.connection_issue_retention_days,
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
        "allow_duplicate_macs": bool(s.allow_duplicate_macs),
        "min_session_duration_seconds": s.min_session_duration_seconds if s.min_session_duration_seconds is not None else 3,
        "support_ticket_rate_limit_count": s.support_ticket_rate_limit_count if s.support_ticket_rate_limit_count is not None else 5,
        "support_ticket_rate_limit_window_minutes": (
            s.support_ticket_rate_limit_window_minutes if s.support_ticket_rate_limit_window_minutes is not None else 60
        ),
        "support_max_attachment_size_mb": s.support_max_attachment_size_mb if s.support_max_attachment_size_mb is not None else 10,
        "support_max_attachments_per_message": (
            s.support_max_attachments_per_message if s.support_max_attachments_per_message is not None else 5
        ),
        "notify_admin_on_ticket_created": bool(s.notify_admin_on_ticket_created),
        "mfa_mode": s.mfa_mode,
        "mfa_role_requirements": json.loads(s.mfa_role_requirements) if s.mfa_role_requirements else {},
        "mfa_remember_device_days": s.mfa_remember_device_days,
        "notify_admin_on_mfa_disabled": bool(s.notify_admin_on_mfa_disabled),
        "reports_default_range_days": s.reports_default_range_days,
        "db_snapshot_retention_days": s.db_snapshot_retention_days,
        "maintenance_mode": s.maintenance_mode,
        "maintenance_message": s.maintenance_message,
        "notification_duration_ms": s.notification_duration_ms,
        "login_theme": s.login_theme or "auto",
        "timezone": s.timezone,
        "time_format": s.time_format,
        # Optional integrations -- see features.py.
        "geoip_enabled": s.geoip_enabled,
        "maxmind_license_key": SECRET_PLACEHOLDER if s.maxmind_license_key else None,
        "captcha_provider": s.captcha_provider or "",
        # Site keys are public by design (shipped to every visitor's
        # browser already) -- not masked, unlike the two secret keys below.
        "turnstile_site_key": s.turnstile_site_key,
        "turnstile_secret_key": SECRET_PLACEHOLDER if s.turnstile_secret_key else None,
        "recaptcha_site_key": s.recaptcha_site_key,
        "recaptcha_secret_key": SECRET_PLACEHOLDER if s.recaptcha_secret_key else None,
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
    # Lets the Settings page distinguish "toggled on but the DB hasn't
    # downloaded yet" from "actually working" -- see features.geoip_enabled's
    # own AND-with-file-presence logic, surfaced here for the UI (Diagnostics-
    # style status line under the GeoIP card), not just enforced server-side.
    from pathlib import Path
    body["geoip_country_db_present"] = Path(env_settings.GEOIP_DB_PATH).is_file()
    body["geoip_city_db_present"] = Path(env_settings.GEOIP_CITY_DB_PATH).is_file()
    body["geoip_asn_db_present"] = Path(env_settings.GEOIP_ASN_DB_PATH).is_file()
    return body


@router.patch("")
def update_settings(body: UpdateSettingsRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if body.default_new_user_role is not None:
        if not db.query(RoleDef).filter(RoleDef.slug == body.default_new_user_role).first():
            raise HTTPException(status_code=400, detail=f"No such role: '{body.default_new_user_role}'.")
    row = get_settings_row(db)
    fields_set = body.model_fields_set
    changes = []
    # Captured before the loop below can touch it -- feeds the dedicated
    # mac_duplicate_policy_changed audit entry after the loop (see there).
    prev_allow_duplicate_macs = bool(row.allow_duplicate_macs)
    prev_mfa_mode = row.mfa_mode or "optional"

    if body.mfa_role_requirements is not None:
        valid_slugs = {r.slug for r in db.query(RoleDef).all()}
        unknown = set(body.mfa_role_requirements) - valid_slugs
        if unknown:
            raise HTTPException(status_code=400, detail=f"No such role(s): {', '.join(sorted(unknown))}.")

    for field in ("portal_url", "min_password_length",
                   "session_timeout_minutes", "account_lockout_threshold", "account_lockout_minutes",
                   "password_history_count",
                   "audit_retention_days", "connection_issue_retention_days", "log_failed_login_attempts", "default_new_user_role",
                   "default_bandwidth_monthly_gb", "default_quota_enforcement_policy", "allow_duplicate_macs",
                   "min_session_duration_seconds", "admin_notification_email",
                   "notify_admin_on_user_created", "notify_admin_on_client_revoked",
                   "quota_notify_warning_pct", "quota_notify_critical_pct", "notify_admin_on_quota_critical",
                   "support_ticket_rate_limit_count", "support_ticket_rate_limit_window_minutes",
                   "support_max_attachment_size_mb", "support_max_attachments_per_message", "notify_admin_on_ticket_created",
                   "mfa_mode", "mfa_remember_device_days", "notify_admin_on_mfa_disabled",
                   "reports_default_range_days", "db_snapshot_retention_days", "maintenance_mode", "maintenance_message",
                   "notification_duration_ms", "login_theme", "timezone", "time_format",
                   "geoip_enabled"):
        if field in fields_set:
            value = getattr(body, field)
            if value != getattr(row, field):
                setattr(row, field, value)
                changes.append(field)

    # mfa_role_requirements: a dict on the request, a JSON string on the
    # column -- handled separately from the simple-value loop above for
    # that reason (an empty dict {} means "clear every per-role override",
    # stored as NULL rather than the literal string "{}", so
    # app_settings.py's refresh_runtime_cache's falsy-check keeps treating
    # "no overrides" as NULL either way).
    if "mfa_role_requirements" in fields_set:
        new_value = json.dumps(body.mfa_role_requirements) if body.mfa_role_requirements else None
        if new_value != row.mfa_role_requirements:
            row.mfa_role_requirements = new_value
            changes.append("mfa_role_requirements")

    # Secret-bearing fields: an incoming value exactly equal to
    # SECRET_PLACEHOLDER means "unchanged" (the Settings page always
    # round-trips whatever GET returned, which is the placeholder for any
    # already-set secret -- see _serialize()) -- same convention
    # email_providers.py's own PATCH endpoint already established. Site
    # keys (turnstile_site_key/recaptcha_site_key) are plain fields, not
    # secrets, and go through the loop above unmasked.
    for field in ("maxmind_license_key", "turnstile_secret_key", "recaptcha_secret_key"):
        if field in fields_set:
            value = getattr(body, field)
            if value == SECRET_PLACEHOLDER:
                continue
            if value != getattr(row, field):
                setattr(row, field, value)
                changes.append(field)

    if "captcha_provider" in fields_set:
        # "" is the real "explicitly disabled" value (see the schema's own
        # validator) -- distinct from omitted, which reaches this branch
        # not at all (fields_set check above).
        new_provider = body.captcha_provider or None
        if new_provider != row.captcha_provider:
            row.captcha_provider = new_provider
            changes.append("captcha_provider")
    if "turnstile_site_key" in fields_set and body.turnstile_site_key != row.turnstile_site_key:
        row.turnstile_site_key = body.turnstile_site_key
        changes.append("turnstile_site_key")
    if "recaptcha_site_key" in fields_set and body.recaptcha_site_key != row.recaptcha_site_key:
        row.recaptcha_site_key = body.recaptcha_site_key
        changes.append("recaptcha_site_key")

    # Each of these three checks only fires when THIS request actually
    # touches the field group in question -- not just because the DB
    # already happens to be in that state. Settings has one page-wide Save
    # button, not a Save per card, so every save round-trips the entire
    # form; without this guard, an incomplete CAPTCHA/GeoIP/notification
    # config left over from an earlier save (e.g. a provider picked but
    # its keys never finished being typed in) would permanently block
    # every future save of anything else on the page, not just that one
    # card, until an admin happened to notice and fix the unrelated
    # section. Confirmed live: an admin's Security-only change (lockout/
    # password-history fields, no CAPTCHA field touched at all) was
    # rejected with "Turnstile requires both a site key and a secret
    # key." because captcha_provider was already "turnstile" in the DB
    # from an earlier incomplete save.
    captcha_touched = bool({"captcha_provider", "turnstile_site_key", "turnstile_secret_key",
                             "recaptcha_site_key", "recaptcha_secret_key"} & fields_set)
    if captcha_touched:
        if row.captcha_provider == "turnstile" and not (row.turnstile_site_key and row.turnstile_secret_key):
            raise HTTPException(status_code=400, detail="Turnstile requires both a site key and a secret key.")
        if row.captcha_provider == "recaptcha" and not (row.recaptcha_site_key and row.recaptcha_secret_key):
            raise HTTPException(status_code=400, detail="reCAPTCHA requires both a site key and a secret key.")

    if "geoip_enabled" in fields_set or "maxmind_license_key" in fields_set:
        if row.geoip_enabled and not row.maxmind_license_key:
            raise HTTPException(status_code=400, detail="A MaxMind license key is required to enable Geo/IP.")

    notify_fields = {"notify_admin_on_user_created", "notify_admin_on_client_revoked",
                      "notify_admin_on_quota_critical", "notify_admin_on_ticket_created",
                      "notify_admin_on_mfa_disabled", "admin_notification_email"}
    if notify_fields & fields_set:
        if (row.notify_admin_on_user_created or row.notify_admin_on_client_revoked
                or row.notify_admin_on_quota_critical or row.notify_admin_on_ticket_created
                or row.notify_admin_on_mfa_disabled) and not row.admin_notification_email:
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
        # A dedicated, directly searchable audit action for this one
        # security-relevant toggle -- see the spec's explicit ask for
        # "previous value, new value" on enabling/disabling duplicate MAC
        # support, beyond what the generic update_settings line above
        # (field names only, no values) already records.
        if "allow_duplicate_macs" in changes:
            new_allow_duplicate_macs = bool(row.allow_duplicate_macs)
            log_action(
                db, admin, "mac_duplicate_policy_changed",
                detail=f"{'enabled' if prev_allow_duplicate_macs else 'disabled'} -> "
                       f"{'enabled' if new_allow_duplicate_macs else 'disabled'}",
            )
        # Same "dedicated, directly searchable audit action with old/new
        # values" treatment for the global MFA mode -- this is the one
        # setting change the spec explicitly lists under "MFA settings
        # changed" user/admin-facing events.
        if "mfa_mode" in changes:
            log_action(db, admin, "mfa_mode_changed", detail=f"{prev_mfa_mode} -> {row.mfa_mode or 'optional'}")
    return _serialize()


# --- Optional integrations: MaxMind GeoIP -----------------------------------

class ValidateGeoipKeyRequest(BaseModel):
    license_key: str


@router.post("/geoip/validate")
def validate_geoip_key(body: ValidateGeoipKeyRequest, _: User = Depends(require_admin)):
    """Checks a MaxMind license key against MaxMind's own download
    endpoint -- the SAME URL geoip-update.sh's fetch_edition already
    downloads from -- but only reads the HTTP status (200 = valid, 401/403
    = bad/revoked key), never the response body, so this is fast (no
    multi-MB archive transfer) and stdlib-only (urllib, same "no new
    dependency" convention as captcha.py/mailer.py). Called by the
    Settings page's "Validate Key" button, BEFORE Save -- this never
    writes anything, purely a read-only check against MaxMind."""
    import urllib.error
    import urllib.request

    key = body.license_key.strip()
    if not re.match(r"^[A-Za-z0-9_-]{10,}$", key):
        raise HTTPException(status_code=400, detail="Doesn't look like a valid MaxMind license key.")
    url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={key}&suffix=tar.gz"
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=10) as resp:
            valid = resp.status == 200
    except urllib.error.HTTPError as e:
        valid = False
        if e.code not in (401, 403):
            # An unexpected status (not the two MaxMind uses for a bad
            # key) -- surface it rather than silently reporting "invalid",
            # which would be misleading if e.g. MaxMind itself is down.
            raise HTTPException(status_code=502, detail=f"MaxMind returned an unexpected status ({e.code}) -- try again shortly.")
    except (urllib.error.URLError, TimeoutError):
        raise HTTPException(status_code=502, detail="Could not reach MaxMind to validate this key -- check network connectivity and try again.")
    return {"valid": valid}


def _host_executor_config():
    from services.system.host_executor import HostExecutorConfig

    if not env_settings.HOST_SSH_TARGET or not env_settings.HOST_SSH_KEY_PATH:
        raise HTTPException(
            status_code=400,
            detail="Host executor is not configured -- set HOST_SSH_TARGET and "
            "HOST_SSH_KEY_PATH (see .env.example) before GeoIP refresh can run.",
        )
    return HostExecutorConfig(
        ssh_key_path=env_settings.HOST_SSH_KEY_PATH,
        ssh_target=env_settings.HOST_SSH_TARGET,
        remote_script_path=env_settings.HOST_SSH_REMOTE_SCRIPT_PATH,
        use_sudo=env_settings.HOST_SSH_USE_SUDO,
        timeout_seconds=max(env_settings.HOST_SSH_TIMEOUT_SECONDS, 300),  # a real download can take longer than a session kill
        ssh_port=env_settings.HOST_SSH_PORT,
    )


@router.post("/geoip/refresh")
def refresh_geoip(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Triggers the host-side "geoip-update" action (see
    cli/openvpn_admin.py's _geoip_update / host_executor.py) -- writes the
    currently-saved maxmind_license_key into the host's vpn-tools.conf (if
    set) and re-runs geoip-update.sh. Separate from PATCH /api/settings on
    purpose: PATCH only ever touches the DB, fast and side-effect-free;
    this is the one explicit action that reaches out over SSH and can take
    up to a few minutes (3 full GeoLite2 editions), so the Settings page
    calls it explicitly (its "Save & Refresh Databases" button) rather
    than it being an invisible side effect of every settings save,
    including ones that never touched GeoIP at all."""
    from services.openvpn.exceptions import HostExecutorError, OpenVPNError
    from services.system.host_executor import run_host_command

    row = get_settings_row(db)
    if not row.geoip_enabled:
        raise HTTPException(status_code=400, detail="Enable Geo/IP and save before refreshing.")
    if not row.maxmind_license_key:
        raise HTTPException(status_code=400, detail="No MaxMind license key is saved yet.")

    config = _host_executor_config()
    try:
        args = ["--license-key", row.maxmind_license_key]
        data = run_host_command(config, "geoip-update", *args)
    except (OpenVPNError, HostExecutorError) as e:
        raise HTTPException(status_code=502, detail=f"GeoIP refresh failed: {e.detail}")
    log_action(db, admin, "geoip_refresh", detail="triggered via Settings")
    return data


# --- Optional integrations: CAPTCHA ------------------------------------------

class TestCaptchaRequest(BaseModel):
    provider: str
    secret_key: str | None = None

    @field_validator("provider")
    @classmethod
    def _valid_provider(cls, v: str) -> str:
        if v not in _CAPTCHA_PROVIDERS:
            raise ValueError(f"provider must be one of: {', '.join(_CAPTCHA_PROVIDERS)}.")
        return v


@router.post("/captcha/test")
def test_captcha(body: TestCaptchaRequest, _: User = Depends(require_admin)):
    """Calls the GIVEN provider/secret_key's siteverify with a
    deliberately-invalid token and checks for a well-formed JSON response.
    Deliberately takes the provider/secret straight from the request body
    -- i.e. the Settings page's CURRENT form fields -- rather than reading
    whatever's already saved, same "test what was actually passed in, not
    necessarily the saved config" precedent as email_providers.py's own
    per-profile Test button. Found live: reading the saved/active config
    here meant typing a dummy secret into an unsaved or non-active
    provider's field and clicking Test silently re-tested a DIFFERENT,
    already-working provider instead, reporting success for values the
    admin never actually typed.

    A `secret_key` of None/blank/the mask placeholder means "use whatever
    is already saved for THIS specific provider" (not necessarily the
    currently-active one -- an admin can test a provider they haven't
    switched to yet), same placeholder-means-unchanged convention as the
    PATCH endpoint above."""
    secret_key = body.secret_key
    if not secret_key or secret_key == SECRET_PLACEHOLDER:
        secret_key = runtime.turnstile_secret_key if body.provider == "turnstile" else runtime.recaptcha_secret_key
    if not secret_key:
        raise HTTPException(status_code=400, detail="No secret key to test -- enter one first.")
    result = captcha.diagnostic_check(provider=body.provider, secret_key=secret_key)
    result["provider"] = body.provider
    if result["reachable"] and not result["secret_verifiable"]:
        result["note"] = ("Google's reCAPTCHA API can't confirm a secret key is valid this way -- only that "
                           "the provider is reachable. This secret could still be wrong; the real test is "
                           "attempting to log in with the widget.")
    else:
        result["note"] = ("This confirms the secret key is accepted and the provider is reachable -- "
                           "it does not exercise the actual widget, which needs a real browser round-trip.")
    return result


# Outbound email provider configuration/testing (SMTP, Resend, ...) moved
# to routes/email_providers.py's own router -- see that module's docstring.
# The single-SMTP-block /api/settings/smtp/test endpoint that used to live
# here is gone; its equivalent is now /api/email-providers/{id}/test,
# scoped to one profile among potentially several.
