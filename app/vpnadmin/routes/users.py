import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session, selectinload

from services.openvpn.exceptions import ValidationError as MacFormatError
from services.openvpn.validator import normalize_mac

from .. import app_settings, geo_lists, mailer, policy_store, vpn_identity_sync
from .. import cli_wrapper as cli
from ..audit import log_action
from ..auth import hash_password, require_user, verify_password
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..geo_validators import valid_asn_list as _valid_asn_list
from ..geo_validators import valid_city_list as _valid_city_list
from ..geo_validators import valid_country_list as _valid_country_list
from ..geo_validators import valid_ip_list as _valid_ip_list
from ..models import Gender, Role, RoleDef, Team, User, VpnProfileLink
from ..permissions import require_permission
from ..policy_store import PolicyValidationError

router = APIRouter(prefix="/api/users", tags=["users"])

require_admin = require_permission("users", "manage")  # former auth.require_admin, see permissions.py


def _resolve_role(db: Session, slug: str) -> RoleDef:
    """Same validate-then-resolve pattern as _resolve_teams below, for the
    role slug a CreateUserRequest/UpdateUserRequest carries -- kept as a
    plain slug string (not a role_id int) so the existing users.html
    <select> and any external API caller keeps working unchanged through
    this migration; Roles Management (Phase 5) can still create/reference
    custom roles by slug the same way."""
    role = db.query(RoleDef).filter(RoleDef.slug == slug.strip().lower()).first()
    if role is None:
        raise HTTPException(status_code=400, detail=f"No such role: '{slug}'.")
    return role


def _resolve_creatable_role(db: Session, slug: str) -> RoleDef:
    """Same as _resolve_role, but additionally rejects "super_admin" --
    reserved exclusively for the bootstrap admin account (see
    db.py's _promote_bootstrap_admin_to_super_admin), never assignable via
    Add User or an admin edit. Server-side backstop behind the Add-User
    dropdown already excluding it client-side (see users.html)."""
    role = _resolve_role(db, slug)
    if role.slug == "super_admin":
        raise HTTPException(status_code=400, detail="The Super Admin role can't be assigned -- it's reserved for the bootstrap admin account.")
    return role


_PW_UPPER_RE = re.compile(r"[A-Z]")
_PW_DIGIT_RE = re.compile(r"[0-9]")
# "Special character" == anything that isn't a letter or digit -- matches
# generateStrongPassword's own "!@#$%^&*-_=+?" class in app.js (a subset of
# this, not the full set), so every password that helper generates already
# satisfies this check, and this check itself doesn't require any specific
# symbol, just at least one from outside [A-Za-z0-9].
_PW_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")


def _valid_password(v: str) -> str:
    """Enforces this app's password complexity policy: minimum length
    (admin-configurable via Settings -> Security, read live off the runtime
    cache rather than hardcoded, so a changed policy applies to the very
    next request, not just after a restart -- see app_settings.py) plus a
    fixed set of complexity rules (uppercase, digit, special character)
    that apply regardless of the configured length. Used for account
    creation, admin password resets, and self-service password changes
    alike -- every path that ever sets a User.password_hash goes through
    this one function. Lists every unmet requirement in a single message
    (not just the first one hit) so a user isn't stuck fixing one problem
    at a time across repeated failed submits."""
    min_len = app_settings.runtime.min_password_length
    problems = []
    if len(v) < min_len:
        problems.append(f"at least {min_len} characters")
    if not _PW_UPPER_RE.search(v):
        problems.append("at least 1 uppercase letter")
    if not _PW_DIGIT_RE.search(v):
        problems.append("at least 1 number")
    if not _PW_SPECIAL_RE.search(v):
        problems.append("at least 1 special character")
    if problems:
        raise ValueError("Password must contain " + ", ".join(problems) + ".")
    return v


def _valid_first_name(v: str | None) -> str | None:
    """First Name is required (see task feedback): must be present and
    non-blank wherever this runs. Callers that allow the field to be
    entirely omitted (self-service password-only updates, admin edits that
    don't touch it) pass None through untouched -- this only rejects an
    explicitly-provided-but-blank value, it doesn't force every request to
    include the field."""
    if v is None:
        return None
    v = v.strip()
    if not v:
        raise ValueError("First Name is required.")
    return v


# Loose but real validation -- catches typos ("bob@@x", "bob@x") without
# chasing full RFC 5322 (this field is informational, not used for login or
# delivery today, see models.py's User.email comment). The base pattern is
# deliberately unchanged from before; the two extra structural checks below
# (no ".." anywhere, local part doesn't start/end with ".") catch a couple
# more common typos ("bob..smith@x.com", ".bob@x.com", "bob.@x.com") that
# the regex alone lets through, without chasing full RFC 5322 -- still just
# "does this look like a real address", not a deliverability guarantee.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _check_email_shape(v: str) -> None:
    if not _EMAIL_RE.match(v):
        raise ValueError("That doesn't look like a valid email address.")
    if ".." in v:
        raise ValueError("That doesn't look like a valid email address.")
    local = v.split("@", 1)[0]
    if local.startswith(".") or local.endswith("."):
        raise ValueError("That doesn't look like a valid email address.")


def _valid_email(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if not v:
        return None  # explicit "" from the form means "clear it", not an error
    _check_email_shape(v)
    return v


# Email is required both at account creation and on every subsequent admin
# edit (task feedback: "a user record should not be saved without a valid
# email address") -- unlike _valid_email above, blank/None isn't a valid
# "skip it" value here. Note: rows created before this requirement existed
# can still carry a null email today (nothing backfills it) -- the first
# time such an account is next edited, this now forces an email to be
# supplied before the save succeeds. That's the intended behavior per this
# feedback, not a bug.
def _valid_email_required(v: str) -> str:
    v = (v or "").strip()
    if not v:
        raise ValueError("Email is required.")
    _check_email_shape(v)
    return v


# Pakistan (+92) gets a real, strict shape check -- 3-digit mobile prefix,
# dash, 7-digit subscriber number, e.g. +92-321-1234567 -- because that's
# this deployment's own explicitly-requested standard format. This is
# deliberately NOT generalized to every dial code: a 3+7 split is specific
# to Pakistan's own numbering plan and would reject plenty of legitimately-
# formatted numbers from the 200+ other countries this app's phone-input
# dropdown supports (see app.js's DIAL_CODES) -- most countries don't share
# that grouping at all. Every other dial code keeps the older, deliberately
# loose E.164-shaped bounds check below (a well-known rabbit hole to do
# properly per-country -- see e.g. libphonenumber -- so this only rejects
# the obviously-wrong stuff: missing "+", letters, wildly too few/many
# digits), now also accepting one dash between the dial code and the local
# number (matching the client-side phone-input's new default grouping)
# alongside the older no-dash form already sitting in the database from
# before this change, so existing rows don't need a migration.
_PHONE_PK_RE = re.compile(r"^\+92-\d{3}-\d{7}$")
_PHONE_GENERAL_RE = re.compile(r"^\+\d{1,4}-\d{4,14}$")  # dial code - local number, one dash
_PHONE_LEGACY_RE = re.compile(r"^\+\d{7,15}$")  # pre-existing no-dash rows; still accepted, never produced fresh


def _valid_phone(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if not v:
        return None  # explicit "" from the form means "clear it", not an error

    if v.startswith("+92"):
        # A bare compact "+923001234567" (old format, or hand-typed without
        # dashes) gets normalized into the standard +92-XXX-XXXXXXX shape
        # rather than rejected outright, as long as it's genuinely 10 local
        # digits (3+7) -- "always stored in a standardized format" per the
        # task, without forcing a fresh round-trip through the UI just to
        # fix formatting on an otherwise-valid number.
        if _PHONE_LEGACY_RE.match(v) and not v.startswith("+92-"):
            local = v[3:]
            if len(local) == 10:
                v = f"+92-{local[:3]}-{local[3:]}"
        if not _PHONE_PK_RE.match(v):
            raise ValueError(
                "Pakistani phone numbers must be in the format +92-321-1234567 "
                "(3-digit prefix, dash, 7-digit number)."
            )
        return v

    if _PHONE_GENERAL_RE.match(v) or _PHONE_LEGACY_RE.match(v):
        return v
    raise ValueError(
        "Phone number must be in the format +<country code>-<number>, e.g. +92-321-1234567."
    )


# _valid_country_list/_valid_city_list/_valid_asn_list/_valid_ip_list used
# to live here as free functions; they now live in geo_validators.py
# (imported near the top of this file under their original _valid_* names,
# so every call site below is unchanged) since policy_store.py needs the
# exact same rules for the Clients page's Manage Restrictions dialog --
# see geo_validators.py's module docstring.


# Mirrors policy_store.set_policy's own validation (that module is the
# real enforcement point, since it's the one writing client_policy.json --
# see its docstring) -- validating here too gives a clean 422 with a field
# name attached, rather than only discovering a bad value later when
# create_user/update_user calls policy_store and gets a PolicyValidationError.
def _valid_allowed_os(v: list[str]) -> list[str]:
    normalized = sorted({o.strip().lower() for o in v if o.strip()})
    bad = [o for o in normalized if o not in policy_store.VALID_OS]
    if bad:
        raise ValueError(f"Invalid OS name(s): {', '.join(bad)} -- expected any of: {', '.join(sorted(policy_store.VALID_OS))}.")
    return normalized


def _valid_bandwidth_gb(v: float | None) -> float | None:
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        raise ValueError("Bandwidth quota must be a number.")
    if v < 0.1:
        raise ValueError("Bandwidth quota must be at least 0.1 GB (100 MB) -- leave blank for unlimited.")
    return v


# Reuses services.openvpn.validator.normalize_mac -- the exact same
# MAC-format check/normalization openvpn-install.sh's do_add_mac performs
# (see that module's docstring) -- rather than duplicating a second regex
# here that could quietly drift out of sync with what the CLI layer
# actually accepts. Accepts any of the common separator styles (colon,
# dash, dot, or none) and normalizes to lowercase colon-separated form
# (e.g. "AA:BB:CC:DD:EE:FF" -> "aa:bb:cc:dd:ee:ff") so what's stored/sent
# to cli.add_client is always in one consistent shape regardless of how
# the admin typed it.
def _valid_mac_format(v: str) -> str:
    v = (v or "").strip()
    if not v:
        raise ValueError("Device MAC Address is required.")
    try:
        return normalize_mac(v)
    except MacFormatError:
        raise ValueError(
            f"'{v}' isn't a valid MAC address -- expected 6 hex byte pairs, "
            "e.g. AA:BB:CC:DD:EE:FF or aa:bb:cc:dd:ee:ff (colons, dashes, or no separator all work)."
        )


def _resolve_teams(db: Session, team_ids: list[int]) -> list[Team]:
    """Validates every id in team_ids references an existing Team, and
    returns the Team rows themselves (for assigning to User.teams). Used by
    both the admin-edit and self-service endpoints so a client can only
    ever land a user in real teams, never arbitrary free text or bogus ids.
    A user can belong to zero, one, or several teams at once."""
    if not team_ids:
        return []
    teams = db.query(Team).filter(Team.id.in_(team_ids)).all()
    found_ids = {t.id for t in teams}
    missing = [tid for tid in team_ids if tid not in found_ids]
    if missing:
        raise HTTPException(status_code=400, detail=f"No such team(s): {missing}")
    return teams


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"  # a RoleDef slug -- resolved/validated in create_user() via _resolve_role
    first_name: str
    last_name: str | None = None
    gender: Gender = Gender.unspecified
    email: str
    phone: str | None = None
    # User creation is now the single VPN-profile provisioning entry point
    # (task feedback: "Remove Add a New Client... User creation should
    # become the primary onboarding workflow") -- required, same as the
    # old standalone Add Client form's MAC field. See create_user() below:
    # this creates the VPN cert (cli.add_client) BEFORE the User row, so a
    # MAC/name conflict fails closed with no user created at all.
    mac: str
    team_ids: list[int] = []

    # "Send VPN Profile via Email" checkbox (Add User form) -- best-effort,
    # fire-and-forget: see create_user()'s own handling below for why a
    # failed send never rolls back the just-created user (matches this
    # app's existing stance on notify_admin_on_user_created/similar).
    send_vpn_profile_email: bool = False

    # VPN-profile-level restrictions, applied to the just-created client
    # (see create_user() below) the same way Manage Restrictions on the
    # Clients page would -- these were previously only settable AFTER
    # creation, via a separate trip to the Clients page. Both optional,
    # same "empty/blank = unrestricted" convention as policy_store.set_policy.
    allowed_os: list[str] = []
    bandwidth_monthly_gb: float | None = None

    @field_validator("allowed_os")
    @classmethod
    def _os(cls, v: list[str]) -> list[str]:
        return _valid_allowed_os(v)

    @field_validator("bandwidth_monthly_gb")
    @classmethod
    def _bandwidth(cls, v: float | None) -> float | None:
        return _valid_bandwidth_gb(v)

    @field_validator("mac")
    @classmethod
    def _valid_mac(cls, v: str) -> str:
        return _valid_mac_format(v)

    restrict_login_by_country: bool = False
    allowed_login_countries: list[str] = []
    restrict_login_by_ip: bool = False
    allowed_login_ips: list[str] = []
    restrict_login_by_city: bool = False
    allowed_login_cities: list[str] = []
    restrict_login_by_asn: bool = False
    allowed_login_asns: list[str] = []

    @field_validator("allowed_login_countries")
    @classmethod
    def _countries(cls, v: list[str]) -> list[str]:
        return _valid_country_list(v)

    @field_validator("allowed_login_ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        return _valid_ip_list(v)

    @field_validator("allowed_login_cities")
    @classmethod
    def _cities(cls, v: list[str]) -> list[str]:
        return _valid_city_list(v)

    @field_validator("allowed_login_asns")
    @classmethod
    def _asns(cls, v: list[str]) -> list[str]:
        return _valid_asn_list(v)

    @field_validator("username")
    @classmethod
    def _valid_username(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) < 3 or len(v) > 64:
            raise ValueError("Username must be 3-64 characters.")
        return v

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str) -> str:
        return _valid_password(v)

    @field_validator("first_name")
    @classmethod
    def _first_name(cls, v: str) -> str:
        result = _valid_first_name(v)
        if result is None:
            raise ValueError("First Name is required.")
        return result

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return _valid_email_required(v)

    @field_validator("phone")
    @classmethod
    def _phone(cls, v: str | None) -> str | None:
        return _valid_phone(v)


class UpdateUserRequest(BaseModel):
    """Admin-only edits to another (or their own, for non-guardrailed
    fields) user's account. Password here is an unconditional admin reset --
    no current-password check, unlike the self-service /me endpoint below."""
    role: str | None = None  # a RoleDef slug -- resolved/validated in update_user() via _resolve_role
    is_active: bool | None = None
    deleted: bool | None = None  # True = soft-delete, False = restore
    password: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    gender: Gender | None = None
    email: str | None = None
    phone: str | None = None
    team_ids: list[int] | None = None  # explicit [] = clear all teams; see model_fields_set usage below

    # Same VPN-profile restrictions as CreateUserRequest, editable after the
    # fact too -- see update_user() below, which syncs these onto the
    # linked VPN profile's policy (a no-op if this user has no linked
    # profile yet, e.g. the rare cert-created-but-DB-failed edge case).
    # None means "not provided in this PATCH" (model_fields_set decides,
    # same convention as team_ids/allowed_login_* above); an explicit []/null
    # clears the restriction.
    allowed_os: list[str] | None = None
    bandwidth_monthly_gb: float | None = None

    @field_validator("allowed_os")
    @classmethod
    def _os(cls, v: list[str] | None) -> list[str] | None:
        return _valid_allowed_os(v) if v is not None else v

    @field_validator("bandwidth_monthly_gb")
    @classmethod
    def _bandwidth(cls, v: float | None) -> float | None:
        return _valid_bandwidth_gb(v)

    restrict_login_by_country: bool | None = None
    allowed_login_countries: list[str] | None = None  # explicit [] = clear the list
    restrict_login_by_ip: bool | None = None
    allowed_login_ips: list[str] | None = None  # explicit [] = clear the list
    restrict_login_by_city: bool | None = None
    allowed_login_cities: list[str] | None = None  # explicit [] = clear the list
    restrict_login_by_asn: bool | None = None
    allowed_login_asns: list[str] | None = None  # explicit [] = clear the list

    @field_validator("allowed_login_countries")
    @classmethod
    def _countries(cls, v: list[str] | None) -> list[str] | None:
        return _valid_country_list(v) if v is not None else v

    @field_validator("allowed_login_ips")
    @classmethod
    def _ips(cls, v: list[str] | None) -> list[str] | None:
        return _valid_ip_list(v) if v is not None else v

    @field_validator("allowed_login_cities")
    @classmethod
    def _cities(cls, v: list[str] | None) -> list[str] | None:
        return _valid_city_list(v) if v is not None else v

    @field_validator("allowed_login_asns")
    @classmethod
    def _asns(cls, v: list[str] | None) -> list[str] | None:
        return _valid_asn_list(v) if v is not None else v

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str | None) -> str | None:
        return _valid_password(v) if v else v

    @field_validator("first_name")
    @classmethod
    def _first_name(cls, v: str | None) -> str | None:
        return _valid_first_name(v)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str | None) -> str:
        # Required on every admin edit, same as at creation -- see
        # _valid_email_required's docstring above for the "existing
        # null-email accounts" behavior this implies. Only runs when the
        # field is actually present in the request body (Pydantic skips
        # unset-default fields), so a partial PATCH that never touches
        # email (e.g. the restore-from-deleted button's {deleted, is_active}
        # body) is unaffected.
        return _valid_email_required(v)

    @field_validator("phone")
    @classmethod
    def _phone(cls, v: str | None) -> str | None:
        return _valid_phone(v)


class UpdateProfileRequest(BaseModel):
    """Self-service: any logged-in user editing their own profile. No role/
    is_active/deleted here -- those are admin-only, via UpdateUserRequest."""
    first_name: str | None = None
    last_name: str | None = None
    gender: Gender | None = None
    email: str | None = None
    phone: str | None = None
    current_password: str | None = None
    new_password: str | None = None

    @field_validator("new_password")
    @classmethod
    def _pw(cls, v: str | None) -> str | None:
        return _valid_password(v) if v else v

    @field_validator("first_name")
    @classmethod
    def _first_name(cls, v: str | None) -> str | None:
        return _valid_first_name(v)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        return _valid_email(v)

    @field_validator("phone")
    @classmethod
    def _phone(cls, v: str | None) -> str | None:
        return _valid_phone(v)


def _role_slug(u: User) -> str:
    """u.role_def is the dynamic-RBAC role (see permissions.py); it's set
    for every user going forward (create_user always sets it, and
    migrate_user_roles backfills every pre-existing row on startup -- see
    db.py's _seed_rbac), but this falls back to the legacy `role` enum
    column for the narrow in-flight-request window before that backfill
    runs on a fresh deploy, rather than ever returning None."""
    return u.role_def.slug if u.role_def is not None else u.role.value


def _serialize(u: User, policies: dict | None = None) -> dict:
    # `policies` is an optional pre-fetched {vpn_client_name: policy_dict}
    # map (see _USERS_LIST_OPTIONS callers below) -- avoids an extra
    # policy_store file-lock/read per user on the list endpoints (N+1-ish,
    # even though it's a JSON file rather than a DB query). Single-user
    # callers (create_user/update_user/link_vpn_profile) just pass a
    # one-entry dict for the user they're already touching.
    client_name = u.vpn_profile_link.vpn_client_name if u.vpn_profile_link else None
    policy = (policies or {}).get(client_name) or {} if client_name else {}
    return {
        "id": u.id,
        "username": u.username,
        "role": _role_slug(u),
        "role_name": u.role_def.name if u.role_def is not None else u.role.value.capitalize(),
        "is_active": u.is_active,
        "is_bootstrap_admin": u.is_bootstrap_admin,
        "deleted": u.deleted,
        "deleted_at": u.deleted_at.isoformat() if u.deleted_at else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "display_name": u.display_name,
        "gender": u.gender.value if u.gender else Gender.unspecified.value,
        "email": u.email,
        "phone": u.phone,
        "team_ids": [t.id for t in u.teams],
        "teams": [t.name for t in u.teams],
        "restrict_login_by_country": u.restrict_login_by_country,
        "allowed_login_countries": json.loads(u.allowed_login_countries or "[]"),
        "restrict_login_by_ip": u.restrict_login_by_ip,
        "allowed_login_ips": json.loads(u.allowed_login_ips or "[]"),
        "restrict_login_by_city": u.restrict_login_by_city,
        "allowed_login_cities": json.loads(u.allowed_login_cities or "[]"),
        "restrict_login_by_asn": u.restrict_login_by_asn,
        "allowed_login_asns": json.loads(u.allowed_login_asns or "[]"),
        "vpn_client_name": client_name,
        "allowed_os": policy.get("allowed_os") or [],
        "bandwidth_monthly_gb": policy.get("bandwidth_monthly_gb"),
    }


def _guard_against_self_lockout(db: Session, target: User, admin: User, *, removing: bool) -> None:
    """Shared guardrail for anything that would demote/deactivate/delete an
    admin: can't do it to yourself, and can't do it if it would leave zero
    active, non-deleted admins."""
    if not removing:
        return
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You can't demote, deactivate, or delete your own account.")
    remaining_admins = db.query(User).join(RoleDef, User.role_id == RoleDef.id).filter(
        RoleDef.slug == "admin", User.is_active.is_(True), User.deleted.is_(False), User.id != target.id
    ).count()
    if remaining_admins == 0:
        raise HTTPException(status_code=400, detail="Can't remove the last active admin account.")


# selectinload(role_def)/(teams): _serialize() (above) touches both per user
# -- without eager-loading, each is a separate lazy-fired query the first
# time it's touched, i.e. up to 2 extra queries per user (N+1) on every
# call to either endpoint below. This batches each into one extra query
# total, up front, regardless of how many users are returned.
_USERS_LIST_OPTIONS = (selectinload(User.role_def), selectinload(User.teams), selectinload(User.vpn_profile_link))


@router.get("")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = (
        db.query(User).options(*_USERS_LIST_OPTIONS)
        .filter(User.deleted.is_(False)).order_by(User.username).all()
    )
    # One bulk policy_store read for the whole list, not one per user -- see
    # _serialize's docstring.
    policies = policy_store.get_all_policies()
    return [_serialize(u, policies) for u in users]


@router.get("/deleted")
def list_deleted_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = (
        db.query(User).options(*_USERS_LIST_OPTIONS)
        .filter(User.deleted.is_(True)).order_by(User.deleted_at.desc()).all()
    )
    policies = policy_store.get_all_policies()
    return [_serialize(u, policies) for u in users]


@router.get("/me")
def whoami(user: User = Depends(require_user)):
    # Any logged-in user can see their own profile (unlike the admin-only
    # routes above) -- this is what the self-service /profile page reads.
    client_name = user.vpn_profile_link.vpn_client_name if user.vpn_profile_link else None
    policies = {client_name: policy_store.get_policy(client_name)} if client_name else {}
    return _serialize(user, policies)


@router.patch("/me")
def update_my_profile(body: UpdateProfileRequest, user: User = Depends(require_user), db: Session = Depends(get_db)):
    changes = []
    for field in ("first_name", "last_name", "gender"):
        value = getattr(body, field)
        if value is not None and value != getattr(user, field):
            setattr(user, field, value)
            changes.append(field)
    # email/phone use model_fields_set (not "is not None") so an explicit ""
    # submitted from the form clears the field instead of being ignored --
    # unlike first_name/last_name/gender above, which have no "unset" UI
    # affordance and where None simply means "this request didn't touch it".
    for field in ("email", "phone"):
        if field in body.model_fields_set:
            value = getattr(body, field)
            if value != getattr(user, field):
                setattr(user, field, value)
                changes.append(field)

    # Team membership is deliberately NOT self-service for anyone (not even
    # admins/editors editing their own account) -- UpdateProfileRequest has
    # no team_ids field at all. Assignment happens only through admin/editor
    # user management (PATCH /api/users/{id}'s UpdateUserRequest.team_ids),
    # per the "Regular users should not be able to assign or modify their
    # own team membership" requirement -- see profile.html, which shows
    # team(s) read-only.

    if body.new_password:
        if not body.current_password or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        user.password_hash = hash_password(body.new_password)
        changes.append("password")

    if changes:
        db.commit()
        log_action(db, user, "update_own_profile", target=user.username, detail=", ".join(changes))
    return _serialize(user)


@router.post("", status_code=201)
def create_user(body: CreateUserRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first() is not None:
        raise HTTPException(status_code=409, detail=f"Username '{body.username}' already exists.")
    teams = _resolve_teams(db, body.team_ids)
    role_def = _resolve_creatable_role(db, body.role)

    # VPN cert is created FIRST, before any DB write -- a MAC/name conflict
    # (or any other cli.add_client failure) means no user is created at
    # all, matching the approved failure-recovery design (see
    # vpn_identity_sync.py's module comment, plan §7): a partial "user
    # exists, cert doesn't" state should never happen. The reverse ("cert
    # exists, user creation then fails") is the one accepted rare edge
    # case -- see the except block below for the recovery path.
    try:
        cli.add_client(body.username, body.mac)
    except ScriptError as e:
        log_action(db, admin, "create_user", target=body.username, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)

    # The legacy `role` enum column (Role: admin/editor/viewer only) can't
    # represent a custom or "User" self-service role -- role_id (below) is what
    # every permission check actually reads now, so this is just a
    # best-effort placeholder for that column until it's removed in a later
    # cleanup (see permissions.py's migrate_user_roles docstring).
    legacy_role = Role(role_def.slug) if role_def.slug in Role._value2member_map_ else Role.viewer
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=legacy_role,
        role_id=role_def.id,
        first_name=body.first_name,
        last_name=body.last_name,
        gender=body.gender,
        email=body.email,
        phone=body.phone,
        teams=teams,
        restrict_login_by_country=body.restrict_login_by_country,
        allowed_login_countries=json.dumps(body.allowed_login_countries) if body.allowed_login_countries else None,
        restrict_login_by_ip=body.restrict_login_by_ip,
        allowed_login_ips=json.dumps(body.allowed_login_ips) if body.allowed_login_ips else None,
        restrict_login_by_city=body.restrict_login_by_city,
        allowed_login_cities=json.dumps(body.allowed_login_cities) if body.allowed_login_cities else None,
        restrict_login_by_asn=body.restrict_login_by_asn,
        allowed_login_asns=json.dumps(body.allowed_login_asns) if body.allowed_login_asns else None,
    )
    try:
        db.add(user)
        db.flush()
        db.add(VpnProfileLink(user_id=user.id, vpn_client_name=body.username, link_source="created_with_profile"))
        db.commit()
    except Exception:
        db.rollback()
        # Accepted rare edge case (per approved failure-recovery design):
        # the VPN cert now exists but no portal user/link was created for
        # it. Surface a clear, actionable error rather than a generic 500 --
        # the admin's recovery path is Edit User -> "Attach existing VPN
        # profile" on whatever user this was meant for (or a fresh Add
        # User with the same MAC, since the name is now taken by the
        # orphaned cert -- pick a different username, then attach).
        log_action(db, admin, "create_user", target=body.username,
                   detail=f"VPN profile '{body.username}' was created but the user record failed to save", success=False)
        raise HTTPException(
            status_code=500,
            detail=f"A VPN profile named '{body.username}' was created, but saving the user account failed. "
                   f"The VPN profile was NOT rolled back -- use Edit User's \"Attach existing VPN profile\" to link it "
                   f"to an account manually.",
        )
    log_action(db, admin, "create_user", target=body.username, detail=f"role={role_def.slug}")

    # Sync VPN-profile-level restrictions onto the just-created client, same
    # write path as Manage Restrictions on the Clients page. Best-effort:
    # both fields are already validated at the Pydantic level above, so
    # this should never actually raise -- but the user/link/cert all
    # already exist at this point, so a failure here (e.g. a filesystem
    # hiccup writing client_policy.json) must not undo any of that. Skipped
    # entirely (no file write at all) when neither restriction was set --
    # matches policy_store's own "no policy entry = fully unrestricted"
    # default, avoids touching client_policy.json for the common case.
    # Settings -> VPN Management's org-wide default only fills in when this
    # request left the per-user quota blank -- an explicit 0.1+ GB value on
    # the form (including one that happens to match the default) always
    # wins, same "most specific setting wins" precedence as every other
    # env-var/DB-row-default pair in this app (see app_settings.py).
    effective_bandwidth = body.bandwidth_monthly_gb if body.bandwidth_monthly_gb is not None else app_settings.runtime.default_bandwidth_monthly_gb
    # Location & Network Restrictions sync: the toggle+list pairs on User
    # (restrict_login_by_country + allowed_login_countries, etc.) collapse
    # onto policy_store's plain "list, empty/None = unrestricted" shape here
    # -- a restriction toggle left off means "sync nothing for this kind",
    # same as an admin never having touched that Login Restrictions field
    # at all. See policy_store.set_policy's docstring for the shared
    # geo_validators.py rules this data has already passed once, at the
    # CreateUserRequest field-validator level, above.
    policy = {}
    if body.allowed_os or effective_bandwidth or body.restrict_login_by_country or body.restrict_login_by_city \
            or body.restrict_login_by_asn or body.restrict_login_by_ip:
        try:
            policy = policy_store.set_policy(
                body.username,
                allowed_os=body.allowed_os or None,
                bandwidth_monthly_gb=effective_bandwidth,
                allowed_countries=body.allowed_login_countries if body.restrict_login_by_country else None,
                allowed_cities=body.allowed_login_cities if body.restrict_login_by_city else None,
                allowed_asns=body.allowed_login_asns if body.restrict_login_by_asn else None,
                allowed_ips=body.allowed_login_ips if body.restrict_login_by_ip else None,
            )
        except (PolicyValidationError, OSError) as e:
            log_action(db, admin, "create_user", target=body.username,
                       detail=f"VPN profile restrictions could not be applied: {e}", success=False)

    if app_settings.runtime.notify_admin_on_user_created:
        mailer.send_admin_notification(
            subject=f"New user created: {body.username}",
            body=(
                f"{admin.username} created a new user account.\n\n"
                f"Username: {body.username}\n"
                f"Role: {role_def.name}\n"
                f"Email: {body.email}\n"
                f"VPN profile: {body.username}\n"
            ),
        )

    # "Send VPN Profile via Email" checkbox -- deliberately runs LAST,
    # after the user/link/cert and restrictions are all already committed:
    # an email failure here must never roll back or fail the request for
    # an account that otherwise finished creating successfully, same
    # fire-and-forget stance as notify_admin_on_user_created above. Best-
    # effort recipient name for the greeting -- falls back to a generic
    # one inside the template if blank.
    email_warning = None
    if body.send_vpn_profile_email:
        recipient_name = f"{body.first_name} {body.last_name}".strip() if body.last_name else body.first_name
        try:
            ovpn_content = cli.show_ovpn(body.username)
            mailer.send_ovpn_profile(
                to_address=body.email, client_name=body.username,
                ovpn_content=ovpn_content, recipient_name=recipient_name,
            )
            log_action(db, admin, "email_ovpn", target=body.username, detail=f"sent to {body.email} (on creation)", success=True)
        except Exception as e:
            email_warning = f"User created, but the VPN profile email could not be sent: {e}"
            log_action(db, admin, "email_ovpn", target=body.username, detail=f"send to {body.email} failed (on creation): {e}", success=False)

    result = _serialize(user, {body.username: policy})
    if email_warning:
        result["warning"] = email_warning
    return result


@router.patch("/{user_id}")
def update_user(user_id: int, body: UpdateUserRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    # Deliberately NOT excluding already-deleted targets here (unlike the
    # other lookups in this file) -- this is also the restore path
    # (`{"deleted": false}`), so a deleted user must still be reachable by
    # PATCH. Other mutations on an already-deleted account are harmless too
    # (they just take effect if/when it's restored).

    # The bootstrap admin -- the very first admin account a deployment ever
    # creates (see User.is_bootstrap_admin / auth.bootstrap_admin) -- can
    # never be demoted, deactivated, or (soft-)deleted, by anyone, including
    # another admin. Every other admin account remains demotable/removable
    # by another admin, same as before this rule existed, subject only to
    # the last-admin-standing/self-lockout guardrails below.
    if target.is_bootstrap_admin:
        if body.role is not None and body.role.strip().lower() != "super_admin":
            raise HTTPException(status_code=400, detail="The bootstrap admin account cannot be demoted.")
        if body.is_active is False:
            raise HTTPException(status_code=400, detail="The bootstrap admin account cannot be deactivated.")
        if body.deleted is True:
            raise HTTPException(status_code=400, detail="The bootstrap admin account cannot be deleted.")

    # Guardrails against an admin locking everyone (including themselves)
    # out: demoting, deactivating, or deleting the last active admin (or
    # yourself) is blocked, regardless of which of those three the request
    # is doing -- this is the general rule that predates the bootstrap-admin
    # special case above, and still applies to every admin (bootstrap or
    # not), including situations the unconditional bootstrap check above
    # doesn't cover (e.g. a non-bootstrap admin demoting/deactivating/
    # deleting themselves, or removing the last other active admin).
    would_remove = _role_slug(target) == "admin" and (
        (body.role is not None and body.role.strip().lower() != "admin")
        or body.is_active is False
        or body.deleted is True
    )
    _guard_against_self_lockout(db, target, admin, removing=would_remove)

    changes = []
    if body.role is not None:
        # Non-bootstrap targets go through the same "super_admin isn't
        # assignable" guard as create_user -- the bootstrap-admin block
        # above already enforces the opposite direction (that account's
        # role can ONLY ever be set to "super_admin", never anything else),
        # so by the time a bootstrap target reaches here body.role is
        # necessarily already "super_admin" and the plain resolver is fine.
        new_role_def = _resolve_role(db, body.role) if target.is_bootstrap_admin else _resolve_creatable_role(db, body.role)
        if new_role_def.id != target.role_id:
            changes.append(f"role {_role_slug(target)}->{new_role_def.slug}")
            target.role_id = new_role_def.id
            # Keep the legacy enum column in sync where representable, same
            # placeholder rule as create_user() above -- see that comment.
            if new_role_def.slug in Role._value2member_map_:
                target.role = Role(new_role_def.slug)
    became_inactive = became_active = False
    if body.is_active is not None and body.is_active != target.is_active:
        changes.append(f"is_active {target.is_active}->{body.is_active}")
        became_inactive = target.is_active and not body.is_active
        became_active = not target.is_active and body.is_active
        target.is_active = body.is_active
    if body.deleted is not None and body.deleted != target.deleted:
        target.deleted = body.deleted
        target.deleted_at = datetime.now(timezone.utc) if body.deleted else None
        changes.append("deleted" if body.deleted else "restored")
    if body.password:
        target.password_hash = hash_password(body.password)
        changes.append("password reset")
    for field in ("first_name", "last_name", "gender"):
        value = getattr(body, field)
        if value is not None and value != getattr(target, field):
            setattr(target, field, value)
            changes.append(field)
    for field in ("email", "phone"):
        if field in body.model_fields_set:
            value = getattr(body, field)
            if value != getattr(target, field):
                setattr(target, field, value)
                changes.append(field)
    if "team_ids" in body.model_fields_set:
        new_teams = _resolve_teams(db, body.team_ids or [])
        if {t.id for t in new_teams} != {t.id for t in target.teams}:
            target.teams = new_teams
            changes.append("teams")
    if "restrict_login_by_country" in body.model_fields_set and body.restrict_login_by_country != target.restrict_login_by_country:
        target.restrict_login_by_country = body.restrict_login_by_country
        changes.append(f"restrict_login_by_country {target.restrict_login_by_country}")
    if "allowed_login_countries" in body.model_fields_set:
        new_value = json.dumps(body.allowed_login_countries) if body.allowed_login_countries else None
        if new_value != target.allowed_login_countries:
            target.allowed_login_countries = new_value
            changes.append("allowed_login_countries")
    if "restrict_login_by_ip" in body.model_fields_set and body.restrict_login_by_ip != target.restrict_login_by_ip:
        target.restrict_login_by_ip = body.restrict_login_by_ip
        changes.append(f"restrict_login_by_ip {target.restrict_login_by_ip}")
    if "allowed_login_ips" in body.model_fields_set:
        new_value = json.dumps(body.allowed_login_ips) if body.allowed_login_ips else None
        if new_value != target.allowed_login_ips:
            target.allowed_login_ips = new_value
            changes.append("allowed_login_ips")
    if "restrict_login_by_city" in body.model_fields_set and body.restrict_login_by_city != target.restrict_login_by_city:
        target.restrict_login_by_city = body.restrict_login_by_city
        changes.append(f"restrict_login_by_city {target.restrict_login_by_city}")
    if "allowed_login_cities" in body.model_fields_set:
        new_value = json.dumps(body.allowed_login_cities) if body.allowed_login_cities else None
        if new_value != target.allowed_login_cities:
            target.allowed_login_cities = new_value
            changes.append("allowed_login_cities")
    if "restrict_login_by_asn" in body.model_fields_set and body.restrict_login_by_asn != target.restrict_login_by_asn:
        target.restrict_login_by_asn = body.restrict_login_by_asn
        changes.append(f"restrict_login_by_asn {target.restrict_login_by_asn}")
    if "allowed_login_asns" in body.model_fields_set:
        new_value = json.dumps(body.allowed_login_asns) if body.allowed_login_asns else None
        if new_value != target.allowed_login_asns:
            target.allowed_login_asns = new_value
            changes.append("allowed_login_asns")
    # created_at is intentionally immutable here -- it's a factual record of
    # account creation, not admin-editable through this endpoint (unlike the
    # other profile fields above).

    db.commit()
    if changes:
        log_action(db, admin, "update_user", target=target.username, detail="; ".join(changes))
    # Identity lifecycle sync (Phase 3, see vpn_identity_sync.py): mirror a
    # suspend/reactivate onto this user's linked VPN cert, if any -- gated
    # by protected_from_auto_revoke inside those functions.
    if became_inactive:
        vpn_identity_sync.sync_after_portal_suspend(db, target)
    elif became_active:
        vpn_identity_sync.sync_after_portal_reactivate(db, target)

    # Sync VPN-profile-level restrictions onto the linked client's policy --
    # a no-op if this user has no linked profile yet (the rare
    # cert-created-but-DB-failed edge case; there's nothing to sync onto
    # until an admin attaches one via the vpn-link endpoint below).
    #
    # Location & Network Restrictions (country/city/ASN/IP) are read from
    # `target` -- already committed above -- rather than from `body`,
    # because each is a toggle+list PAIR (restrict_login_by_country +
    # allowed_login_countries) and this PATCH can touch just one half of a
    # pair (e.g. only the toggle) while leaving the other at whatever it
    # already was; `target` always reflects the correct POST-MERGE
    # combination of both, `body` alone would not. allowed_os/
    # bandwidth_monthly_gb stay body-driven (unchanged from before this
    # sync) since those have no such toggle -- "field present in this PATCH
    # at all" is already the right signal for them.
    restriction_fields_touched = bool(
        {"restrict_login_by_country", "allowed_login_countries", "restrict_login_by_city", "allowed_login_cities",
         "restrict_login_by_asn", "allowed_login_asns", "restrict_login_by_ip", "allowed_login_ips"}
        & body.model_fields_set
    )
    client_name = target.vpn_profile_link.vpn_client_name if target.vpn_profile_link else None
    policy = policy_store.get_policy(client_name) if client_name else {}
    if client_name and ("allowed_os" in body.model_fields_set or "bandwidth_monthly_gb" in body.model_fields_set
                         or restriction_fields_touched):
        try:
            policy = policy_store.set_policy(
                client_name,
                allowed_os=body.allowed_os if "allowed_os" in body.model_fields_set else ...,
                bandwidth_monthly_gb=body.bandwidth_monthly_gb if "bandwidth_monthly_gb" in body.model_fields_set else ...,
                allowed_countries=(json.loads(target.allowed_login_countries or "[]") if target.restrict_login_by_country else None)
                    if restriction_fields_touched else ...,
                allowed_cities=(json.loads(target.allowed_login_cities or "[]") if target.restrict_login_by_city else None)
                    if restriction_fields_touched else ...,
                allowed_asns=(json.loads(target.allowed_login_asns or "[]") if target.restrict_login_by_asn else None)
                    if restriction_fields_touched else ...,
                allowed_ips=(json.loads(target.allowed_login_ips or "[]") if target.restrict_login_by_ip else None)
                    if restriction_fields_touched else ...,
            )
            log_action(db, admin, "update_user", target=target.username, detail="synced VPN profile restrictions")
        except (PolicyValidationError, OSError) as e:
            log_action(db, admin, "update_user", target=target.username,
                       detail=f"VPN profile restrictions could not be applied: {e}", success=False)
    return _serialize(target, {client_name: policy} if client_name else {})


class VpnLinkRequest(BaseModel):
    vpn_client_name: str


@router.post("/{user_id}/vpn-link", status_code=201)
def link_vpn_profile(user_id: int, body: VpnLinkRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Attaches an existing, unlinked VPN profile to a user that doesn't
    have one yet (task feedback: "For existing VPN profiles... Edit a
    User. Select an existing VPN profile from a dropdown."). Mirrors
    vpn_identity_sync.auto_link_new_client's "link an existing user"
    branch, but for the inverse trigger (an admin picking the profile from
    Edit User, not a cert being created) -- link_source records that
    distinction (manual_admin_link vs. created_with_profile).

    VpnProfileLink.vpn_client_name is unique at the DB level, so a race
    between two admins attaching the same just-unassigned profile to two
    different users can't both succeed -- the loser gets a clean 409 from
    the IntegrityError below, never a silent double-link."""
    target = db.get(User, user_id)
    if target is None or target.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    if target.vpn_profile_link is not None:
        raise HTTPException(status_code=400, detail=f"'{target.username}' already has a linked VPN profile ('{target.vpn_profile_link.vpn_client_name}').")
    name = body.vpn_client_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="VPN profile name is required.")
    if db.query(VpnProfileLink).filter(VpnProfileLink.vpn_client_name == name).first() is not None:
        raise HTTPException(status_code=409, detail=f"'{name}' is already linked to another user.")
    db.add(VpnProfileLink(user_id=target.id, vpn_client_name=name, link_source="manual_admin_link", linked_by=admin.username))
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"'{name}' was just linked to another user -- pick a different profile.")
    log_action(db, admin, "link_vpn_profile", target=target.username, detail=name)

    # Push this user's already-configured Device & Access Policy / Location
    # & Network Restrictions onto the profile it's just been attached to --
    # same "the User side is the sync source" direction as create_user/
    # update_user above. This profile may have been sitting unassigned with
    # its own (possibly different, possibly none) restrictions from before
    # the link -- the user's settings win, since they're what an admin was
    # just looking at when they chose to attach this profile.
    policy = {}
    try:
        policy = policy_store.set_policy(
            name,
            allowed_countries=json.loads(target.allowed_login_countries or "[]") if target.restrict_login_by_country else None,
            allowed_cities=json.loads(target.allowed_login_cities or "[]") if target.restrict_login_by_city else None,
            allowed_asns=json.loads(target.allowed_login_asns or "[]") if target.restrict_login_by_asn else None,
            allowed_ips=json.loads(target.allowed_login_ips or "[]") if target.restrict_login_by_ip else None,
        )
    except (PolicyValidationError, OSError) as e:
        log_action(db, admin, "link_vpn_profile", target=target.username,
                   detail=f"VPN profile restrictions could not be synced: {e}", success=False)
    return _serialize(target, {name: policy})


@router.delete("/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Soft delete: the account is deactivated, hidden from the main user
    list, and can no longer log in, but the row and its audit history are
    kept and remain visible/restorable under GET /api/users/deleted, or
    permanently removable via DELETE /{user_id}/permanent below."""
    target = db.get(User, user_id)
    if target is None or target.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    if target.is_bootstrap_admin:
        raise HTTPException(status_code=400, detail="The bootstrap admin account cannot be deleted.")
    _guard_against_self_lockout(db, target, admin, removing=(_role_slug(target) == "admin"))
    target.deleted = True
    target.deleted_at = datetime.now(timezone.utc)
    target.is_active = False
    db.commit()
    log_action(db, admin, "delete_user", target=target.username)
    vpn_identity_sync.sync_after_portal_delete(db, target)
    return {"message": f"User '{target.username}' deleted (recoverable from the Deleted users list)."}


@router.delete("/{user_id}/permanent")
def permanently_delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Hard delete: irreversibly removes the row from the database. Only
    available for accounts that are already soft-deleted (see delete_user
    above) -- a distinct, more destructive action from soft-delete, with
    its own confirmation in the UI. Safe with respect to the audit log:
    AuditLog.username is a plain string snapshot, not a foreign key to
    User, so history for a permanently-deleted account is preserved (this
    action is itself logged, before the row is removed, for exactly that
    reason)."""
    target = db.get(User, user_id)
    if target is None or not target.deleted:
        raise HTTPException(status_code=404, detail="User not found in the deleted list.")
    if target.is_bootstrap_admin:
        # Belt-and-suspenders: delete_user() above already prevents the
        # bootstrap admin from ever reaching deleted=True in the first
        # place, so this should be unreachable in practice, but the rule is
        # "cannot be deleted, full stop" -- enforce it here too rather than
        # relying solely on that earlier check never being bypassed.
        raise HTTPException(status_code=400, detail="The bootstrap admin account cannot be deleted.")
    username = target.username
    # Before the row is gone -- closes the "cert stays live with no owning
    # user" gap a failed earlier revoke could otherwise leave behind. See
    # its own docstring.
    vpn_identity_sync.sync_before_portal_permanent_delete(db, target)
    # VpnProfileLink.user_id has ondelete="CASCADE" at the DB level, but
    # that's only actually enforced by Postgres -- SQLite requires
    # `PRAGMA foreign_keys=ON` (not set here) to honor it, and without it
    # SQLAlchemy's default ORM behavior on `db.delete(target)` is to try
    # nulling out the dependent row's FK instead of cascading, which then
    # violates vpn_profile_links.user_id's NOT NULL constraint. Delete the
    # link explicitly first so this works the same on both dialects,
    # rather than relying on cascade semantics that differ between them.
    if target.vpn_profile_link is not None:
        db.delete(target.vpn_profile_link)
    log_action(db, admin, "permanently_delete_user", target=username,
               detail="hard-deleted from the deleted-users list -- irreversible")
    db.delete(target)
    db.commit()
    return {"message": f"User '{username}' permanently deleted. This cannot be undone."}
