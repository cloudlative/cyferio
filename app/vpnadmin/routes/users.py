import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator, model_validator
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


def _check_password_reuse(user: User, new_password: str) -> None:
    """Settings -> Security's "Remember last N passwords": rejects a new
    password that matches the account's current password or any of its
    last N previous ones (N = app_settings.runtime.password_history_count,
    0 = disabled). Called on every password-setting path -- self-service
    change, admin reset, and forgot-password reset alike -- right before
    the new hash is committed. Raises ValueError (the same convention
    _valid_password uses) so every caller's existing try/except handles it
    identically."""
    n = app_settings.runtime.password_history_count
    if n <= 0:
        return
    if verify_password(new_password, user.password_hash):
        raise ValueError("That's your current password. Choose a different one.")
    history = json.loads(user.password_history or "[]")
    for old_hash in history[:n]:
        if verify_password(new_password, old_hash):
            raise ValueError(f"That password was used recently. Choose one you haven't used in your last {n} passwords.")


def _record_password_history(user: User) -> None:
    """Pairs with _check_password_reuse above -- call this BEFORE
    overwriting user.password_hash with the new one, so the about-to-be-
    replaced hash gets pushed onto the front of the history list. Trims to
    the currently-configured N on every write, so a later reduction in the
    Settings value takes effect immediately rather than only pruning what
    was over the old, larger limit."""
    n = app_settings.runtime.password_history_count
    if n <= 0:
        user.password_history = None
        return
    history = json.loads(user.password_history or "[]")
    history.insert(0, user.password_hash)
    user.password_history = json.dumps(history[:n])


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
    # become the primary onboarding workflow") -- same as the old standalone
    # Add Client form's MAC field. See create_user() below: this creates the
    # VPN cert (cli.add_client) BEFORE the User row, so a MAC/name conflict
    # fails closed with no user created at all.
    #
    # Optional as of link_existing_vpn_profile below (task feedback: "add an
    # option during user creation to select an existing VPN profile... to
    # support onboarding users who already have standalone VPN profiles and
    # avoid creating duplicate profiles") -- exactly one of mac/
    # link_existing_vpn_profile must be given, see _exactly_one_profile_source
    # below. Kept as two separate fields (rather than a single "profile
    # source" union) so each keeps its own existing validator and the two
    # code paths in create_user() stay easy to read independently.
    mac: str | None = None
    # Name of an already-existing, not-yet-linked VPN profile (see
    # routes/clients.py's get_unassigned_clients) to attach to this new
    # user instead of provisioning a fresh one -- mirrors VpnLinkRequest's
    # own field below, reusing the exact same "attach" semantics via
    # create_user()'s own inlined version of link_vpn_profile()'s logic.
    link_existing_vpn_profile: str | None = None
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
    def _valid_mac(cls, v: str | None) -> str | None:
        return _valid_mac_format(v) if v is not None else None

    @field_validator("link_existing_vpn_profile")
    @classmethod
    def _link_existing(cls, v: str | None) -> str | None:
        return v.strip() or None if v is not None else None

    @model_validator(mode="after")
    def _exactly_one_profile_source(self) -> "CreateUserRequest":
        if bool(self.mac) == bool(self.link_existing_vpn_profile):
            raise ValueError(
                "Provide either a Device MAC Address (to create a new VPN profile) or an existing "
                "VPN profile to link, not both and not neither."
            )
        return self

    # Portal Login Restrictions -- User.restrict_login_by_*/allowed_login_*,
    # enforced only by routes/auth.py's login check.
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

    # VPN Access Restrictions -- a completely separate set from the Portal
    # ones above, applied to the just-created client's policy_store entry
    # (see create_user() below), same as Manage Restrictions on the
    # Clients page would do. Independent storage (client_policy.json, not
    # a User column) and independent enforcement (host-scripts/
    # openvpn-mac-addr-check.py, not routes/auth.py's login check) -- see
    # app_settings.migrate_decouple_portal_and_vpn_restrictions's docstring
    # for why these must never be synced with the Portal fields above.
    vpn_restrict_by_country: bool = False
    vpn_allowed_countries: list[str] = []
    vpn_restrict_by_ip: bool = False
    vpn_allowed_ips: list[str] = []
    vpn_restrict_by_city: bool = False
    vpn_allowed_cities: list[str] = []
    vpn_restrict_by_asn: bool = False
    vpn_allowed_asns: list[str] = []

    @field_validator("vpn_allowed_countries")
    @classmethod
    def _vpn_countries(cls, v: list[str]) -> list[str]:
        return _valid_country_list(v)

    @field_validator("vpn_allowed_ips")
    @classmethod
    def _vpn_ips(cls, v: list[str]) -> list[str]:
        return _valid_ip_list(v)

    @field_validator("vpn_allowed_cities")
    @classmethod
    def _vpn_cities(cls, v: list[str]) -> list[str]:
        return _valid_city_list(v)

    @field_validator("vpn_allowed_asns")
    @classmethod
    def _vpn_asns(cls, v: list[str]) -> list[str]:
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

    # Edit User's "Force Password Reset on Next Login" checkbox -- an
    # explicit, independent toggle for User.must_reset_password, on top of
    # the implicit True an admin password reset (the `password` field
    # above) already forces. None (field omitted) means "not touched by
    # this checkbox"; model_fields_set decides, same convention as every
    # other optional field here. Lets an admin either flag an existing
    # account for a mandatory reset without changing its password, or
    # cancel a pending one (uncheck + save) before the user has logged in
    # again -- see update_user()'s handling below for how this interacts
    # with an in-the-same-request password reset.
    force_password_reset: bool | None = None

    # Multi-Factor Authentication -- per-user override of the global/role
    # policy (see mfa.effective_policy). "required"/"optional"/"exempt", or
    # explicit null to clear back to "inherit role/global" -- same
    # model_fields_set-driven optional-field convention as every other
    # field here.
    mfa_policy_override: str | None = None

    @field_validator("mfa_policy_override")
    @classmethod
    def _mfa_policy_override_choice(cls, v: str | None) -> str | None:
        from ..mfa import VALID_POLICY_OVERRIDES
        if v is not None and v not in VALID_POLICY_OVERRIDES:
            raise ValueError(f"MFA policy override must be one of: {', '.join(VALID_POLICY_OVERRIDES)}.")
        return v

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

    # VPN Access Restrictions -- edits this user's linked client's
    # policy_store entry directly (see update_user() below), completely
    # separate from the Portal Login Restriction fields above. None means
    # "not provided in this PATCH" (model_fields_set decides, same
    # convention as every other field here); an explicit []/false clears
    # that restriction kind.
    vpn_restrict_by_country: bool | None = None
    vpn_allowed_countries: list[str] | None = None
    vpn_restrict_by_ip: bool | None = None
    vpn_allowed_ips: list[str] | None = None
    vpn_restrict_by_city: bool | None = None
    vpn_allowed_cities: list[str] | None = None
    vpn_restrict_by_asn: bool | None = None
    vpn_allowed_asns: list[str] | None = None

    @field_validator("vpn_allowed_countries")
    @classmethod
    def _vpn_countries(cls, v: list[str] | None) -> list[str] | None:
        return _valid_country_list(v) if v is not None else v

    @field_validator("vpn_allowed_ips")
    @classmethod
    def _vpn_ips(cls, v: list[str] | None) -> list[str] | None:
        return _valid_ip_list(v) if v is not None else v

    @field_validator("vpn_allowed_cities")
    @classmethod
    def _vpn_cities(cls, v: list[str] | None) -> list[str] | None:
        return _valid_city_list(v) if v is not None else v

    @field_validator("vpn_allowed_asns")
    @classmethod
    def _vpn_asns(cls, v: list[str] | None) -> list[str] | None:
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

    # Self-service VPN login country restriction -- a single ISO 3166-1
    # alpha-2 code (unlike the admin-side allowed_countries multi-country
    # allowlist a VPN Access Restriction can hold via the Clients page's
    # Manage Restrictions dialog). Deliberately a single field, not a
    # toggle+list pair: the user-facing control is "pick one country, or
    # leave it blank," not "manage a list."
    #
    # VPN ACCESS ONLY -- this is written straight to policy_store (the
    # linked VPN profile's client_policy.json, the mechanism host-scripts/
    # openvpn-mac-addr-check.py actually enforces VPN connections against)
    # and NEVER touches User.restrict_login_by_country/allowed_login_countries
    # (the separate Portal Login Restriction columns routes/auth.py's login
    # check reads). Setting this can never block this account's own portal
    # sign-in, and clearing it can never weaken a Portal restriction an
    # admin configured separately -- see update_my_profile() below and
    # app_settings.migrate_decouple_portal_and_vpn_restrictions's docstring
    # for the full "these two used to be wrongly coupled" history. Explicit
    # "" or null clears the restriction entirely; omitted from the request
    # leaves it untouched (model_fields_set, same convention as every other
    # field here).
    login_country: str | None = None

    @field_validator("login_country")
    @classmethod
    def _login_country(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().upper()
        if not v:
            return None
        return _valid_country_list([v])[0]

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
        "must_reset_password": u.must_reset_password,
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
        # Portal Login Restrictions -- User columns, enforced only by
        # routes/auth.py's login check. Independent from the VPN Access
        # Restrictions block below; see
        # app_settings.migrate_decouple_portal_and_vpn_restrictions's
        # docstring for why these two used to be (wrongly) coupled.
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
        # VPN Access Restrictions -- read-only here, straight from
        # policy_store (the linked client's client_policy.json), enforced
        # only by host-scripts/openvpn-mac-addr-check.py. Edited via the
        # Clients page's Manage Restrictions dialog (PUT
        # /api/clients/{name}/policy), not through this user endpoint --
        # surfaced here purely so Edit User can show an admin both
        # restriction sets side by side without a second request. A
        # "restrict_by" toggle has no separate boolean in policy_store
        # (unlike the Portal columns above): presence of a non-empty list
        # IS the toggle.
        "vpn_restrict_by_country": bool(policy.get("allowed_countries")),
        "vpn_allowed_countries": policy.get("allowed_countries") or [],
        "vpn_restrict_by_city": bool(policy.get("allowed_cities")),
        "vpn_allowed_cities": policy.get("allowed_cities") or [],
        "vpn_restrict_by_asn": bool(policy.get("allowed_asns")),
        "vpn_allowed_asns": policy.get("allowed_asns") or [],
        "vpn_restrict_by_ip": bool(policy.get("allowed_ips")),
        "vpn_allowed_ips": policy.get("allowed_ips") or [],
        # Multi-Factor Authentication -- User Management's status column +
        # Edit User dialog (see mfa.py for effective_policy's precedence).
        "mfa_enabled": u.mfa_enabled,
        "mfa_setup_required": u.mfa_setup_required,
        "mfa_enrolled_at": u.mfa_enrolled_at.isoformat() if u.mfa_enrolled_at else None,
        "mfa_last_used_at": u.mfa_last_used_at.isoformat() if u.mfa_last_used_at else None,
        "mfa_policy_override": u.mfa_policy_override,
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
    # Bug fix: this used to check `value is not None`, which can't tell
    # "field omitted from the request" apart from "explicitly cleared to
    # null" -- and profile.html's own form DOES send `last_name: ... ||
    # null` when the field is blanked out (same as Edit User's admin-side
    # form), so clearing your own Last Name silently did nothing while
    # typing a different value worked fine. model_fields_set is the
    # correct check here too, same as email/phone right below.
    for field in ("first_name", "last_name", "gender"):
        if field in body.model_fields_set:
            value = getattr(body, field)
            if value != getattr(user, field):
                setattr(user, field, value)
                changes.append(field)
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
        try:
            _check_password_reuse(user, body.new_password)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        _record_password_history(user)
        user.password_hash = hash_password(body.new_password)
        # A successful SELF-service change (current password verified
        # above) is the one action that proves the account holder actually
        # knows/received the current password -- clears the forced-change
        # gate that routes/pages.py enforces on every page. See models.py's
        # must_reset_password docstring for what sets this flag.
        user.must_reset_password = False
        changes.append("password")

    if changes:
        db.commit()
        log_action(db, user, "update_own_profile", target=user.username, detail=", ".join(changes))

    # VPN Login Country: written STRAIGHT to policy_store (the linked VPN
    # profile's client_policy.json), never to User.restrict_login_by_country/
    # allowed_login_countries -- those are Portal Login Restrictions, only
    # ever consulted by routes/auth.py's login check. This field is VPN
    # Access Restrictions only, exactly per its docstring on
    # UpdateProfileRequest: setting it must never affect this account's
    # ability to log into the portal, and clearing it must never touch
    # whatever Portal restriction an admin separately configured for this
    # user. Requires a linked VPN profile -- there's no other place for a
    # VPN-only restriction to live for an account that has no VPN profile.
    client_name = user.vpn_profile_link.vpn_client_name if user.vpn_profile_link else None
    policy = policy_store.get_policy(client_name) if client_name else {}
    if "login_country" in body.model_fields_set:
        if client_name is None:
            raise HTTPException(
                status_code=400,
                detail="You don't have a linked VPN profile yet, so a VPN login country restriction can't be applied. "
                       "Contact your administrator.",
            )
        try:
            policy = policy_store.set_policy(
                client_name,
                allowed_countries=[body.login_country] if body.login_country else None,
            )
            log_action(db, user, "update_own_profile", target=user.username,
                       detail=f"VPN login country {body.login_country or '(cleared)'}")
        except (PolicyValidationError, OSError) as e:
            log_action(db, user, "update_own_profile", target=user.username,
                       detail=f"VPN login country restriction could not be applied: {e}", success=False)
            raise HTTPException(status_code=400, detail=f"Could not apply that restriction: {e}")
    return _serialize(user, {client_name: policy} if client_name else {})


@router.post("", status_code=201)
def create_user(body: CreateUserRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first() is not None:
        raise HTTPException(status_code=409, detail=f"Username '{body.username}' already exists.")
    teams = _resolve_teams(db, body.team_ids)
    role_def = _resolve_creatable_role(db, body.role)

    # Two mutually-exclusive ways to give this new user a VPN profile (see
    # CreateUserRequest._exactly_one_profile_source): provision a brand new
    # one (the original, still-default path), or attach an existing,
    # not-yet-linked profile -- same "attach" semantics as VpnLinkRequest/
    # link_vpn_profile() below, inlined here rather than called as a
    # sub-request so the whole thing stays one transaction with the User
    # row (link_vpn_profile() requires the user to already exist, which
    # isn't true yet at this point in create_user()).
    effective_client_name = body.username
    link_source = "created_with_profile"
    linked_by = None
    if body.link_existing_vpn_profile:
        effective_client_name = body.link_existing_vpn_profile
        link_source = "manual_admin_link"
        linked_by = admin.username
        if db.query(VpnProfileLink).filter(VpnProfileLink.vpn_client_name == effective_client_name).first() is not None:
            raise HTTPException(status_code=409, detail=f"'{effective_client_name}' is already linked to another user.")
        existing_names = {c.get("name") for c in cli.get_clients_snapshot()}
        if effective_client_name not in existing_names:
            raise HTTPException(status_code=404, detail=f"No VPN profile named '{effective_client_name}' exists.")
    else:
        # VPN cert is created FIRST, before any DB write -- a MAC/name
        # conflict (or any other cli.add_client failure) means no user is
        # created at all, matching the approved failure-recovery design
        # (see vpn_identity_sync.py's module comment, plan §7): a partial
        # "user exists, cert doesn't" state should never happen. The
        # reverse ("cert exists, user creation then fails") is the one
        # accepted rare edge case -- see the except block below for the
        # recovery path.
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
        # Every newly-provisioned account must change its password on
        # first login, regardless of how the admin set it -- see
        # models.py's must_reset_password docstring for the full policy.
        must_reset_password=True,
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
        db.add(VpnProfileLink(user_id=user.id, vpn_client_name=effective_client_name, link_source=link_source, linked_by=linked_by))
        db.commit()
    except Exception:
        db.rollback()
        # Accepted rare edge case (per approved failure-recovery design):
        # the VPN cert now exists but no portal user/link was created for
        # it. Surface a clear, actionable error rather than a generic 500 --
        # the admin's recovery path is Edit User -> "Attach existing VPN
        # profile" on whatever user this was meant for (or a fresh Add
        # User with the same MAC, since the name is now taken by the
        # orphaned cert -- pick a different username, then attach). When
        # link_existing_vpn_profile was used, the profile itself pre-dates
        # this request entirely (nothing of ours to roll back besides the
        # DB rows already handled above), so the message only talks about
        # a freshly-created cert in the create-new case.
        log_action(db, admin, "create_user", target=body.username,
                   detail=f"VPN profile '{effective_client_name}' was to be linked but the user record failed to save", success=False)
        if body.link_existing_vpn_profile:
            raise HTTPException(
                status_code=500,
                detail=f"Saving the user account failed. '{effective_client_name}' was NOT linked -- try again, or use "
                       f"Edit User's \"Attach existing VPN profile\" once the account exists.",
            )
        raise HTTPException(
            status_code=500,
            detail=f"A VPN profile named '{effective_client_name}' was created, but saving the user account failed. "
                   f"The VPN profile was NOT rolled back -- use Edit User's \"Attach existing VPN profile\" to link it "
                   f"to an account manually.",
        )
    log_action(db, admin, "create_user", target=body.username, detail=f"role={role_def.slug}")

    # Sync VPN-profile-level OS/bandwidth/Access Restrictions onto the
    # just-created client, same write path as Manage Restrictions on the
    # Clients page. Best-effort: every field here is already validated at
    # the Pydantic level above, so this should never actually raise -- but
    # the user/link/cert all already exist at this point, so a failure
    # here (e.g. a filesystem hiccup writing client_policy.json) must not
    # undo any of that. Skipped entirely (no file write at all) when
    # nothing was set -- matches policy_store's own "no policy entry =
    # fully unrestricted" default, avoids touching client_policy.json for
    # the common case.
    #
    # vpn_restrict_by_*/vpn_allowed_* (VPN Access Restrictions) are a
    # completely separate field set from restrict_login_by_*/
    # allowed_login_* (Portal Login Restrictions, set on the User columns
    # right below) -- deliberately NOT derived from each other. See
    # app_settings.migrate_decouple_portal_and_vpn_restrictions's docstring
    # for the full history of why these two used to be (wrongly) coupled.
    # Settings -> VPN Management's org-wide default only fills in when this
    # request left the per-user quota blank -- an explicit 0.1+ GB value on
    # the form (including one that happens to match the default) always
    # wins, same "most specific setting wins" precedence as every other
    # env-var/DB-row-default pair in this app (see app_settings.py).
    effective_bandwidth = body.bandwidth_monthly_gb if body.bandwidth_monthly_gb is not None else app_settings.runtime.default_bandwidth_monthly_gb
    policy = {}
    if body.allowed_os or effective_bandwidth or body.vpn_restrict_by_country or body.vpn_restrict_by_city \
            or body.vpn_restrict_by_asn or body.vpn_restrict_by_ip:
        try:
            policy = policy_store.set_policy(
                effective_client_name,
                allowed_os=body.allowed_os or None,
                bandwidth_monthly_gb=effective_bandwidth,
                allowed_countries=body.vpn_allowed_countries if body.vpn_restrict_by_country else None,
                allowed_cities=body.vpn_allowed_cities if body.vpn_restrict_by_city else None,
                allowed_asns=body.vpn_allowed_asns if body.vpn_restrict_by_asn else None,
                allowed_ips=body.vpn_allowed_ips if body.vpn_restrict_by_ip else None,
            )
        except (PolicyValidationError, OSError) as e:
            log_action(db, admin, "create_user", target=body.username,
                       detail=f"VPN profile restrictions could not be applied: {e}", success=False)

    if app_settings.runtime.notify_admin_on_user_created:
        mailer.send_admin_notification(
            db=db, subject=f"New user created: {body.username}",
            body=(
                f"{admin.username} created a new user account.\n\n"
                f"Username: {body.username}\n"
                f"Role: {role_def.name}\n"
                f"Email: {body.email}\n"
                f"VPN profile: {effective_client_name}"
                f"{' (existing profile, linked)' if body.link_existing_vpn_profile else ''}\n"
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
            ovpn_content = cli.show_ovpn(effective_client_name)
            # send_welcome_email, not send_ovpn_profile -- this is the only
            # request-scoped moment body.password (plaintext) exists at
            # all; it's hashed above and never recoverable again, so the
            # portal-credentials-inclusive welcome email can only ever be
            # sent from here, never as a later "resend" (see mailer.py's
            # send_welcome_email docstring for the full reasoning).
            mailer.send_welcome_email(
                db=db, to_address=body.email, username=body.username, password=body.password,
                client_name=effective_client_name, ovpn_content=ovpn_content, recipient_name=recipient_name,
            )
            log_action(db, admin, "email_ovpn", target=body.username, detail=f"welcome email sent to {body.email} (on creation)", success=True)
        except Exception as e:
            email_warning = f"User created, but the welcome email could not be sent: {e}"
            log_action(db, admin, "email_ovpn", target=body.username, detail=f"welcome email to {body.email} failed (on creation): {e}", success=False)

    result = _serialize(user, {effective_client_name: policy})
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
        try:
            _check_password_reuse(target, body.password)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        _record_password_history(target)
        target.password_hash = hash_password(body.password)
        # Same "not yet confirmed by the account holder" reasoning as a
        # freshly-created account -- see models.py's must_reset_password
        # docstring. Forces a change on next login even though the admin
        # (not the account holder) is the one who just set this password.
        target.must_reset_password = True
        # An admin setting a brand-new password is at least as strong a
        # signal as the self-service forgot-password flow (which already
        # clears these two, see auth.py's reset_password_submit) -- without
        # this, an admin "rescuing" a locked-out user by resetting their
        # password wouldn't actually unlock them; they'd still have to wait
        # out the stale lockout window on top of learning the new password.
        target.failed_login_attempts = 0
        target.locked_until = None
        changes.append("password reset")
    elif "force_password_reset" in body.model_fields_set and body.force_password_reset != target.must_reset_password:
        # Independent of the password-reset branch above -- only reached
        # when this PATCH did NOT also reset the password (a password
        # reset already forces True unconditionally, and takes priority
        # over a stale/contradictory checkbox state in the same request).
        # True = admin flags an existing account for a mandatory reset
        # without touching its password. False = admin cancels a pending
        # one before the user has logged in again.
        target.must_reset_password = body.force_password_reset
        changes.append(f"force_password_reset {target.must_reset_password}")
    # Bug fix: this used to check `value is not None` -- indistinguishable
    # from "field omitted from the request" -- so an explicit `null` (e.g.
    # clearing Last Name in the Edit User form) was silently ignored
    # instead of clearing the column, while typing a NEW value worked fine
    # (that path isn't None either way). model_fields_set is the correct
    # check, same pattern the email/phone loop right below already uses.
    for field in ("first_name", "last_name", "gender"):
        if field in body.model_fields_set:
            value = getattr(body, field)
            if value != getattr(target, field):
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
    if "mfa_policy_override" in body.model_fields_set and body.mfa_policy_override != target.mfa_policy_override:
        old_override = target.mfa_policy_override or "inherit"
        target.mfa_policy_override = body.mfa_policy_override
        changes.append(f"mfa_policy_override {old_override}->{body.mfa_policy_override or 'inherit'}")
        # "MFA bypass granted" is specifically an override set to "exempt"
        # -- see the spec's own audit event list -- a dedicated, directly
        # searchable entry beyond the generic "update_user" line below.
        if body.mfa_policy_override == "exempt":
            log_action(db, admin, "mfa_bypass_granted", target=target.username, success=True)

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

    # Sync VPN-profile-level OS/bandwidth/Access Restrictions onto the
    # linked client's policy -- a no-op if this user has no linked profile
    # yet (the rare cert-created-but-DB-failed edge case; there's nothing
    # to sync onto until an admin attaches one via the vpn-link endpoint
    # below).
    #
    # vpn_restrict_by_*/vpn_allowed_* are VPN Access Restrictions, edited
    # here (Edit User) or equally via the Clients page's Manage
    # Restrictions dialog (PUT /api/clients/{name}/policy) -- both write
    # the exact same policy_store entry, so either surface reflects the
    # other's edits. Deliberately NOT derived from
    # restrict_login_by_country/city/asn/ip (just committed onto `target`
    # above, Portal Login Restrictions) -- the two field sets are fully
    # independent; see app_settings.migrate_decouple_portal_and_vpn_
    # restrictions's docstring for the full rationale.
    #
    # Each restriction kind's touched-ness is judged from ITS OWN
    # toggle+list pair in this PATCH (not "any restriction field present"),
    # same reasoning Portal's own restrict_login_by_country +
    # allowed_login_countries pairing needed before -- the Edit User form
    # always submits a kind's toggle and list together, so treating them as
    # one unit here is safe and avoids a stray, unrelated field in
    # model_fields_set accidentally overwriting a restriction kind nobody
    # touched.
    vpn_country_touched = bool({"vpn_restrict_by_country", "vpn_allowed_countries"} & body.model_fields_set)
    vpn_city_touched = bool({"vpn_restrict_by_city", "vpn_allowed_cities"} & body.model_fields_set)
    vpn_asn_touched = bool({"vpn_restrict_by_asn", "vpn_allowed_asns"} & body.model_fields_set)
    vpn_ip_touched = bool({"vpn_restrict_by_ip", "vpn_allowed_ips"} & body.model_fields_set)
    client_name = target.vpn_profile_link.vpn_client_name if target.vpn_profile_link else None
    policy = policy_store.get_policy(client_name) if client_name else {}
    if client_name and ("allowed_os" in body.model_fields_set or "bandwidth_monthly_gb" in body.model_fields_set
                         or vpn_country_touched or vpn_city_touched or vpn_asn_touched or vpn_ip_touched):
        try:
            policy = policy_store.set_policy(
                client_name,
                allowed_os=body.allowed_os if "allowed_os" in body.model_fields_set else ...,
                bandwidth_monthly_gb=body.bandwidth_monthly_gb if "bandwidth_monthly_gb" in body.model_fields_set else ...,
                allowed_countries=(body.vpn_allowed_countries if body.vpn_restrict_by_country else None) if vpn_country_touched else ...,
                allowed_cities=(body.vpn_allowed_cities if body.vpn_restrict_by_city else None) if vpn_city_touched else ...,
                allowed_asns=(body.vpn_allowed_asns if body.vpn_restrict_by_asn else None) if vpn_asn_touched else ...,
                allowed_ips=(body.vpn_allowed_ips if body.vpn_restrict_by_ip else None) if vpn_ip_touched else ...,
            )
            log_action(db, admin, "update_user", target=target.username, detail="synced VPN profile restrictions")
        except (PolicyValidationError, OSError) as e:
            log_action(db, admin, "update_user", target=target.username,
                       detail=f"VPN profile restrictions could not be applied: {e}", success=False)
    return _serialize(target, {client_name: policy} if client_name else {})


def _get_mfa_target(user_id: int, db: Session) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return target


def _mfa_admin_notice_and_email(admin: User, target: User, db: Session, event_description: str) -> None:
    from .. import mfa as mfa_module
    if mfa_module.is_privileged(target, db) and app_settings.runtime.notify_admin_on_mfa_disabled:
        mailer.send_admin_notification(
            db=db, subject="MFA disabled for a privileged account",
            body=f"{admin.username} disabled multi-factor authentication for {target.username} ({target.display_name}).",
        )
    if target.email:
        mailer.send_mfa_security_notice(db=db, to_address=target.email, username=target.username, event_description=event_description)


@router.post("/{user_id}/mfa/reset")
def reset_user_mfa(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """"Reset MFA" -- used when a user loses their authenticator device.
    Clears the current enrollment entirely (secret + recovery codes) AND
    forces re-enrollment at next login (mfa_setup_required=True) -- unlike
    /mfa/disable below, this doesn't leave the account MFA-less if the
    effective policy still requires it."""
    from ..models import MfaRecoveryCode

    target = _get_mfa_target(user_id, db)
    target.mfa_enabled = False
    target.mfa_secret_encrypted = None
    target.mfa_setup_required = True
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == target.id).delete()
    db.commit()
    log_action(db, admin, "mfa_reset_by_admin", target=target.username, success=True)
    _mfa_admin_notice_and_email(admin, target, db, "An administrator reset multi-factor authentication on your account -- you'll be asked to set it up again at your next login.")
    return {"message": f"MFA reset for '{target.username}' -- they'll be asked to re-enroll at next login."}


@router.post("/{user_id}/mfa/disable")
def disable_user_mfa(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """"Disable MFA" -- troubleshooting/temporary access. Unlike /mfa/reset
    above, does NOT force re-enrollment -- the account is simply left
    without MFA until the user (or another admin action) re-enables it."""
    from ..models import MfaRecoveryCode

    target = _get_mfa_target(user_id, db)
    target.mfa_enabled = False
    target.mfa_secret_encrypted = None
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == target.id).delete()
    db.commit()
    log_action(db, admin, "mfa_disabled_by_admin", target=target.username, success=True)
    _mfa_admin_notice_and_email(admin, target, db, "An administrator disabled multi-factor authentication on your account.")
    return {"message": f"MFA disabled for '{target.username}'."}


@router.post("/{user_id}/mfa/force-enroll")
def force_enroll_user_mfa(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """"Force MFA Enrollment" -- requires the user to complete enrollment at
    their NEXT login, without touching their current enrollment state
    (unlike /mfa/reset, this doesn't clear an already-working enrollment)."""
    target = _get_mfa_target(user_id, db)
    target.mfa_setup_required = True
    db.commit()
    log_action(db, admin, "mfa_force_enroll", target=target.username, success=True)
    return {"message": f"'{target.username}' will be required to set up MFA at their next login."}


class VpnLinkRequest(BaseModel):
    vpn_client_name: str


@router.post("/{user_id}/vpn-link", status_code=201)
def link_vpn_profile(user_id: int, body: VpnLinkRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Attaches an existing, unlinked VPN profile to a user -- or, if the
    user already has one linked, REPLACES that link with this one (task
    feedback: "Remove the immutable behavior for the VPN Profile
    association... Allow administrators to modify an existing VPN Profile
    assignment... Replace it with another available VPN Profile"). The
    previous link, if any, is simply deleted: its VPN client itself (cert,
    MAC allowlist, connection history, usage, VPN Access Restrictions) is
    completely untouched and becomes unassigned again -- exactly the same
    state as a client that was never linked to any portal account, visible
    again via GET /api/clients/unassigned for attaching elsewhere later.
    Mirrors vpn_identity_sync.auto_link_new_client's "link an existing
    user" branch, but for the inverse trigger (an admin picking the
    profile from Edit User, not a cert being created) -- link_source
    records that distinction (manual_admin_link vs. created_with_profile).

    VpnProfileLink.vpn_client_name is unique at the DB level, so a race
    between two admins attaching the same just-unassigned profile to two
    different users can't both succeed -- the loser gets a clean 409 from
    the IntegrityError below, never a silent double-link."""
    target = db.get(User, user_id)
    if target is None or target.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    name = body.vpn_client_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="VPN profile name is required.")
    existing_link = target.vpn_profile_link
    if existing_link is not None and existing_link.vpn_client_name == name:
        raise HTTPException(status_code=400, detail=f"'{target.username}' is already linked to '{name}'.")
    if db.query(VpnProfileLink).filter(VpnProfileLink.vpn_client_name == name).first() is not None:
        raise HTTPException(status_code=409, detail=f"'{name}' is already linked to another user.")
    previous_name = existing_link.vpn_client_name if existing_link is not None else None
    if existing_link is not None:
        db.delete(existing_link)
        db.flush()  # clears the user_id unique slot before the insert below reuses it, same transaction
    db.add(VpnProfileLink(user_id=target.id, vpn_client_name=name, link_source="manual_admin_link", linked_by=admin.username))
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"'{name}' was just linked to another user -- pick a different profile.")
    if previous_name:
        log_action(db, admin, "reassign_vpn_profile", target=target.username, detail=f"'{previous_name}' -> '{name}'")
    else:
        log_action(db, admin, "link_vpn_profile", target=target.username, detail=name)

    # Deliberately NOT syncing this user's Portal Login Restrictions (or
    # anything else) onto the (re)attached client's policy -- VPN Access
    # Restrictions are edited directly (Manage Restrictions on the Clients
    # page, or Edit User's own VPN Access Restrictions fieldset), never
    # derived from a User's Portal columns or carried over from whatever
    # was previously linked. See app_settings.migrate_decouple_portal_
    # and_vpn_restrictions's docstring for why that sync existed once and
    # was removed. The (re)attached client keeps exactly the policy it
    # already had -- its own restrictions, OS/bandwidth quota, usage
    # history -- untouched by this call, same as picking it from the
    # unassigned list on day one.
    return _serialize(target, {name: policy_store.get_policy(name)})


@router.delete("/{user_id}/vpn-link")
def unlink_vpn_profile(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Clears a user's VPN Profile assignment without deleting or revoking
    anything -- task feedback: "Administrators should be able to... Clear
    the assignment if appropriate." The VPN client itself (cert, MAC
    allowlist, connection history, usage, VPN Access Restrictions) is
    completely untouched; it simply becomes unassigned again, exactly like
    a client that was never linked to any portal account, and is visible
    again via GET /api/clients/unassigned for attaching elsewhere. Actually
    revoking/deleting the underlying VPN client stays a deliberate, separate
    action on the Clients page -- this endpoint only ever touches the
    User<->VpnProfileLink association."""
    target = db.get(User, user_id)
    if target is None or target.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    link = target.vpn_profile_link
    if link is None:
        raise HTTPException(status_code=400, detail=f"'{target.username}' has no linked VPN profile to clear.")
    client_name = link.vpn_client_name
    db.delete(link)
    db.commit()
    log_action(db, admin, "unlink_vpn_profile", target=target.username, detail=client_name)
    return _serialize(target, {})


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
