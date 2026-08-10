import ipaddress
import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import app_settings, geo_lists, vpn_identity_sync
from ..audit import log_action
from ..auth import hash_password, require_user, verify_password
from ..db import get_db
from ..models import Gender, Role, RoleDef, Team, User
from ..permissions import require_permission

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


def _valid_password(v: str) -> str:
    # Minimum length is admin-configurable (Settings page -> Security);
    # read live off the runtime cache rather than a hardcoded 8, so a
    # changed policy applies to the very next request, not just after a
    # restart. See app_settings.py.
    min_len = app_settings.runtime.min_password_length
    if len(v) < min_len:
        raise ValueError(f"Password must be at least {min_len} characters.")
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


def _valid_email(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if not v:
        return None  # explicit "" from the form means "clear it", not an error
    if not _EMAIL_RE.match(v):
        raise ValueError("That doesn't look like a valid email address.")
    if ".." in v:
        raise ValueError("That doesn't look like a valid email address.")
    local = v.split("@", 1)[0]
    if local.startswith(".") or local.endswith("."):
        raise ValueError("That doesn't look like a valid email address.")
    return v


# Pakistan (+92) gets a real, strict shape check -- 3-digit mobile prefix,
# dash, 7-digit subscriber number, e.g. +92-333-1234567 -- because that's
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
                "Pakistani phone numbers must be in the format +92-333-1234567 "
                "(3-digit prefix, dash, 7-digit number)."
            )
        return v

    if _PHONE_GENERAL_RE.match(v) or _PHONE_LEGACY_RE.match(v):
        return v
    raise ValueError(
        "Phone number must be in the format +<country code>-<number>, e.g. +92-333-1234567."
    )


def _valid_country_list(v: list[str]) -> list[str]:
    """Same lightweight "2-letter alpha shape" check as policy_store.py's
    client-country validator -- not a fixed enum against a real ISO list,
    for the same reason: less to maintain, and this app's own country
    dropdown (app.js's ISO_3166_COUNTRIES) is already the real source of
    truth for what a human picks from in the UI. Normalizes to uppercase
    and dedupes, preserving first-seen order."""
    seen = []
    for code in v:
        code = (code or "").strip().upper()
        if not code:
            continue
        if len(code) != 2 or not code.isalpha():
            raise ValueError(f"Invalid country code: '{code}' -- expected an ISO 3166-1 alpha-2 code (e.g. PK).")
        if code not in seen:
            seen.append(code)
    return seen


def _valid_ip_list(v: list[str]) -> list[str]:
    """Each entry is either a single IP address or a CIDR range, dual-stack
    (IPv4/IPv6) -- see client_ip.py's ip_matches_allowlist, the runtime
    counterpart that checks a login attempt's IP against exactly this
    list. Normalizes each entry to str(ipaddress...) form (consistent
    formatting regardless of how the admin typed it, e.g. leading zeros)
    and dedupes, preserving first-seen order."""
    seen = []
    for entry in v:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            normalized = str(ipaddress.ip_network(entry, strict=False)) if "/" in entry else str(ipaddress.ip_address(entry))
        except ValueError:
            raise ValueError(f"'{entry}' isn't a valid IP address or CIDR range (e.g. 203.0.113.5 or 10.0.0.0/24).")
        if normalized not in seen:
            seen.append(normalized)
    return seen


def _valid_city_list(v: list[str]) -> list[str]:
    """Each entry must be a real city name from geo_lists.py's City
    pick-list -- picker-only, no free text (see users.html's cascading
    country -> city selector): a hand-typed name GeoIP could never
    actually return at login time would create a restriction that can
    never be satisfied, i.e. a silent, permanent lockout for that
    restriction type. Canonicalizes to the exact casing MaxMind uses and
    dedupes case-insensitively. If the city index hasn't finished its
    first build yet (fresh install / just-replaced mmdb, see geo_lists.py
    for the rebuild window), city_exists() returns None and this falls
    back to a shape-only check instead of blocking admins entirely during
    that window."""
    seen_lower = set()
    result = []
    for name in v:
        name = (name or "").strip()
        if not name:
            continue
        exists = geo_lists.city_exists(name)
        if exists is False:
            raise ValueError(f"'{name}' isn't a known city in the GeoIP database -- pick one from the list.")
        canonical = geo_lists.canonical_city(name) if exists else name
        if len(canonical) > 100:
            raise ValueError(f"City name too long (max 100 characters): '{canonical[:40]}...'")
        key = canonical.lower()
        if key not in seen_lower:
            seen_lower.add(key)
            result.append(canonical)
    return result


def _valid_asn_list(v: list[str]) -> list[str]:
    """Each entry must be a real ASN from geo_lists.py's ASN pick-list --
    same picker-only rationale as _valid_city_list. Normalizes shape
    ("15169" or "as15169" -> "AS15169") first, then checks membership;
    same not-yet-built fallback as _valid_city_list via asn_exists()
    returning None."""
    seen = []
    for entry in v:
        entry = (entry or "").strip().upper()
        if not entry:
            continue
        digits = entry[2:] if entry.startswith("AS") else entry
        if not digits.isdigit():
            raise ValueError(f"'{entry}' isn't a valid AS number -- expected e.g. AS15169 or 15169.")
        normalized = f"AS{int(digits)}"
        exists = geo_lists.asn_exists(normalized)
        if exists is False:
            raise ValueError(f"'{normalized}' isn't a known network in the GeoIP database -- pick one from the list.")
        if normalized not in seen:
            seen.append(normalized)
    return seen


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
    email: str | None = None
    phone: str | None = None
    team_ids: list[int] = []

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
    def _email(cls, v: str | None) -> str | None:
        return _valid_email(v)

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
    def _email(cls, v: str | None) -> str | None:
        return _valid_email(v)

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
    team_ids: list[int] | None = None
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


def _serialize(u: User) -> dict:
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


@router.get("")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [_serialize(u) for u in db.query(User).filter(User.deleted.is_(False)).order_by(User.username).all()]


@router.get("/deleted")
def list_deleted_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [_serialize(u) for u in db.query(User).filter(User.deleted.is_(True)).order_by(User.deleted_at.desc()).all()]


@router.get("/me")
def whoami(user: User = Depends(require_user)):
    # Any logged-in user can see their own profile (unlike the admin-only
    # routes above) -- this is what the self-service /profile page reads.
    return _serialize(user)


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

    if "team_ids" in body.model_fields_set:
        new_teams = _resolve_teams(db, body.team_ids or [])
        if {t.id for t in new_teams} != {t.id for t in user.teams}:
            # Team membership determines which clients/routing policy a
            # user is scoped to -- letting a viewer self-assign into a
            # different team would be a privilege-adjacent change they
            # shouldn't be able to make unsupervised, even though everything
            # else on this form (name, gender, password) is fine for any
            # role to self-serve. Admins/editors still manage their own
            # teams here same as before; only an admin can change a
            # viewer's teams (via PATCH /api/users/{id}).
            if _role_slug(user) == "viewer":
                raise HTTPException(
                    status_code=403,
                    detail="Viewers can't change their own team assignment -- ask an admin.",
                )
            user.teams = new_teams
            changes.append("teams")

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
    role_def = _resolve_role(db, body.role)
    # The legacy `role` enum column (Role: admin/editor/viewer only) can't
    # represent a custom or vpn_self_service role -- role_id (below) is what
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
    db.add(user)
    db.commit()
    log_action(db, admin, "create_user", target=body.username, detail=f"role={role_def.slug}")
    return _serialize(user)


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
        if body.role is not None and body.role.strip().lower() != "admin":
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
        new_role_def = _resolve_role(db, body.role)
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
    return _serialize(target)


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
    log_action(db, admin, "permanently_delete_user", target=username,
               detail="hard-deleted from the deleted-users list -- irreversible")
    db.delete(target)
    db.commit()
    return {"message": f"User '{username}' permanently deleted. This cannot be undone."}
