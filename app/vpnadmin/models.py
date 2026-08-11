import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey, Table, UniqueConstraint, event
from sqlalchemy.orm import backref, validates, relationship

from .db import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    """Deprecated -- being replaced by the dynamic RoleDef/ObjectPermission
    system below (see docs/rbac_identity_design.md and the
    joyful-sauteeing-cookie plan). Kept, and User.role (the column it backs)
    kept mapped, only until Phase 2's route migration + role_id backfill are
    complete and verified in production; every *new* permission check should
    use RoleDef/require_permission, not this enum. Do not add new members
    here -- add a custom RoleDef row instead."""
    admin = "admin"
    editor = "editor"  # can add/revoke/edit VPN clients and manage their MAC
    # addresses (everything in routes/clients.py) -- but not user
    # management, teams, or settings, which stay admin-only
    viewer = "viewer"  # read-only: status/list/check/lint-db, no add/revoke/user-management


class RoleKind(str, enum.Enum):
    system = "system"  # the 4 seeded roles (admin/editor/viewer/user) --
    # undeletable, slug is fixed, see permissions.py's seed_system_roles
    custom = "custom"  # anything an admin creates via Roles Management


class RoleDef(Base):
    """Dynamic role, replacing the `Role` enum above. A role is just a name
    plus a bag of ObjectPermission/RoleApiScope rows -- see
    docs/rbac_identity_design.md §1.1 for the full design."""
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    slug = Column(String(64), unique=True, nullable=False, index=True)  # "admin","editor","viewer",
    # "user" (self-service role), or a custom admin-chosen slug
    name = Column(String(128), nullable=False)  # display name -- editable even for system roles
    description = Column(Text, nullable=True)
    kind = Column(Enum(RoleKind), nullable=False, default=RoleKind.custom)
    is_system = Column(Boolean, nullable=False, default=False)  # blocks delete + slug rename
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    created_by = Column(String(64), nullable=True)  # username snapshot, same pattern as AuditLog

    object_permissions = relationship(
        "ObjectPermission", back_populates="role", cascade="all, delete-orphan"
    )
    api_scopes = relationship(
        "RoleApiScope", back_populates="role", cascade="all, delete-orphan"
    )

    @validates("slug")
    def _normalize_slug(self, key, value):
        return value.strip().lower()


class ObjectPermission(Base):
    """One row per (role, object) -- the CRUD-ish permission matrix from the
    spec. `object_key` is a free string matched against the OBJECTS registry
    in permissions.py (e.g. "dashboard", "vpn_profiles", "users", "roles",
    "audit_log", "settings", "teams", "reports", "health") rather than its
    own DB table -- adding a future module is one line in that registry, not
    a migration."""
    __tablename__ = "role_object_permissions"

    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    object_key = Column(String(64), nullable=False)
    can_view = Column(Boolean, nullable=False, default=False)
    can_create = Column(Boolean, nullable=False, default=False)
    can_update = Column(Boolean, nullable=False, default=False)
    can_delete = Column(Boolean, nullable=False, default=False)
    can_execute = Column(Boolean, nullable=False, default=False)  # non-CRUD actions, e.g. "revoke client"
    can_manage = Column(Boolean, nullable=False, default=False)  # superset: full control incl. delegation

    role = relationship("RoleDef", back_populates="object_permissions")

    __table_args__ = (UniqueConstraint("role_id", "object_key", name="uq_role_object_permission"),)


class ApiScope(str, enum.Enum):
    any = "any"   # operate on any record of this object type
    own = "own"   # operate only on records the caller owns (self-service)


class RoleApiScope(Base):
    """Per (role, object): does this role's access apply to any record, or
    only the caller's own? Holds the same can_view/can_update semantics as
    ObjectPermission but adds the scope dial that makes VPN Self-Service
    User work -- see require_own_or_permission in permissions.py. Absence of
    a row for a given (role, object) defaults to scope="any" (i.e. this
    table only needs a row when a role is deliberately restricted to "own")."""
    __tablename__ = "role_api_scopes"

    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    object_key = Column(String(64), nullable=False)
    scope = Column(Enum(ApiScope), nullable=False, default=ApiScope.any)

    role = relationship("RoleDef", back_populates="api_scopes")

    __table_args__ = (UniqueConstraint("role_id", "object_key", name="uq_role_api_scope"),)


class Gender(str, enum.Enum):
    male = "male"
    female = "female"
    other = "other"
    unspecified = "unspecified"  # default -- nobody is forced to disclose this


class Team(Base):
    """A proper team resource (added on top of the earlier free-text `team`
    field on User -- see git history) so teams can be created/deleted/listed
    on their own, independent of whether any user currently belongs to one.
    Membership is many-to-many (see user_teams below) -- a user can belong
    to zero, one, or several teams; a user with no team is simply absent
    from every team's `members`, not a row here ("Unassigned" is a UI
    concept, not a database one)."""
    __tablename__ = "teams"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    # slug/description/tags added for future reporting (bandwidth/usage/
    # connection-stats by team) -- schema only for now, no reporting UI yet.
    # slug is nullable at the DB level (unlike RoleDef.slug) even though
    # it's required going forward at the API layer: existing rows predate
    # this column and db.py's generic column-sync migration can't backfill
    # a per-row-unique value on its own, so a small one-time slug backfill
    # runs at startup instead (see db.py's _backfill_team_slugs) -- nullable
    # here just means "not yet backfilled on an old row", not "optional."
    slug = Column(String(64), unique=True, nullable=True, index=True)
    description = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)  # JSON list of strings, same convention as User.allowed_login_countries etc.
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    members = relationship("User", secondary="user_teams", back_populates="teams", order_by="User.username")

    @validates("name")
    def _normalize_name(self, key, value):
        return value.strip()

    @validates("slug")
    def _normalize_slug(self, key, value):
        return value.strip().lower() if value else value


# Pure association table for the many-to-many User<->Team membership
# (replaces the earlier single nullable User.team_id FK -- see git history).
# A composite primary key (user_id, team_id) is enough here; there's no need
# for a surrogate id since a given user/team pair can only be linked once.
# New tables like this are picked up automatically by db.init_db()'s
# `Base.metadata.create_all()` -- no change needed to the migration helper
# itself, same as when the `teams` table was first added.
user_teams = Table(
    "user_teams",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("team_id", Integer, ForeignKey("teams.id"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.viewer)
    # Transitional dynamic-RBAC column, added alongside `role` above rather
    # than replacing it -- see docs/rbac_identity_design.md and the
    # joyful-sauteeing-cookie plan's Phase 1/2 split. Nullable and unused
    # until Phase 2's migrate_user_roles() backfill runs and every
    # permission check is confirmed moved onto it; only then does `role`
    # (the enum column above) get removed and this becomes non-nullable.
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)
    role_def = relationship("RoleDef")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    # Forces a password change on next login -- set True for accounts this
    # app auto-creates with a system-generated temp password (VPN profile
    # auto-linking, migration-created accounts; see VpnProfileLink and
    # routes/clients.py). Never set for accounts an admin creates with a
    # password they chose deliberately.
    must_reset_password = Column(Boolean, nullable=False, default=False)

    # Set once, only by auth.bootstrap_admin(), on the very first admin
    # account a fresh deployment creates. Used solely to make that specific
    # account's role permanently un-demotable (see routes/users.py) --
    # deliberately NOT the same thing as "any admin account" (every other
    # admin, including ones later promoted to admin, can be demoted by
    # another admin) or "whichever account is currently named
    # BOOTSTRAP_ADMIN_USERNAME" (that env var could be changed or reused
    # after the fact; this flag is a stable, one-time-set fact about the
    # account itself, immune to later config or username changes).
    is_bootstrap_admin = Column(Boolean, nullable=False, default=False)

    # Profile fields -- all optional except first_name (required, see
    # routes/users.py validators), self-service editable (see
    # routes/users.py PATCH /api/users/me) as well as admin-editable.
    first_name = Column(String(64), nullable=True)
    last_name = Column(String(64), nullable=True)
    gender = Column(Enum(Gender), nullable=False, default=Gender.unspecified)
    # Contact info -- purely informational (not used for login, password
    # reset, or notifications anywhere yet; SMTP delivery for .ovpn files
    # already takes an explicit address per-send, see routes/clients.py
    # email_client_ovpn). Both optional, same self-service/admin-editable
    # rules as first_name/last_name/gender above.
    email = Column(String(254), nullable=True)
    phone = Column(String(32), nullable=True)
    # Deprecated: replaced by the many-to-many `teams` relationship below
    # (a user can now belong to several teams at once, see git history) --
    # this nullable FK column may still physically exist in older databases
    # (this app's migration approach only ever ADDs columns, see db.py) but
    # is no longer read or written anywhere.
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=True)
    teams = relationship("Team", secondary="user_teams", back_populates="members", order_by="Team.name")

    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Soft delete: a "deleted" user is hidden from the normal active-user
    # list and can no longer log in, but the row (and its audit trail)
    # stays in the database and is visible in a dedicated admin view,
    # restorable at any time -- see PATCH /api/users/{id} `deleted` field.
    # Deliberately no hard-delete path is exposed in the UI/API.
    deleted = Column(Boolean, nullable=False, default=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    # --- Login restrictions (country / IP allowlisting) --------------------
    # Both independently toggleable and both optional -- an unset/False
    # restrict_login_by_* or an empty allowed_login_* list means "no
    # restriction of that kind", never a fail-closed lockout by default (see
    # routes/auth.py's login_submit, which only enforces a restriction when
    # BOTH the toggle is on AND the list is non-empty). Stored as JSON text
    # rather than a separate child table -- these are short, admin-only-
    # edited lists (a handful of country codes / IPs per user at most), not
    # something ever queried/joined against independently.
    restrict_login_by_country = Column(Boolean, nullable=False, default=False)
    allowed_login_countries = Column(Text, nullable=True)  # JSON list of ISO 3166-1 alpha-2 codes, e.g. ["PK","AE"]
    restrict_login_by_ip = Column(Boolean, nullable=False, default=False)
    allowed_login_ips = Column(Text, nullable=True)  # JSON list of IPs/CIDRs, e.g. ["203.0.113.5","10.0.0.0/24"]
    # City and ASN follow the exact same optional/independent pattern as
    # country/IP above -- see routes/users.py's _valid_city_list/
    # _valid_asn_list for the format each list entry takes.
    restrict_login_by_city = Column(Boolean, nullable=False, default=False)
    allowed_login_cities = Column(Text, nullable=True)  # JSON list of city names, e.g. ["Karachi","Lahore"]
    restrict_login_by_asn = Column(Boolean, nullable=False, default=False)
    allowed_login_asns = Column(Text, nullable=True)  # JSON list of AS numbers, e.g. ["AS15169","AS8075"]

    @validates("username")
    def _normalize_username(self, key, value):
        return value.strip().lower()

    @property
    def display_name(self) -> str:
        full = " ".join(p for p in (self.first_name, self.last_name) if p)
        return full or self.username

    @property
    def role_slug(self) -> str:
        """Dynamic-RBAC role slug, with a fallback to the legacy `role`
        enum for the narrow pre-backfill window -- see permissions.py's
        migrate_user_roles docstring. Used by templates (base.html,
        profile.html) so they never read the legacy enum column directly,
        which can't represent a custom or "User" self-service role."""
        return self.role_def.slug if self.role_def is not None else self.role.value

    @property
    def role_display_name(self) -> str:
        return self.role_def.name if self.role_def is not None else self.role.value.capitalize()


@event.listens_for(User, "before_insert")
def _default_role_id_from_legacy_role(mapper, connection, target: User) -> None:
    """Safety net for the Phase 1/2 transition (see permissions.py's
    migrate_user_roles docstring): if a User is being inserted with the
    legacy `role` enum set but role_id left unset -- e.g. a test fixture,
    or any other code path that still constructs `User(role=Role.admin)`
    directly instead of going through create_user()/bootstrap_admin(),
    both of which set role_id explicitly -- resolve it from the matching
    seeded RoleDef automatically rather than silently inserting a user
    every require_permission check will then reject. Uses the raw
    `connection` (mapper-level before_insert only gets a Core Connection,
    not an ORM Session) rather than a query, since the owning session may
    not have flushed RoleDef rows yet either."""
    if target.role_id is not None or target.role is None:
        return
    # target.role is normally a Role enum member, but SQLAlchemy's Enum
    # column type accepts a plain matching string transparently too (some
    # callers assign role="editor" directly rather than role=Role.editor)
    # -- handle both rather than assuming .value always exists.
    role_value = target.role.value if hasattr(target.role, "value") else target.role
    roles_table = RoleDef.__table__
    row = connection.execute(
        roles_table.select().where(roles_table.c.slug == role_value)
    ).first()
    if row is not None:
        target.role_id = row.id


class AppSettings(Base):
    """Runtime-editable application settings, admin-managed via the
    Settings page (routes/settings.py) -- a single singleton row (id is
    always 1), not a key/value table, so every setting is well-typed and
    discoverable straight from this class rather than a stringly-typed
    blob. Every column is nullable: NULL means "not overridden here, fall
    back to the environment-variable default in config.py" (see
    app_settings.py's EffectiveSettings), so a fresh install with no admin
    ever touching this page behaves exactly as it did before this table
    existed."""
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True)

    # Branding (see config.py's APP_NAME/APP_TAGLINE/APP_FOOTER_CREDIT)
    app_name = Column(String(128), nullable=True)
    app_tagline = Column(String(256), nullable=True)
    app_footer_credit = Column(String(256), nullable=True)

    # Outbound email (see config.py's SMTP_* / mailer.py)
    smtp_host = Column(String(255), nullable=True)
    smtp_port = Column(Integer, nullable=True)
    smtp_username = Column(String(255), nullable=True)
    smtp_password = Column(String(255), nullable=True)
    smtp_from = Column(String(255), nullable=True)
    smtp_use_tls = Column(Boolean, nullable=True)

    # Security
    min_password_length = Column(Integer, nullable=True)
    session_timeout_minutes = Column(Integer, nullable=True)

    # Audit log retention -- NULL/0 means "keep forever" (no pruning).
    audit_retention_days = Column(Integer, nullable=True)

    # Theming (see config.py's LOGIN_THEME) -- NULL/"auto" rotates through
    # all 6 named themes on a fixed 2-hour schedule (see app_settings.py's
    # resolve_active_theme); any other value pins that one theme.
    login_theme = Column(String(32), nullable=True)

    # Display timezone (see config.py's APP_TIMEZONE) -- an IANA name, e.g.
    # "Asia/Karachi". Purely a display setting: every stored timestamp
    # stays UTC, this only affects how app.js's fmtTimestamp() renders it.
    timezone = Column(String(64), nullable=True)
    # "24h" or "12h" -- paired with timezone above, same fmtTimestamp().
    time_format = Column(String(8), nullable=True)

    updated_at = Column(DateTime(timezone=True), nullable=True)
    updated_by = Column(String(64), nullable=True)  # username snapshot, not a FK -- see AuditLog for the same pattern


class AuditLog(Base):
    """Records every state-changing action (add/revoke client, user
    management), for accountability -- who did what, and when. Read-only
    operations (list/status/check) are deliberately NOT logged here to keep
    this table meaningful rather than a firehose of GET requests."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    username = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)  # e.g. "add_client", "revoke_client"
    target = Column(String(128), nullable=True)  # e.g. the client name affected
    detail = Column(Text, nullable=True)  # short human-readable outcome/error
    success = Column(Boolean, nullable=False, default=True)


class VpnProfileLink(Base):
    """The only place the VPN-cert world (file/EasyRSA/CLI-based, see
    cli_wrapper.py -- clients are never their own DB rows) and the portal-
    user world (this DB) are tied together. Strictly 1:1 (both columns
    unique) -- one portal user, one VPN profile, enforced at the DB level,
    not just in application code. Deliberately its own table rather than a
    column on User, since a VPN client can (transiently, before an admin
    links or a migration runs) exist with no linked portal user at all."""
    __tablename__ = "vpn_profile_links"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    vpn_client_name = Column(String(64), unique=True, nullable=False, index=True)  # == cli_wrapper client name

    # "created_with_profile" (either routes/users.py's create_user -- the
    # standard path since the User<->VPN Profile lifecycle unification, a
    # cert created as a side effect of creating the portal user -- or
    # routes/clients.py's add_client, which still exists server-side for
    # API completeness even though its own UI form was removed) |
    # "migration_exact_match" (migrate_vpn_profiles.py, via
    # migration_engine.py) | "manual_admin_link" (an admin explicitly
    # attaches an existing, unassigned profile via Edit User, or links an
    # unmatched pair the old way).
    link_source = Column(String(32), nullable=False)

    # Permanent guarantee, not a one-time migration skip: every cert that
    # was already live in production before this feature shipped gets this
    # set True at migration time and it is NEVER flipped back by any code
    # path afterward. Every lifecycle-sync hook that would call
    # cli.revoke_client/purge_revoked checks this first -- a real,
    # currently-connected user's VPN access must never go down because of a
    # portal-side action, full stop, no matter what later happens to the
    # linked portal account. Only link_source="created_with_profile" (cert
    # and account born together, going forward) gets the full bidirectional
    # sync. See docs/rbac_identity_design.md §4.
    protected_from_auto_revoke = Column(Boolean, nullable=False, default=False)

    linked_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    linked_by = Column(String(64), nullable=True)  # username snapshot; NULL for system-performed migration link

    # uselist=False must be on the backref, not this forward relationship
    # (this side -- VpnProfileLink.user -- is already many-to-one/scalar by
    # default; it's User.vpn_profile_link, the reverse side, that needs to
    # be told not to be a collection).
    user = relationship("User", backref=backref("vpn_profile_link", uselist=False))


class MigrationReport(Base):
    """A persisted snapshot of what migrate_vpn_profiles.py's `run` command
    actually did -- so `last-report` can re-fetch it later rather than only
    ever being available in that one terminal session. `report_json` holds
    the exact shape documented in docs/rbac_identity_design.md §5
    (linked_existing / created_new_accounts / unmatched_portal_users /
    conflicts) -- MINUS any temp_password field, which is deliberately
    stripped before this is ever written (see migration_engine.py's
    apply_migration) so a plaintext temp password never sits at rest in
    the DB, even redacted-on-read; it's stripped on write instead."""
    __tablename__ = "migration_reports"

    id = Column(Integer, primary_key=True)
    run_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    run_by = Column(String(64), nullable=False)  # username snapshot, same pattern as AuditLog
    is_preview = Column(Boolean, nullable=False, default=False)  # True = preview run, never wrote anything
    report_json = Column(Text, nullable=False)
