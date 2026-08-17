import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, BigInteger, String, Boolean, Date, DateTime, Enum, Text, Float, ForeignKey, Table, UniqueConstraint, event
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
    # Forces a password change on next login, enforced by every page route
    # in routes/pages.py (redirects to /change-password until cleared) --
    # set True for: accounts this app auto-creates with a system-generated
    # temp password (VPN profile auto-linking, migration-created accounts;
    # see VpnProfileLink and routes/clients.py), EVERY newly admin-created
    # account (routes/users.py's create_user -- changed from this column's
    # original narrower scope: an admin choosing the initial password is
    # still "provisioned for you", not proof the account holder has ever
    # seen/confirmed it), and an admin's manual password reset
    # (update_user's password-reset branch -- a reset password is exactly
    # as "not yet confirmed by the account holder" as a freshly-created
    # one). Cleared only by a successful SELF-service change
    # (update_my_profile), which is the one action that proves the account
    # holder actually knows the current password.
    must_reset_password = Column(Boolean, nullable=False, default=False)

    # Self-service "Forgot password" (routes/auth.py's forgot_password/
    # reset_password) -- a hash of the emailed token, never the plaintext
    # (same defense-in-depth reasoning as password_hash itself: a DB leak
    # alone shouldn't hand out working reset links). Single active token
    # per account -- requesting a new one overwrites these, invalidating
    # whatever was emailed before. expires_at enforces the time limit;
    # both columns are cleared back to NULL the moment the token is
    # consumed (or replaced), which is what makes it single-use -- there's
    # no separate "used" flag because a spent/superseded token simply no
    # longer matches anything in this column.
    password_reset_token_hash = Column(String(64), nullable=True)
    password_reset_expires_at = Column(DateTime(timezone=True), nullable=True)

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

    # --- Account lockout (see AppSettings.account_lockout_threshold/
    # account_lockout_minutes, auth.py's login_submit) -----------------------
    # failed_login_attempts resets to 0 on any successful login; once it
    # reaches the configured threshold, locked_until is set to
    # now + account_lockout_minutes and login is refused (with a clear
    # "try again after ..." message) until that time passes, at which point
    # the next attempt is allowed again (and either succeeds, resetting the
    # counter, or fails and starts a fresh lockout window). No admin
    # unlock button is needed for the common case since it's just a timer,
    # but an admin can already zero this out manually via the DB if ever
    # needed -- no UI for that yet, deliberately out of scope here.
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)

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

    # The portal's own public URL, e.g. "https://vpn.example.com" -- used
    # by the welcome email (mailer.send_welcome_email) so a new user knows
    # where to log in. NULL falls back to "https://{APP_DOMAIN}" (see
    # config.py's APP_DOMAIN, already required for Traefik routing) --
    # only needs setting explicitly here if the public URL differs from
    # that routing domain.
    portal_url = Column(String(512), nullable=True)

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
    # Account lockout after repeated failed login attempts -- NULL/0 on the
    # threshold disables lockout entirely (the pre-existing behavior). See
    # User.failed_login_attempts/locked_until below for the per-account
    # counters this drives, and auth.py's login_submit for enforcement.
    account_lockout_threshold = Column(Integer, nullable=True)
    account_lockout_minutes = Column(Integer, nullable=True)

    # Audit log retention -- NULL/0 means "keep forever" (no pruning).
    audit_retention_days = Column(Integer, nullable=True)
    # Whether a plain wrong-password login attempt (as opposed to the
    # country/city/ASN/IP restriction blocks, which are always logged) gets
    # its own AuditLog row -- see auth.py's login_submit. Defaults to True;
    # an admin who finds the resulting volume unhelpful can turn it off.
    log_failed_login_attempts = Column(Boolean, nullable=True)

    # User Management: which RoleDef slug the Add User form pre-selects --
    # purely a UX default (an admin can always pick a different role before
    # submitting), not a server-side fallback, since the form always submits
    # an explicit role. NULL falls back to "user" (the self-service role).
    default_new_user_role = Column(String(64), nullable=True)

    # VPN Management: the Monthly Bandwidth Quota (GB) applied to a new
    # user's VPN profile when the Add User form's own quota field is left
    # blank -- NULL means "no org-wide default", i.e. unlimited, same as
    # leaving the per-user field blank always has meant. See create_user()
    # in routes/users.py.
    default_bandwidth_monthly_gb = Column(Float, nullable=True)

    # VPN Management: global default for what happens when a client's
    # bandwidth_monthly_gb quota is exhausted -- "soft" (the connect-time-
    # only behavior this app has always had: an already-connected session
    # keeps running, only the next connection attempt is refused) or
    # "hard" (host-scripts/quota_enforcer.py actively kills an in-progress
    # session the moment it crosses quota). NULL/unset falls back to
    # "soft" (see app_settings.py's refresh_runtime_cache) -- a fresh
    # install's behavior never silently changes. Per-client override lives
    # on client_policy.json's own quota_enforcement_policy field (see
    # policy_store.set_policy), same "global default, profile-level
    # override" shape as default_bandwidth_monthly_gb above.
    default_quota_enforcement_policy = Column(String(8), nullable=True)

    # Notifications: admin-facing (not per-user) event emails, sent via the
    # same SMTP config as .ovpn delivery -- see mailer.py's
    # send_admin_notification. All three are opt-in (default off) so a
    # fresh install with SMTP configured for .ovpn delivery doesn't
    # suddenly start emailing anyone without an explicit admin choice.
    admin_notification_email = Column(String(254), nullable=True)
    notify_admin_on_user_created = Column(Boolean, nullable=True)
    notify_admin_on_client_revoked = Column(Boolean, nullable=True)
    # Quota threshold notifications (QuotaNotification below) -- NULL falls
    # back to 80/95 (see app_settings.py's refresh_runtime_cache). Admin
    # email is critical-only, opt-in (default off), same "admin notified
    # only for the more serious case" stance every other quota control in
    # this app already takes -- the in-app notification (both levels) is
    # always on for the affected user, no opt-out, since it's their own
    # quota being reported to them, not a broadcast.
    quota_notify_warning_pct = Column(Integer, nullable=True)
    quota_notify_critical_pct = Column(Integer, nullable=True)
    notify_admin_on_quota_critical = Column(Boolean, nullable=True)

    # Reporting: default selected range (days) for the Dashboard's Usage
    # Analytics chart -- 0 means "All time". Purely a UI default, same
    # spirit as default_new_user_role above; an admin can still change the
    # dropdown per-visit.
    reports_default_range_days = Column(Integer, nullable=True)
    # Database Reporting: how long to keep DbStatSnapshot rows -- NULL/0
    # means "keep forever" (no pruning), same convention as
    # audit_retention_days above. See app_settings.py's
    # prune_db_stat_snapshots() and main.py's lifespan() for where this is
    # enforced. Does NOT control how often a snapshot is taken (that's a
    # fixed code constant, main.py's DB_SNAPSHOT_INTERVAL_SECONDS) -- only
    # how much history is retained.
    db_snapshot_retention_days = Column(Integer, nullable=True)

    # System Administration: when true, login is blocked for every role
    # except admin/super_admin, with `maintenance_message` (falls back to a
    # generic message if blank) shown in place of the normal error -- see
    # auth.py's login_submit. Does not touch already-established sessions.
    maintenance_mode = Column(Boolean, nullable=True)
    maintenance_message = Column(String(512), nullable=True)

    # Toast/notification popup display duration, in milliseconds -- NULL
    # falls back to app_settings.py's 1000ms (1 second) default. Read
    # client-side by static/app.js's toast() via window.NOTIFICATION_DURATION_MS
    # (see base.html), not fetched per-toast -- see refresh_runtime_cache's
    # docstring for why templates/JS read the cached `runtime` value instead
    # of hitting the DB/API on every render.
    notification_duration_ms = Column(Integer, nullable=True)

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


class DbStatSnapshot(Base):
    """One row per periodic sample of whole-database Postgres statistics --
    written by health.py's write_db_stat_snapshot(), on a fixed interval
    (main.py's DB_SNAPSHOT_INTERVAL_SECONDS), for Database Reporting's
    trend charts (routes/reports.py's GET /api/reports/database). Exists
    because health.py's get_database_health() is a live, point-in-time
    reading with no history -- "table growth"/"connection trends"/"peak
    connections" can't be answered from a single live query.

    Deliberately whole-database aggregates only -- no per-table rows here
    (per-table size breakdown stays live/point-in-time, computed fresh on
    every GET /api/reports/database call, not tracked historically; storing
    N tables x every snapshot would multiply row count for a "current
    state" fact that doesn't need a time series).

    xact_commit/xact_rollback/blks_hit/blks_read are stored as the RAW
    CUMULATIVE counters pg_stat_database reports (since server start/stats
    reset) -- not deltas. Rates (commits/min, cache hit ratio) are computed
    by diffing consecutive rows when a report is read, not pre-computed
    here, so the raw numbers stay available if that differencing logic
    ever needs to change.

    NULL on every numeric column (not just at write time, but structurally
    nullable) mirrors get_database_health()'s own "N/A on SQLite dev, not
    an error" stance -- a snapshot taken against a non-Postgres engine
    still gets a row (so the time series has no silent gaps), just with
    every stat left NULL."""
    __tablename__ = "db_stat_snapshots"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    db_size_bytes = Column(BigInteger, nullable=True)
    active_connections = Column(Integer, nullable=True)
    idle_connections = Column(Integer, nullable=True)
    xact_commit = Column(BigInteger, nullable=True)
    xact_rollback = Column(BigInteger, nullable=True)
    blks_hit = Column(BigInteger, nullable=True)
    blks_read = Column(BigInteger, nullable=True)
    waiting_locks_count = Column(Integer, nullable=True)
    long_running_query_count = Column(Integer, nullable=True)


class QuotaNotification(Base):
    """One row per (user, month, threshold-level) bandwidth-quota crossing
    -- written by main.py's _quota_notification_loop, backing the in-app
    notification bell (routes/notifications.py) and, for "critical" only,
    an optional admin email (mailer.send_admin_notification, gated by
    AppSettings.notify_admin_on_quota_critical).

    The unique constraint is what makes "notify once per user per month
    per level" enforceable -- the loop still does a query-first existence
    check before inserting (clearer intent, same effect), this is the
    backstop against a duplicate slipping through. `period_start` is the
    first-of-month this row concerns, same "YYYY-MM-01" convention
    policy_lib.py's client_usage.json already uses -- lets a user cross
    80% again next month and get a fresh notification, not silence
    forever after the first one."""
    __tablename__ = "quota_notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    vpn_client_name = Column(String(64), nullable=False)
    level = Column(String(16), nullable=False)  # "warning" | "critical"
    pct_used = Column(Float, nullable=False)  # the pct_used value AT THE TIME this was raised, not live
    message = Column(String(512), nullable=False)  # pre-built human-readable text, see the loop -- UI renders verbatim
    period_start = Column(Date, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    read_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User")

    __table_args__ = (UniqueConstraint("user_id", "period_start", "level", name="uq_quota_notif_period_level"),)


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
