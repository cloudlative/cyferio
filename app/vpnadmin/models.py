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

    # Password reuse prevention (Settings -> Security's "Remember last N
    # passwords") -- a JSON list of previous password_hash values, most
    # recent first, capped at whatever app_settings.runtime.
    # password_history_count currently is (see routes/users.py's
    # _check_password_reuse/_record_password_history). NULL/"[]" = no
    # history yet, same as a brand-new account or the feature having just
    # been enabled. Deliberately stores the SAME bcrypt hashes password_hash
    # itself already holds (not plaintext) -- same reasoning as
    # password_hash: a DB leak alone must never hand out working passwords,
    # past or present.
    password_history = Column(Text, nullable=True)

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

    # --- Multi-Factor Authentication (TOTP) -- see mfa.py -------------------
    # mfa_enabled=True means this account has completed enrollment and MUST
    # be challenged for a second factor at login whenever the effective
    # policy calls for it (mfa.effective_policy) -- it does NOT by itself
    # mean "always challenged" (see the kill-switch/exempt cases there).
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    # Fernet-encrypted TOTP secret (see config.MFA_ENCRYPTION_KEY, mfa.py's
    # encrypt_secret/decrypt_secret) -- the raw secret is never stored, never
    # logged, and never returned by any API response after the enrollment
    # step that first generates it.
    mfa_secret_encrypted = Column(Text, nullable=True)
    mfa_enrolled_at = Column(DateTime(timezone=True), nullable=True)
    mfa_last_used_at = Column(DateTime(timezone=True), nullable=True)
    # Per-user override of the global/role MFA policy -- "required",
    # "optional", "exempt", or NULL (inherit role/global, the default). See
    # mfa.effective_policy for the full precedence order.
    mfa_policy_override = Column(String(16), nullable=True)
    # Admin-forced re-enrollment: set True by routes/users.py's
    # /mfa/reset and /mfa/force-enroll actions, or automatically whenever
    # an admin resets a user's MFA. Checked at login (routes/auth.py) --
    # a True value redirects to mandatory /mfa/setup before a session is
    # ever established, regardless of mfa_enabled's current value.
    mfa_setup_required = Column(Boolean, nullable=False, default=False)
    # OTP brute-force lockout -- deliberately a SEPARATE counter from
    # failed_login_attempts/locked_until above: a password brute-force and
    # an OTP brute-force against an already-known-correct password are
    # different attack surfaces, and conflating them would let a wrong-OTP
    # streak lock someone out of the password step too (or vice versa).
    # Reuses the SAME account_lockout_threshold/account_lockout_minutes
    # settings for the actual math (see routes/mfa.py) -- one lockout
    # policy concept, not two near-duplicate Settings fields.
    mfa_failed_attempts = Column(Integer, nullable=False, default=0)
    mfa_locked_until = Column(DateTime(timezone=True), nullable=True)

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

    # Outbound email (see config.py's SMTP_* / mailer.py) -- DEPRECATED as
    # of the multi-provider EmailProvider table below: mailer.py no longer
    # reads these directly, only db.migrate_legacy_smtp_provider() does,
    # once, to seed an initial "Primary SMTP" EmailProvider row from
    # whatever's already here (or the env-var fallback) on first startup
    # after upgrading. Kept (not dropped) both because this app's
    # migration approach only ever ADDs (see db.py's _sync_missing_columns
    # docstring) and so an admin's already-configured SMTP settings aren't
    # silently lost if that one-time migration is ever re-examined.
    smtp_host = Column(String(255), nullable=True)
    smtp_port = Column(Integer, nullable=True)
    smtp_username = Column(String(255), nullable=True)
    smtp_password = Column(String(255), nullable=True)
    smtp_from = Column(String(255), nullable=True)
    smtp_use_tls = Column(Boolean, nullable=True)

    # Internal migration bookkeeping, not an admin-editable setting (not
    # read by EffectiveSettings, never shown on the Settings page) -- same
    # "store it here anyway, it's the one singleton row every deployment
    # already has" pragmatism as the deprecated smtp_* columns above.
    # NULL = app_settings.migrate_decouple_portal_and_vpn_restrictions()
    # hasn't run yet for this deployment; a timestamp = it ran (once) at
    # that moment. See that function's docstring for why this needs a
    # real one-time marker rather than being safely re-run on every
    # startup like most of this app's other self-healing migrations.
    restrictions_decoupled_at = Column(DateTime(timezone=True), nullable=True)

    # Security
    min_password_length = Column(Integer, nullable=True)
    session_timeout_minutes = Column(Integer, nullable=True)
    # Account lockout after repeated failed login attempts -- NULL/0 on the
    # threshold disables lockout entirely (the pre-existing behavior). See
    # User.failed_login_attempts/locked_until below for the per-account
    # counters this drives, and auth.py's login_submit for enforcement.
    account_lockout_threshold = Column(Integer, nullable=True)
    account_lockout_minutes = Column(Integer, nullable=True)
    # Password reuse prevention: how many of a user's previous passwords
    # (User.password_history) a new password is checked against on every
    # password-setting path -- self-service change, admin reset, and
    # forgot-password reset alike (see routes/users.py's
    # _check_password_reuse). 0 disables the feature entirely (the
    # pre-existing behavior); NULL falls back to 3.
    password_history_count = Column(Integer, nullable=True)

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

    # Optional integrations (see features.py) -- MaxMind GeoIP. The app
    # previously had NO knowledge of the license key at all; it only lived
    # in the host's /etc/openvpn/vpn-tools.conf, read by the host-side
    # geoip-update.sh. Storing it here lets the Settings page manage it
    # (add/update/disable/re-enable, see routes/settings.py's geoip
    # endpoints) without SSHing in -- saving a key here still only takes
    # effect on the host once routes/settings.py triggers the
    # "geoip-update" host_executor action, which writes it into
    # vpn-tools.conf and re-runs geoip-update.sh; this column is the
    # source of truth the app shows back to the admin, not a live mirror
    # of whatever's on the host filesystem (see geoip_enabled's own note
    # on why enabling still checks file presence, not just this key).
    # Plaintext, same precedent as smtp_password above -- no new
    # encryption introduced for this column.
    maxmind_license_key = Column(String(64), nullable=True)
    # NULL/false = disabled even if a key IS stored -- lets an admin turn
    # GeoIP off without losing/re-entering the key (see the "disable
    # without reinstalling" / "re-enable later" requirements). True alone
    # isn't sufficient for the feature to actually be usable -- see
    # features.geoip_enabled(), which also checks the .mmdb file exists.
    geoip_enabled = Column(Boolean, nullable=True)

    # Optional integrations -- CAPTCHA. Mirrors config.py's env-var-only
    # CAPTCHA_PROVIDER/TURNSTILE_*/RECAPTCHA_* as DB overrides, same
    # nullable-column-falls-back-to-env-var layering as every setting
    # above (see captcha.py's _active_keys(), updated to check these
    # first). NULL provider = CAPTCHA disabled (falls back to whatever
    # CAPTCHA_PROVIDER the environment has, including blank).
    captcha_provider = Column(String(16), nullable=True)
    turnstile_site_key = Column(String(255), nullable=True)
    turnstile_secret_key = Column(String(255), nullable=True)  # plaintext, same precedent as smtp_password
    recaptcha_site_key = Column(String(255), nullable=True)
    recaptcha_secret_key = Column(String(255), nullable=True)  # plaintext, same precedent as smtp_password

    # My Connection Issues: how long to keep ConnectionRejectionLog rows --
    # NULL/0 means "keep forever" (no pruning), same convention as
    # audit_retention_days above. See app_settings.py's
    # prune_connection_rejections() and main.py's lifespan().
    connection_issue_retention_days = Column(Integer, nullable=True)

    # MAC Address Duplication Policy -- NULL/false (default) preserves the
    # original, always-on behavior: openvpn-install.sh's find_mac_owner()
    # rejects registering a MAC already assigned to a different client.
    # True relaxes that ONE check (do_add_client/do_add_mac's cross-client
    # conflict check) to allow the same MAC on multiple clients -- e.g.
    # shared/virtualized devices. Threaded through to the script per-call
    # as the ALLOW_DUPLICATE_MACS env var (see cli_wrapper.py's
    # _run_install_script()), never a persistent change to the script
    # itself. Deliberately does NOT affect connect-time enforcement --
    # host-scripts/openvpn-mac-addr-check.py's db_lookup() only ever
    # checks a MAC against the connecting client's OWN registrations, not
    # other clients', so this setting can't weaken who's allowed to
    # actually connect, only whether registering a shared MAC is accepted.
    allow_duplicate_macs = Column(Boolean, nullable=True)

    # Connection History / Reporting accuracy -- a session_history.jsonl
    # entry (host-scripts/openvpn-client-disconnect.py) whose duration is
    # BELOW this many seconds is treated as a dropped/instant connection
    # rather than a real, meaningful VPN session: the client-connect script
    # already accepted it (it passed the MAC/OS/geo/quota gates -- this is
    # NOT a ConnectionRejectionLog policy rejection), but it disconnected
    # too fast to represent actual usage -- e.g. a flaky network, a client
    # immediately retrying on a stale config, or a duplicate-CN kick.
    # Excluded from Connection History and every session-based report/chart
    # (session counts, average duration, connection trends, peak usage,
    # most-active-clients) -- see cli_wrapper.status_session_history's
    # filtering and status_dropped_sessions() for the complement, surfaced
    # on Diagnostics instead. NULL falls back to 3 (app_settings.py's
    # refresh_runtime_cache); an admin can set 0 to disable the split
    # entirely (every session counts, the original behavior).
    min_session_duration_seconds = Column(Integer, nullable=True)

    # Support Ticketing System -- admin-tweakable preferences (Settings ->
    # Support), NOT hardcoded constants (unlike the old routes/support.py's
    # fixed MAX_SUBJECT_LENGTH/SUPPORT_REQUEST_RATE_LIMIT it replaces): see
    # routes/tickets.py's/routes/me_tickets.py's rate-limit check and
    # attachment upload validation. NULL falls back to the defaults noted
    # below (app_settings.py's refresh_runtime_cache), same convention as
    # every other tunable in this table.
    support_ticket_rate_limit_count = Column(Integer, nullable=True)  # default 5
    support_ticket_rate_limit_window_minutes = Column(Integer, nullable=True)  # default 60
    support_max_attachment_size_mb = Column(Integer, nullable=True)  # default 10
    support_max_attachments_per_message = Column(Integer, nullable=True)  # default 5
    # Same notify_admin_on_* pattern as notify_admin_on_user_created/
    # notify_admin_on_client_revoked -- gated by admin_notification_email
    # being set (see routes/settings.py's notify_fields check).
    notify_admin_on_ticket_created = Column(Boolean, nullable=True)
    # Duplicate Cleanup Tools -- the "created within a configurable time
    # window of each other" heuristic used by GET /api/tickets/
    # duplicate-clusters (routes/tickets.py) to group candidate duplicates
    # by (subject) or (user + category) proximity in time. Admin-tweakable
    # per the Settings tunables preference -- NOT a hardcoded constant.
    # NULL falls back to 1440 (24h, app_settings.py's refresh_runtime_cache).
    ticket_duplicate_window_minutes = Column(Integer, nullable=True)

    # Multi-Factor Authentication (TOTP) -- see mfa.py's effective_policy
    # for how these three combine with User.mfa_policy_override.
    # "disabled" | "optional" | "required" -- NULL falls back to "optional"
    # (app_settings.py's refresh_runtime_cache). "disabled" is a kill
    # switch: nobody is challenged regardless of individual enrollment or
    # role/user overrides, for emergency recovery.
    mfa_mode = Column(String(16), nullable=True)
    # JSON {role_slug: "required"|"optional"|"exempt"} -- a role not
    # mentioned here inherits mfa_mode. See routes/settings.py's validator
    # for the allowed value set.
    mfa_role_requirements = Column(Text, nullable=True)
    # "Remember this device" -- 0/NULL = disabled (never skip the
    # challenge for a trusted device). See models.MfaTrustedDevice.
    mfa_remember_device_days = Column(Integer, nullable=True)
    # Same notify_admin_on_* pattern as notify_admin_on_ticket_created above
    # -- gated by admin_notification_email being set (routes/settings.py's
    # notify_fields check). Fires when MFA is disabled (any path -- self-
    # service or admin action) for a privileged account (mfa.is_privileged).
    notify_admin_on_mfa_disabled = Column(Boolean, nullable=True)

    # Release Availability Indicator/Popup -- see release_check.py. NULL
    # falls back to release_check.py's own defaults (app_settings.py's
    # refresh_runtime_cache). release_check_critical_major_bump toggles
    # WHICH of the two classification signals release_check.classify()
    # applies (a semver major-version bump is always treated as critical
    # regardless of this flag; this only controls whether that heuristic
    # is EXTENDED with the major-bump check versus relying solely on the
    # release body/name mentioning "security"/"critical") -- see that
    # module's own docstring for the documented classification rule.
    release_check_enabled = Column(Boolean, nullable=True)
    release_check_interval_minutes = Column(Integer, nullable=True)
    release_check_critical_major_bump = Column(Boolean, nullable=True)
    github_repo = Column(String(128), nullable=True)  # "owner/repo", NULL falls back to config.RELEASE_CHECK_REPO
    # Internal bookkeeping, not admin-editable (not in _serialize()) --
    # which release tag the background loop already auto-filed an upgrade
    # ticket for, so it never files a duplicate on every subsequent check
    # tick until an admin (or a completed upgrade) moves past it. Same
    # "persisted marker, not a re-derivable fact" reasoning as
    # restrictions_decoupled_at above.
    last_release_notified_tag = Column(String(64), nullable=True)

    # VPN Device Availability Monitoring & Offline Alert Notifications --
    # global DEFAULTS only (Settings -> Device Monitoring). Per-device
    # values (threshold, cooldown mode, etc. -- VpnProfileLink's
    # monitoring_* columns) always win once a device's own monitoring is
    # configured; these only seed a new device's config and drive the
    # background check's own tick cadence. See app_settings.py's
    # refresh_runtime_cache for the NULL-falls-back-to-these-defaults values.
    device_monitoring_check_interval_minutes = Column(Integer, nullable=True)  # how often the offline-check tick runs
    device_monitoring_default_offline_threshold_minutes = Column(Integer, nullable=True)  # pre-filled on a newly-enabled device
    device_monitoring_default_cooldown_minutes = Column(Integer, nullable=True)  # pre-filled "repeat" cooldown value
    device_monitoring_default_recovery_notify = Column(Boolean, nullable=True)  # pre-filled "notify on recovery" toggle

    # System Audit -- see system_audit/__init__.py and main.py's
    # _system_audit_loop.
    audit_schedule_enabled = Column(Boolean, nullable=True)
    audit_schedule_interval_hours = Column(Integer, nullable=True)  # 24=daily, 168=weekly, 720=monthly
    notify_admin_on_audit_finding = Column(Boolean, nullable=True)

    updated_at = Column(DateTime(timezone=True), nullable=True)
    updated_by = Column(String(64), nullable=True)  # username snapshot, not a FK -- see AuditLog for the same pattern


class EmailProvider(Base):
    """One configured outbound-email delivery profile (Settings ->
    Outbound Email) -- an admin can define several (e.g. a primary SMTP
    relay and a Resend account), but exactly one is ever both `is_active`
    and `is_default` at a time, and that's the ONE mailer.py ever actually
    sends through (see mailer._resolve_default_provider). Every other row
    just sits configured-but-unused until an admin switches the default,
    or is used one-off via its own "Test" button in the UI (routes/
    email_providers.py's test endpoint), which bypasses is_default/
    is_active entirely -- testing a profile doesn't require it to be live.

    `config` is a JSON blob (not one column per field) specifically so
    each provider TYPE can have its own field set without a schema
    migration every time a new provider is added -- see email_providers.py's
    module docstring for the full provider-abstraction design. Never
    contains anything this app wouldn't already store in plaintext
    elsewhere (AppSettings.smtp_password was always plaintext too); no new
    encryption introduced here, consistent with that existing baseline."""
    __tablename__ = "email_providers"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)  # admin-chosen label, e.g. "Primary SMTP", "Resend Production"
    # Matches an email_providers.PROVIDERS registry key ("smtp", "resend",
    # ...) -- plain string, not a DB-native Enum, so adding a new provider
    # type never needs _sync_enum_values()'s ALTER TYPE dance (see db.py).
    provider_type = Column(String(32), nullable=False)
    # Active = usable at all (shows up as a candidate default, can be
    # tested); a disabled profile is kept configured but can't be made
    # the default and is skipped if it somehow still were (defense in
    # depth -- routes/email_providers.py's set_default already refuses to
    # activate a disabled profile as default in the first place).
    is_active = Column(Boolean, nullable=False, default=True)
    # Exactly one row may ever have this true -- enforced at the
    # application level (routes/email_providers.py's set_default clears
    # every other row's flag in the same transaction), not a DB
    # constraint, since SQLite has no native partial-unique-index support
    # portable to Postgres without dialect-specific DDL.
    is_default = Column(Boolean, nullable=False, default=False)
    config = Column(Text, nullable=False, default="{}")  # JSON-encoded, provider-specific -- see email_providers.py
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)


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


class ConnectionRejectionLog(Base):
    """One row per rejected OpenVPN tunnel connect attempt -- fed by
    host-scripts/openvpn-mac-addr-check.py's reject(), which best-effort
    POSTs here (via routes/host_ingest.py's /internal/connection-rejections,
    bearer-token authenticated) in addition to its pre-existing flat-file
    write to /etc/openvpn/server/openvpn.log (vpn-status.py --rejected-
    connections keeps parsing that file unchanged -- this table is a new,
    separate, DB-backed history, not a replacement).

    Deliberately NOT a per-User FK: `vpn_client_name` (the OpenVPN
    common_name) is the join key back to VpnProfileLink, matched at read
    time by routes/me_connection_issues.py -- a rejection can happen for a
    common_name with no (or a since-unlinked) portal user, and the host
    script only ever knows the cert's common_name, never a portal user id.

    `reason` is one of the exact strings openvpn-mac-addr-check.py already
    emits: mac_mismatch, os_not_allowed, country_not_allowed,
    country_lookup_failed, city_not_allowed, city_lookup_failed,
    asn_not_allowed, asn_lookup_failed, ip_not_allowed, bandwidth_exceeded.
    The detected_* columns are all nullable since not every reason
    populates every field (e.g. os_not_allowed never sets detected_country).

    Pruned by app_settings.py's prune_connection_rejections(), governed by
    AppSettings.connection_issue_retention_days, same "0/NULL = keep
    forever" shape as audit_retention_days/db_snapshot_retention_days."""
    __tablename__ = "connection_rejection_log"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    vpn_client_name = Column(String(64), nullable=False, index=True)
    reason = Column(String(32), nullable=False)
    message = Column(Text, nullable=True)
    source_ip = Column(String(64), nullable=True)
    detected_mac = Column(String(32), nullable=True)
    detected_country = Column(String(8), nullable=True)
    detected_city = Column(String(128), nullable=True)
    detected_asn = Column(String(16), nullable=True)
    detected_asn_name = Column(String(255), nullable=True)
    # What openvpn_db.txt actually had on file for this common_name at the
    # MOMENT of rejection (mac_mismatch rows only, NULL for every other
    # reason) -- frozen at ingestion time by host-scripts/
    # openvpn-mac-addr-check.py's db_lookup_registered(), specifically so
    # this never needs (and never gets) a live re-lookup against the
    # CURRENT file the way vpn-status.py's flat-file-backed
    # cmd_rejected() historically did (see that function's own comment on
    # why a live recompute against historical rows is misleading -- an
    # admin registering the MAC later must never make an old rejection
    # look retroactively "resolved"). NULL also covers rows ingested
    # before this column existed. Comma-joined if the name had multiple
    # MACs on file (openvpn_db.txt allows one-to-many for multi-device
    # users) -- String(255), not String(32) like detected_mac, to leave
    # room for that.
    registered_mac_at_time = Column(String(255), nullable=True)

    # The client's raw IV_PLAT value (env_iv_plat) at the moment of THIS
    # rejection -- captured for every reason, not just os_not_allowed, so
    # Diagnostics can show/filter by OS the same way it already does for
    # the flat-file-derived rejected view (which reads this straight off
    # the per-attempt env dump instead). Nullable: rows ingested before
    # this column existed (and, in principle, an attempt where OpenVPN
    # never reported IV_PLAT at all) simply have no value here.
    detected_os = Column(String(64), nullable=True)

    # Set by routes/me_connection_issues.py's request_access_review() the
    # moment it files a SupportTicket from this row -- lets GET "" (list_my_
    # connection_issues) tell the frontend "a ticket already exists for
    # this rejection" so a page refresh renders "View Ticket #N" instead of
    # reverting to "Request Access Review" and inviting a second, duplicate
    # ticket for the exact same rejection. Nullable: most rows never get a
    # review requested against them at all. No relationship() needed here
    # (nothing walks from a ticket back to the rejection it came from) --
    # just the id, same as every other "id" surfaced to the frontend.
    review_ticket_id = Column(Integer, ForeignKey("support_tickets.id"), nullable=True)


class ClientMac(Base):
    """A queryable DB mirror of openvpn_db.txt's `name=mac` bindings --
    NOT the connect-time enforcement source, which stays the flat file
    (read by host-scripts/openvpn-mac-addr-check.py's db_lookup(), an
    unprivileged host-side script with zero DB credentials on the
    security-critical connect path; moving that lookup to a live DB call
    would make VPN connectivity itself depend on the app/DB being
    reachable -- a real regression for no benefit). This table exists
    purely so the app can query/report/join on MAC bindings without
    shelling out, mirroring what routes/clients.py's add_client_mac/
    remove_client_mac and routes/me_vpn.py's add_my_mac/remove_my_mac
    already do to the file via cli_wrapper -- see
    client_mac_mirror.py's record_mac_added/record_mac_removed, called
    right after each of those succeeds.

    Kept in sync with the file (which can still drift out from under the
    app -- hand edits, SSH, setup.sh provisioning) by a full resync
    against openvpn-install.sh's --dump-macs at every startup (see
    main.py's lifespan() and cli_wrapper.dump_macs()) -- the same
    "startup-time reconciliation, no separate scheduler" precedent as
    db._sync_missing_columns()/the prune_* functions."""
    __tablename__ = "client_macs"

    id = Column(Integer, primary_key=True)
    vpn_client_name = Column(String(64), nullable=False, index=True)
    mac = Column(String(32), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("vpn_client_name", "mac", name="uq_client_mac"),)


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

    # --- VPN Device Availability Monitoring & Offline Alert Notifications --
    # Per-profile monitoring CONFIG lives here (columns on the existing
    # 1:1 user<->VPN-profile link), not a new parallel entity -- see
    # device_monitoring.py's module docstring for the full reasoning.
    # Everything below defaults to "monitoring off" so an upgrade never
    # starts alerting on a client nobody has opted in.
    monitoring_enabled = Column(Boolean, nullable=False, default=False)
    monitoring_name = Column(String(128), nullable=True)  # optional friendly label, e.g. "Head Office Gateway"

    # A pluggable "check type" hook for future monitoring kinds (heartbeat,
    # latency, packet loss, tunnel health, bandwidth, external endpoint --
    # see the feature spec's "design for extensibility" section) without a
    # rearchitect: device_monitoring.CHECK_TYPES is the registry, only
    # "connectivity" (online/offline via the existing status snapshot) is
    # implemented today. Stored per-profile (not hardcoded) so a future
    # check type can be turned on for one device at a time going forward.
    check_type = Column(String(32), nullable=False, default="connectivity")

    # "Expected Connectivity" -- informational scheduling context an admin
    # sets to describe what "normal" looks like for this device.
    # "always"/"business_hours"/"custom" per the spec. Only "always" (24x7)
    # actually changes alerting behavior today (business_hours/custom are
    # captured and surfaced, but the offline-check tick doesn't yet apply a
    # schedule window to them -- see device_monitoring.py's docstring on
    # why that's a deliberately deferred V2, not a half-built V1 that
    # silently produces wrong schedule-aware alerts).
    expected_connectivity = Column(String(24), nullable=False, default="always")

    # Offline Detection Threshold, in minutes -- one of
    # device_monitoring.OFFLINE_THRESHOLD_CHOICES_MINUTES.
    offline_threshold_minutes = Column(Integer, nullable=False, default=15)

    # Notification Configuration -- independent Email/Slack toggles, plus
    # WHO gets the email (assigned user / selected admins / custom
    # addresses). Slack has no per-device recipient list of its own -- it
    # always fans out to every enabled, subscribed SlackWorkspace (see
    # slack_notifications.notify), same as every other event type in this
    # app; there's no per-device Slack routing today.
    notify_email_enabled = Column(Boolean, nullable=False, default=True)
    notify_slack_enabled = Column(Boolean, nullable=False, default=True)
    notify_assigned_user = Column(Boolean, nullable=False, default=True)
    # JSON list of User.id -- admins selected to also receive the email.
    notify_admin_user_ids = Column(Text, nullable=True)
    # JSON list of extra email addresses (no portal account required).
    notify_additional_emails = Column(Text, nullable=True)
    # Recovery ("device came back online") notification -- optional per spec.
    notify_on_recovery = Column(Boolean, nullable=False, default=True)

    # Alert Cooldown / Noise Reduction -- "once" (a single alert per
    # offline episode, silent until it recovers) or "repeat" (re-alert
    # every alert_cooldown_repeat_minutes while still offline). See
    # device_monitoring.py's run_offline_check for how this is applied.
    alert_cooldown_mode = Column(String(16), nullable=False, default="once")
    alert_cooldown_repeat_minutes = Column(Integer, nullable=True)  # only meaningful when mode == "repeat"

    # Maintenance Mode -- admin-toggled, temporarily suppresses OFFLINE
    # alerts for this device (a planned outage/upgrade) without disabling
    # monitoring itself: status/outage history keeps being tracked (so the
    # availability report stays accurate), only the notification fan-out is
    # skipped. `maintenance_mode_until`, if set, is an optional auto-expiry
    # the offline-check tick enforces (see run_offline_check) so a
    # maintenance window an admin forgets to close doesn't silently suppress
    # alerts forever.
    maintenance_mode = Column(Boolean, nullable=False, default=False)
    maintenance_mode_note = Column(String(255), nullable=True)
    maintenance_mode_until = Column(DateTime(timezone=True), nullable=True)


class VpnDeviceStatus(Base):
    """One row per monitored VPN profile (vpn_client_name) -- the CURRENT
    state device_monitoring.run_offline_check() maintains: is it online or
    offline right now (from the monitoring engine's point of view, which is
    threshold-aware -- distinct from the live "online"/"offline" the
    Clients page shows straight from vpn-status.py), since when, and when
    the last alert for the current episode went out (for cooldown).

    Deliberately its own table rather than columns on VpnProfileLink --
    this is mutable, high-churn STATE written by a background loop on every
    tick, while VpnProfileLink's monitoring_* columns above are admin-edited
    CONFIG written rarely, from a request handler. Keeping them apart means
    the frequent background writes never contend with (or get swept into)
    an admin's config-save transaction, and a future second check_type can
    reuse this same table (keyed by (vpn_client_name, check_type)) without
    VpnProfileLink growing a further set of check-type-specific columns.

    Row lifecycle: created the first time monitoring is turned on for a
    profile (or the first tick after), never deleted while monitoring stays
    on -- see device_monitoring.get_or_create_status(). Left in place (not
    deleted) if monitoring is later disabled, so re-enabling doesn't lose
    the last-known last_seen_at/history linkage; only current_status resets
    to "unknown" on disable (see disable path)."""
    __tablename__ = "vpn_device_statuses"

    id = Column(Integer, primary_key=True)
    vpn_client_name = Column(String(64), nullable=False, index=True)
    check_type = Column(String(32), nullable=False, default="connectivity")

    # "online" | "offline" | "unknown" (unknown = monitoring just turned on,
    # no tick has classified it yet). Deliberately NOT "warning" as a status
    # value -- the dashboard widget derives "warning" for its own display
    # (e.g. "offline but within threshold, not yet alerted") from
    # current_status + offline_since + the profile's own threshold, rather
    # than persisting a third state here that would just be a projection of
    # the same two columns.
    current_status = Column(String(16), nullable=False, default="unknown")

    last_seen_at = Column(DateTime(timezone=True), nullable=True)  # last tick this device was observed online
    offline_since = Column(DateTime(timezone=True), nullable=True)  # set when current_status flips to "offline"

    # Cooldown bookkeeping for the CURRENT offline episode -- cleared
    # (set back to None) every time the device comes back online, so a
    # fresh episode always starts from "no alert sent yet" regardless of
    # how the previous episode's cooldown played out.
    last_alert_sent_at = Column(DateTime(timezone=True), nullable=True)
    alert_count = Column(Integer, nullable=False, default=0)  # alerts sent so far THIS episode

    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("vpn_client_name", "check_type", name="uq_device_status_client_check"),)


class VpnDeviceOutage(Base):
    """One row per completed (or in-progress) offline episode for a
    monitored VPN profile -- the Device Availability report's (routes/
    device_monitoring.py) raw data: uptime %, downtime %, outage count, and
    average outage duration are all derived by aggregating these rows over
    a date range, rather than replaying VpnDeviceStatus's current-state-only
    columns (which have no history once an episode ends).

    `ended_at`/`duration_seconds` are NULL while the outage is still
    ongoing -- opened by run_offline_check() the moment a device is first
    observed offline (not only once the alert threshold is crossed, so a
    brief blip that never quite reaches the alert threshold still counts
    against availability), closed the moment it's observed online again."""
    __tablename__ = "vpn_device_outages"

    id = Column(Integer, primary_key=True)
    vpn_client_name = Column(String(64), nullable=False, index=True)
    check_type = Column(String(32), nullable=False, default="connectivity")
    started_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    # Whether this outage ever actually crossed the alert threshold (vs. a
    # blip shorter than offline_threshold_minutes that recovered on its
    # own) -- lets the "Most Unstable Devices" report distinguish real
    # alerted outages from sub-threshold noise if it ever needs to.
    alerted = Column(Boolean, nullable=False, default=False)


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


# --- Support Ticketing System -----------------------------------------------
# See routes/me_tickets.py (self-service) and routes/tickets.py (admin
# console) for the RBAC-gated read/write surface, permissions.py's
# "support_tickets" object for the RBAC registration, and support_tickets.py
# for the STATUSES/PRIORITIES/CATEGORIES constants these columns reference
# by plain string, not a DB-native Enum (see that module's docstring for
# why). No dedicated "ticket event" table for the activity timeline -- every
# status/priority/assignment change is logged via audit.log_action(target=
# f"TCK-{id}") like any other state-changing action, and the ticket detail
# view reads it back filtered by that same target, interleaved with
# SupportTicketMessage rows by timestamp.

class SupportTicket(Base):
    __tablename__ = "support_tickets"

    id = Column(Integer, primary_key=True)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    subject = Column(String(200), nullable=False)
    category = Column(String(64), nullable=False)  # leaf slug, see support_tickets.CATEGORIES
    priority = Column(String(16), nullable=False, default="medium")
    # Own scope (routes/me_tickets.py) always filters on created_by_user_id
    # -- same "structural ownership, no separate scope check" pattern as
    # VpnProfileLink/me_vpn.py. Any scope (routes/tickets.py) sees every row.
    status = Column(String(32), nullable=False, default="new", index=True)
    assigned_admin_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    # Optional -- set from the auto-attached diagnostic context (see
    # context_snapshot below) when the category is VPN-related and the
    # submitter has a linked profile, or left NULL otherwise.
    vpn_client_name = Column(String(64), nullable=True)
    # JSON blob captured ONCE at ticket-creation time (IP/session/last-
    # rejection info from me_vpn.py/me_connection_issues.py/client_ip.py) --
    # display-only, a frozen snapshot of "what did the submitter's own
    # environment look like when they filed this", never re-queried live.
    context_snapshot = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    # Soft delete -- same "hide from every normal list/detail query, keep
    # the row (and its audit trail) around, restorable" pattern as
    # User.deleted/deleted_at above (see that column's own docstring).
    # Deliberately no hard-delete path anywhere in the UI/API -- a ticket
    # can hold a support conversation an admin may need to reference again
    # later (compliance, a re-opened complaint, a duplicate-cleanup
    # decision made in error).
    deleted = Column(Boolean, nullable=False, default=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    deleted_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Lock/Unlock (Enhanced Ticket Management Controls) -- an admin-only
    # freeze distinct from "duplicate" below: a locked ticket is NOT
    # necessarily a duplicate of anything, it's just had further
    # self-service action paused on it (e.g. a ticket under dispute/
    # investigation). Blocks self-service replies/reopen the same way a
    # duplicate does (routes/me_tickets.py), but the admin console itself
    # is never blocked -- an admin needs to be able to act on (and unlock)
    # a locked ticket.
    locked = Column(Boolean, nullable=False, default=False)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    locked_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # --- Duplicate Ticket Management ----------------------------------------
    # A ticket becomes a duplicate by pointing at its "parent" -- a plain
    # nullable self-FK, deliberately NOT a new `STATUSES` value (see
    # support_tickets.py's STATUSES docstring for why that set is
    # load-bearing for lifecycle checks): "is this ticket a duplicate" is
    # orthogonal to its actual status (a duplicate can still be new/open/
    # resolved/etc independently), so folding it into status would force
    # every status-based check in this app to also special-case duplicate-
    # ness. The parent's subject/etc is intentionally NOT denormalized onto
    # this row -- derived at serialize time via the `duplicate_of`
    # relationship below, same as every other *_.display_name-style
    # derived field in this codebase (e.g. t.assigned_admin.display_name).
    #
    # Behavior once set (Option A, the spec's Recommended choice): the
    # duplicate stays open/readable, but independent processing is
    # blocked -- routes/me_tickets.py refuses a self-service reply/reopen,
    # and routes/tickets.py's admin reply/update endpoints also refuse
    # further action, redirecting the admin to the parent ticket instead.
    # (Option B -- auto-closing the duplicate -- was considered and
    # rejected: closing would fire the normal "your ticket is closed"
    # notification/timestamp semantics on a ticket that isn't actually
    # resolved, and would make the duplicate's own history read as if the
    # issue was addressed on ITS thread rather than the parent's, which is
    # exactly the confusion this feature exists to prevent.)
    duplicate_of_ticket_id = Column(Integer, ForeignKey("support_tickets.id"), nullable=True, index=True)
    marked_duplicate_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    marked_duplicate_at = Column(DateTime(timezone=True), nullable=True)

    created_by = relationship("User", foreign_keys=[created_by_user_id])
    assigned_admin = relationship("User", foreign_keys=[assigned_admin_id])
    deleted_by = relationship("User", foreign_keys=[deleted_by_user_id])
    locked_by = relationship("User", foreign_keys=[locked_by_user_id])
    marked_duplicate_by = relationship("User", foreign_keys=[marked_duplicate_by_user_id])
    # remote_side pins which end of this self-referential FK is "one" (the
    # parent) -- duplicate_of is this ticket's parent (scalar), duplicates
    # is the parent's list of tickets pointing at it (collection), same
    # shape as any other one-to-many backref, just self-joined.
    duplicate_of = relationship("SupportTicket", remote_side=[id], foreign_keys=[duplicate_of_ticket_id],
                                 backref=backref("duplicates", order_by="SupportTicket.created_at"))
    messages = relationship("SupportTicketMessage", backref="ticket", order_by="SupportTicketMessage.created_at",
                             cascade="all, delete-orphan")

    # --- Merge scaffolding (deferred) ---------------------------------------
    # TODO(duplicate-merge): section 5 of the Duplicate Cleanup Tools spec
    # asks only for the DATA MODEL to support a future real merge, not a
    # working merge UI/endpoint in this pass. What a full merge would need,
    # deferred here on purpose (matches this app's "future consideration"
    # comment style, see config.py's APP_VERSION):
    #   - Re-parenting every SupportTicketMessage/SupportTicketAttachment
    #     row from the duplicate(s) onto the parent ticket_id (a plain
    #     UPDATE ... WHERE ticket_id IN (...), no schema change needed --
    #     both tables already key on ticket_id alone).
    #   - Preserving audit history: AuditLog rows are keyed by
    #     target=f"TCK-{id}" per-ticket (see AuditLog's own docstring), so a
    #     merge would need to decide whether to also log a synthetic
    #     "merged from TCK-{dup_id}" marker on the parent rather than
    #     silently orphaning the duplicate's own history -- no new column
    #     needed for that, just a log_action call at merge time.
    #   - What happens to the duplicate's OWN id/row afterward (soft-delete
    #     it via `deleted` above, most likely, rather than removing the
    #     self-FK trail) is a product decision, not a schema question --
    #     duplicate_of_ticket_id already gives a merge implementation
    #     everything it needs to find "every ticket that pointed at this
    #     parent" without a new column or table.


class SupportTicketMessage(Base):
    __tablename__ = "support_ticket_messages"

    id = Column(Integer, primary_key=True)
    ticket_id = Column(Integer, ForeignKey("support_tickets.id", ondelete="CASCADE"), nullable=False, index=True)
    author_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Admin-only visibility -- filtered out server-side in routes/
    # me_tickets.py's serialization, never merely hidden client-side, so a
    # self-service response can't leak an internal note by inspecting the
    # raw JSON.
    is_internal_note = Column(Boolean, nullable=False, default=False)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)

    author = relationship("User")
    attachments = relationship("SupportTicketAttachment", backref="message", cascade="all, delete-orphan")


class SupportTicketAttachment(Base):
    """Metadata row for one uploaded file -- the file itself lives on disk
    under config.TICKET_ATTACHMENTS_DIR (see routes/me_tickets.py's/routes/
    tickets.py's upload handling, added in the Attachments phase), never in
    the DB. `stored_path` is relative to that root, e.g.
    "42/3f9e.../screenshot.png" -- ticket id as the leading path segment
    purely for on-disk organization, not itself a security boundary (every
    download still re-checks the caller owns or can manage the parent
    ticket, via ticket_id/message_id, not by trusting the path)."""
    __tablename__ = "support_ticket_attachments"

    id = Column(Integer, primary_key=True)
    ticket_id = Column(Integer, ForeignKey("support_tickets.id", ondelete="CASCADE"), nullable=False, index=True)
    message_id = Column(Integer, ForeignKey("support_ticket_messages.id", ondelete="CASCADE"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_path = Column(String(512), nullable=False)
    content_type = Column(String(128), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    uploaded_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class TicketNotification(Base):
    """In-app notification bell entry for a ticket event -- sibling to
    QuotaNotification (models.py, above), not folded into that table: the
    two have genuinely different shapes (QuotaNotification's pct_used/
    period_start/unique-constraint don't apply here, and vice versa a
    ticket_id FK doesn't belong on a quota row). routes/notifications.py's
    list_my_notifications merges both tables for display -- see that
    module's own comment for the id-prefixing scheme that keeps a single
    read/read-all contract working across two source tables."""
    __tablename__ = "ticket_notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    ticket_id = Column(Integer, ForeignKey("support_tickets.id", ondelete="CASCADE"), nullable=False)
    kind = Column(String(32), nullable=False)  # "ticket_created" | "ticket_reply" | "ticket_status_changed" | "ticket_assigned"
    message = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    read_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User")
    # Read by routes/notifications.py's _ticket_link_url() to tell a
    # notification's own recipient apart from the ticket's creator (so an
    # admin's notification links to the admin console page, not the
    # self-service one) -- no backref needed, SupportTicket doesn't need to
    # walk back to its notifications.
    ticket = relationship("SupportTicket")


class MfaRecoveryCode(Base):
    """One single-use MFA recovery code -- see mfa.py's
    generate_recovery_codes/consume_recovery_code. code_hash is sha256, the
    same reasoning as auth.py's _hash_reset_token: a high-entropy value
    looked up by exact match, not a low-entropy human password, so bcrypt's
    deliberate slowness buys nothing here. Regenerating (self-service or
    admin reset) deletes every existing row for the user and inserts a
    fresh batch -- that's what "invalidate previous codes when regenerated"
    means in practice, no separate `active` flag needed."""
    __tablename__ = "mfa_recovery_codes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user = relationship("User")


# --- Slack Integration for Notifications ------------------------------------
# See slack_notifications.py for the fan-out module these back, and
# routes/settings.py's Slack section for the admin-facing CRUD. Deliberately
# its own table (not columns bolted onto AppSettings, unlike most other
# integrations in this app) specifically so "which workspace(s) get this
# notification" is a real query over real rows from day one, not a single
# hardcoded webhook threaded through every call site -- a thin, single-row
# deployment today (routes/settings.py currently only ever creates/edits ONE
# row) is a natural, no-code-change starting point for a future "add a
# second Slack workspace" UI, rather than a retrofit.

class SlackWorkspace(Base):
    """One configured Slack incoming-webhook target. `notify_types` is a
    JSON object ({event_type: bool}, keys from slack_notifications.
    EVENT_TYPES) -- a JSON blob rather than one boolean column per event
    type, same reasoning as SupportTicket/AppSettings' other JSON-text
    columns (mfa_role_requirements, EmailProvider.config): the event-type
    registry can grow without a schema migration every time. A type not
    present in the dict defaults to OFF (opt-in per type, matching this
    app's every other notify_admin_on_* toggle's default-off stance)."""
    __tablename__ = "slack_workspaces"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, default="Default Workspace")
    # NOT NULL, but "no webhook configured yet" is a real, common state
    # (get_or_create_default_workspace's first-ever row, before an admin
    # has entered one) -- represented as "" (empty string), never a true
    # SQL NULL. routes/settings.py's Pydantic layer treats this field as
    # `str | None` (None = "not configured", matching every OTHER optional
    # secret field's convention on this page) and converts at the
    # boundary; nothing in this module or routes/settings.py should ever
    # assign Python `None` directly to this column -- doing so 500s with a
    # NotNullViolation instead of the empty-string sentinel this table
    # actually expects (confirmed hitting this live 2026-08-21 while
    # manually clearing a test row -- not reachable through any real user-
    # facing code path today, but worth knowing before adding one, e.g. a
    # future "disconnect Slack" action).
    webhook_url = Column(String(512), nullable=False)
    # Optional Slack channel override ("#ops-alerts") -- Slack's incoming
    # webhooks are already bound to one fixed channel at creation time on
    # Slack's side; this lets an admin redirect to a DIFFERENT channel the
    # same webhook app is permitted to post into, purely optional.
    channel_override = Column(String(128), nullable=True)
    is_enabled = Column(Boolean, nullable=False, default=True)
    # NOT NULL, same "" / "{}" -not- None sentinel convention as
    # webhook_url above -- see that column's own comment.
    notify_types = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)
    updated_by = Column(String(64), nullable=True)


class SlackDeliveryLog(Base):
    """One row per Slack webhook delivery ATTEMPT (success or failure) --
    so a silently-failing webhook (revoked, rate-limited, wrong channel) is
    diagnosable from the Settings page rather than swallowed. Deliberately
    NOT rolled into AuditLog: this is delivery telemetry for an outbound
    integration (same category as email would be, if this app tracked
    individual SMTP send attempts, which it doesn't), not an
    accountability record of an admin/user action."""
    __tablename__ = "slack_delivery_log"

    id = Column(Integer, primary_key=True)
    # Nullable: a "Send Test Notification" against a webhook URL typed into
    # the form but not yet saved has no workspace row to point at yet.
    workspace_id = Column(Integer, ForeignKey("slack_workspaces.id", ondelete="CASCADE"), nullable=True)
    event_type = Column(String(64), nullable=False)  # a slack_notifications.EVENT_TYPES key, or "test"
    message_preview = Column(String(512), nullable=True)
    success = Column(Boolean, nullable=False, default=True)
    error_detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)

    workspace = relationship("SlackWorkspace")


class MfaTrustedDevice(Base):
    """"Remember this device" (Settings -> Multi-Factor Authentication ->
    mfa_remember_device_days) -- one row per device a user chose to trust
    at the /mfa/verify step. token_hash is sha256 of the opaque value
    stored in the `mfa_trusted_device` cookie (routes/mfa.py); the cookie
    itself carries no user identity, so a lookup is always scoped to the
    user_id already resolved from the in-progress login attempt, not just
    "any row matching this hash" -- a stolen cookie is useless without also
    guessing which account it belongs to. Never bypasses a MANDATORY
    enrollment requirement (mfa.effective_policy == "required" and not yet
    enrolled) -- see routes/auth.py's login_submit."""
    __tablename__ = "mfa_trusted_devices"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, index=True)
    user_agent = Column(String(255), nullable=True)
    created_ip = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User")


class AuditRun(Base):
    """One row per System Audit execution (manual "Run Audit Now" or the
    scheduled loop, see main.py's _system_audit_loop) -- the parent of a
    batch of AuditFinding rows below. Same "one row per periodic sample"
    shape as DbStatSnapshot, just triggered by an audit tick instead of a
    fixed timer, and with child rows instead of flat columns (a run's
    finding count varies check-to-check, unlike DbStatSnapshot's fixed set
    of stat columns).

    `node_hostname` exists from day one even though this deployment is
    single-server (see system_audit/__init__.py's module docstring) --
    keeping every row server-labeled now means a future multi-node rollup
    is a filter/group-by on data already being collected, not a schema
    migration.

    status: "running" (in progress -- set at insert, before any check has
    executed) | "completed" | "failed" (the run itself errored out, not
    "found findings" -- a clean audit with zero findings is still
    "completed"). score is NULL while running, and can also be NULL after
    "failed" if the run didn't get far enough to compute one.

    The severity/status count columns are denormalized (also derivable by
    counting this run's AuditFinding rows) purely so the audit list page
    doesn't need a GROUP BY query per row just to render its summary --
    same reasoning as User.display_name-style denormalization elsewhere in
    this app. Written once, when the run finishes (see run_audit())."""
    __tablename__ = "audit_runs"

    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    trigger = Column(String(16), nullable=False)  # "manual" | "scheduled"
    triggered_by = Column(String(64), nullable=True)  # username, NULL for "scheduled"
    status = Column(String(16), nullable=False, default="running")  # "running" | "completed" | "failed"
    error_detail = Column(Text, nullable=True)  # set only when status == "failed"
    node_hostname = Column(String(255), nullable=True)

    score = Column(Integer, nullable=True)  # 0-100, see system_audit/__init__.py's compute_score()
    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    info_count = Column(Integer, nullable=False, default=0)
    passed_count = Column(Integer, nullable=False, default=0)
    # How this run's non-passed findings compare to the immediately
    # preceding completed run -- "new" (didn't exist last run) vs.
    # "resolved" (existed last run, gone/now-passed this run). Computed by
    # diffing check_id sets, see run_audit()'s own comment.
    new_findings_count = Column(Integer, nullable=False, default=0)
    resolved_findings_count = Column(Integer, nullable=False, default=0)

    findings = relationship("AuditFinding", back_populates="run", cascade="all, delete-orphan",
                             order_by="AuditFinding.id")


# Stable ordering for severity comparisons (score weighting, "worse than"
# checks) -- higher index = more severe. Kept next to the model since both
# AuditFinding (severity column comment) and system_audit/__init__.py
# (compute_score, notification thresholds) reference it.
AUDIT_SEVERITIES = ("passed", "info", "low", "medium", "high", "critical")


class AuditFinding(Base):
    """One row per individual check result within one AuditRun. Every
    check runs on every audit (there's no "skip this check" concept) and
    always produces exactly one row, including a "passed" one -- this is
    what makes the Critical/High/.../Passed dashboard counts (spec's
    example: "Critical 2, High 5, ..., Passed 74") a plain GROUP BY over
    this table's severity column rather than something inferred from
    absence.

    `check_id` is the check catalog's stable identifier (e.g.
    "ssh.permit_root_login", see system_audit/ssh_checks.py) -- NOT the
    row id, and NOT unique within a run (each check_id appears once per
    run, but across runs it's what lets run_audit() diff "does this
    check_id's non-passed status persist from the previous run" to
    classify new vs. resolved. Renaming a check_id effectively starts its
    history over -- acceptable, matches this catalog being new.

    Every text field here is operator-facing, host-derived evidence (a
    config line, a file permission octal, a package version) -- see
    system_audit/__init__.py's Finding dataclass docstring for the redaction
    stance (never a secret/token/key material, by construction of what the
    checks read)."""
    __tablename__ = "audit_findings"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("audit_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    check_id = Column(String(128), nullable=False, index=True)
    category = Column(String(32), nullable=False)  # "system" | "ssh" | "firewall"
    severity = Column(String(16), nullable=False)  # one of AUDIT_SEVERITIES above
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    why_it_matters = Column(Text, nullable=True)
    current_state = Column(Text, nullable=True)
    expected_state = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    # JSON-encoded {"type": "chmod", "path": ..., "mode": ...} -- see
    # system_audit/__init__.py's Finding.remediation_action docstring.
    # NULL for the overwhelming majority of findings (every SSH/firewall
    # check, every "passed"/informational finding) -- only the specific
    # file-permission checks that support "Fix Automatically" set this.
    remediation_action = Column(Text, nullable=True)
    automated_remediation_available = Column(Boolean, nullable=False, default=False)
    # Set by routes/system_audit.py's POST .../remediate once a fix has
    # actually been applied to THIS finding (a specific row on a specific
    # past run, not "the current state" -- the next audit run will
    # naturally re-check and, if the fix held, report status="resolved"
    # on its own new row; these columns are the permanent record of what
    # was done and by whom, kept on the original finding row rather than
    # only in AuditLog free text so the UI can show "Fixed by X on Y"
    # directly next to the finding it fixed).
    remediated_at = Column(DateTime(timezone=True), nullable=True)
    remediated_by = Column(String(64), nullable=True)
    # JSON-encoded {"previous_mode": ..., "new_mode": ..., "verified": ...}
    # -- the exact before/after. No one-click "Undo" action is built on
    # top of this yet (deliberately: audit_remediate.py's chmod action
    # takes no mode argument from the caller AT ALL, by design -- an undo
    # would need to reintroduce exactly that "set to a caller-supplied
    # mode" capability this phase specifically avoided). This column
    # exists so the UI can still SHOW the previous value for a manual
    # revert (`chmod <previous_mode> <path>` over a real SSH session) if
    # an admin ever needs one.
    remediation_result = Column(Text, nullable=True)
    # "new" | "existing" | "resolved" -- computed by run_audit() relative
    # to the previous completed run, NOT set by the individual check
    # itself (a check has no notion of history). "resolved" rows are
    # written on the run where the issue went away (i.e. this row's own
    # severity is "passed" but the check_id was non-passed last run) --
    # kept as a real row (not just implied by absence) so the finding
    # HISTORY (spec section 9's "Resolved findings" count) has something
    # concrete to point at.
    status = Column(String(16), nullable=False, default="existing")

    run = relationship("AuditRun", back_populates="findings")


class AuditNotification(Base):
    """One row per (admin user, audit run, alert reason) -- backs the
    in-app notification bell for System Audit alerts (new Critical/High
    findings, a security-score drop, a previously-resolved finding
    returning -- see system_audit/__init__.py's run_audit() for exactly
    when these get written). A separate table from QuotaNotification/
    TicketNotification, not a third case folded into notifications.py's
    existing two -- same "genuinely different shape, don't force a
    polymorphic table" reasoning as that router's own docstring (this one
    has a run_id, not a ticket_id or a quota period).

    Broadcast to every admin/super_admin account (a loop at write time
    over has_permission(..., "system_audit", "view") users, mirroring
    admin_notification_email's single-recipient email being sent once per
    triggering event) -- there's no "own scope" for a system-wide security
    posture the way a personal quota notification has an owning user."""
    __tablename__ = "audit_notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("audit_runs.id", ondelete="CASCADE"), nullable=False)
    reason = Column(String(32), nullable=False)  # "new_critical" | "new_high" | "score_dropped" | "finding_regressed"
    message = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    read_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User")
    run = relationship("AuditRun")
