import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey, Table
from sqlalchemy.orm import validates, relationship

from .db import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"
    viewer = "viewer"  # read-only: status/list/check/lint-db, no add/revoke/user-management


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
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    members = relationship("User", secondary="user_teams", back_populates="teams", order_by="User.username")

    @validates("name")
    def _normalize_name(self, key, value):
        return value.strip()


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
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

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

    @validates("username")
    def _normalize_username(self, key, value):
        return value.strip().lower()

    @property
    def display_name(self) -> str:
        full = " ".join(p for p in (self.first_name, self.last_name) if p)
        return full or self.username


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
