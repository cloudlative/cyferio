import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text
from sqlalchemy.orm import validates

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


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.viewer)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Profile fields -- all optional, self-service editable (see
    # routes/users.py PATCH /api/users/me) as well as admin-editable.
    first_name = Column(String(64), nullable=True)
    last_name = Column(String(64), nullable=True)
    gender = Column(Enum(Gender), nullable=False, default=Gender.unspecified)
    team = Column(String(64), nullable=True)

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
