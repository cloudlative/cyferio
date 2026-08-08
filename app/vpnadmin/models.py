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


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.viewer)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    @validates("username")
    def _normalize_username(self, key, value):
        return value.strip().lower()


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
