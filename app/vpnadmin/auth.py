"""
Authentication and role-based access control.

Sessions use Starlette's built-in SessionMiddleware (a signed, httponly
cookie -- no server-side session store needed). Passwords are hashed with
bcrypt via passlib. Two roles: admin (full control) and viewer (read-only).
"""
from datetime import datetime, timezone

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Role, User

# Used directly rather than via passlib: passlib (last released 2020, now
# unmaintained) is incompatible with bcrypt>=4.1's dropped __about__
# attribute and throws on hash/verify -- a real, currently-reproducible
# break for anyone installing this fresh, not a hypothetical concern.
_BCRYPT_MAX_BYTES = 72  # bcrypt silently ignores anything beyond this


def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    pw_bytes = password.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    try:
        return bcrypt.checkpw(pw_bytes, password_hash.encode("ascii"))
    except ValueError:
        # Malformed/foreign hash format -- treat as a failed verification,
        # not a crash.
        return False


def bootstrap_admin(db: Session) -> None:
    """Create the initial admin account from BOOTSTRAP_ADMIN_USERNAME/PASSWORD
    if no users exist yet. No-op on every subsequent startup once any user
    exists, so it's safe to leave the env vars set permanently."""
    if db.query(User).first() is not None:
        return
    if not settings.BOOTSTRAP_ADMIN_USERNAME or not settings.BOOTSTRAP_ADMIN_PASSWORD:
        return
    admin = User(
        username=settings.BOOTSTRAP_ADMIN_USERNAME,
        password_hash=hash_password(settings.BOOTSTRAP_ADMIN_PASSWORD),
        role=Role.admin,
    )
    db.add(admin)
    db.commit()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    user_id = request.session.get("user_id")
    if user_id is None:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.deleted:
        return None
    return user


def require_user(user: User | None = Depends(get_current_user)) -> User:
    """For API routes: 401 if not logged in."""
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """For API routes that mutate state: 403 unless the caller is an admin."""
    if user.role != Role.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


def login_user(request: Request, user: User, db: Session | None = None) -> None:
    # Store the minimum needed to re-derive identity; role/is_active are
    # re-checked from the DB on every request via get_current_user, so a
    # role change or deactivation takes effect immediately, not just on
    # next login.
    request.session["user_id"] = user.id
    if db is not None:
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()


def logout_user(request: Request) -> None:
    request.session.clear()
