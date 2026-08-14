"""
Authentication and role-based access control.

Sessions use Starlette's built-in SessionMiddleware (a signed, httponly
cookie -- no server-side session store needed). Passwords are hashed with
bcrypt via passlib. Two roles: admin (full control) and viewer (read-only).
"""

from datetime import UTC, datetime

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from . import app_settings
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
    # db.init_db() (which seeds the system RoleDef rows -- see permissions.py)
    # always runs before this is called (see main.py's startup sequence), so
    # the "admin" RoleDef is guaranteed to already exist here. Setting both
    # role_id (dynamic RBAC, what require_permission actually checks) and
    # the legacy `role` enum column keeps this account fully functional
    # under both systems for the duration of the Phase 1/2 transition.
    from .models import RoleDef

    admin_role = db.query(RoleDef).filter(RoleDef.slug == "admin").first()
    admin = User(
        username=settings.BOOTSTRAP_ADMIN_USERNAME,
        password_hash=hash_password(settings.BOOTSTRAP_ADMIN_PASSWORD),
        role=Role.admin,
        role_id=admin_role.id if admin_role is not None else None,
        is_bootstrap_admin=True,
    )
    db.add(admin)
    db.commit()


def ensure_bootstrap_admin_flag(db: Session) -> None:
    """Idempotent backfill for User.is_bootstrap_admin: if no account is
    currently flagged, designate one. This covers deployments that existed
    before the flag did (bootstrap_admin() above only sets it at the
    moment of first-ever account creation, which already happened for
    those) -- without this, the "bootstrap admin can never be demoted"
    rule would silently protect nobody on any pre-existing database. Prefers
    whichever admin's username still matches BOOTSTRAP_ADMIN_USERNAME;
    falls back to the earliest-created admin account. No-op once any
    account already has the flag, so this is safe to call on every
    startup, not just the first."""
    if db.query(User).filter(User.is_bootstrap_admin.is_(True)).first() is not None:
        return
    candidate = None
    if settings.BOOTSTRAP_ADMIN_USERNAME:
        candidate = (
            db.query(User)
            .filter(
                User.username == settings.BOOTSTRAP_ADMIN_USERNAME.strip().lower(),
                User.role == Role.admin,
            )
            .first()
        )
    if candidate is None:
        candidate = db.query(User).filter(User.role == Role.admin).order_by(User.created_at).first()
    if candidate is not None:
        candidate.is_bootstrap_admin = True
        db.commit()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    user_id = request.session.get("user_id")
    if user_id is None:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.deleted:
        return None

    # Session-timeout enforcement (Settings page -> session_timeout_minutes,
    # see app_settings.py). Deliberately enforced here at the application
    # level -- based on time since last activity, checked/refreshed on
    # every request -- rather than by trying to change SessionMiddleware's
    # cookie max_age at runtime, which is fixed at process startup and
    # would need a full restart to pick up a new value. This approach also
    # gives a sliding (not fixed) session: any activity resets the clock,
    # matching how "session timeout" is understood in most admin tools.
    last_activity_iso = request.session.get("last_activity")
    now = datetime.now(UTC)
    if last_activity_iso is not None:
        try:
            last_activity = datetime.fromisoformat(last_activity_iso)
        except ValueError:
            last_activity = now  # malformed value -- don't hard-lock the user out over it
        elapsed_minutes = (now - last_activity).total_seconds() / 60
        if elapsed_minutes > app_settings.runtime.session_timeout_minutes:
            request.session.clear()
            return None
    request.session["last_activity"] = now.isoformat()
    return user


def require_user(user: User | None = Depends(get_current_user)) -> User:
    """For API routes: 401 if not logged in."""
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


# require_admin / require_client_manager used to live here as hardcoded
# Role-enum checks. Removed -- replaced by permissions.py's dynamic
# require_permission(object_key, action), which every former call site now
# uses (often via a module-local `require_admin = require_permission(...)`
# alias, to avoid touching every Depends() at the call site -- see
# routes/settings.py, routes/teams.py, routes/status.py, routes/users.py,
# and routes/clients.py's `_require_client_manager`). See
# docs/rbac_identity_design.md and the joyful-sauteeing-cookie plan.


def login_user(request: Request, user: User, db: Session | None = None) -> None:
    # Store the minimum needed to re-derive identity; role/is_active are
    # re-checked from the DB on every request via get_current_user, so a
    # role change or deactivation takes effect immediately, not just on
    # next login.
    request.session["user_id"] = user.id
    if db is not None:
        user.last_login_at = datetime.now(UTC)
        db.commit()


def logout_user(request: Request) -> None:
    request.session.clear()
