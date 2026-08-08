from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..audit import log_action
from ..auth import hash_password, require_admin, require_user, verify_password
from ..db import get_db
from ..models import Gender, Role, User

router = APIRouter(prefix="/api/users", tags=["users"])


def _valid_password(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters.")
    return v


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: Role = Role.viewer
    first_name: str | None = None
    last_name: str | None = None
    gender: Gender = Gender.unspecified
    team: str | None = None

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


class UpdateUserRequest(BaseModel):
    """Admin-only edits to another (or their own, for non-guardrailed
    fields) user's account. Password here is an unconditional admin reset --
    no current-password check, unlike the self-service /me endpoint below."""
    role: Role | None = None
    is_active: bool | None = None
    deleted: bool | None = None  # True = soft-delete, False = restore
    password: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    gender: Gender | None = None
    team: str | None = None
    created_at: datetime | None = None  # deliberately admin-editable; see note on PATCH below

    @field_validator("password")
    @classmethod
    def _pw(cls, v: str | None) -> str | None:
        return _valid_password(v) if v else v


class UpdateProfileRequest(BaseModel):
    """Self-service: any logged-in user editing their own profile. No role/
    is_active/deleted here -- those are admin-only, via UpdateUserRequest."""
    first_name: str | None = None
    last_name: str | None = None
    gender: Gender | None = None
    team: str | None = None
    current_password: str | None = None
    new_password: str | None = None

    @field_validator("new_password")
    @classmethod
    def _pw(cls, v: str | None) -> str | None:
        return _valid_password(v) if v else v


def _serialize(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role.value,
        "is_active": u.is_active,
        "deleted": u.deleted,
        "deleted_at": u.deleted_at.isoformat() if u.deleted_at else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "display_name": u.display_name,
        "gender": u.gender.value if u.gender else Gender.unspecified.value,
        "team": u.team,
    }


def _guard_against_self_lockout(db: Session, target: User, admin: User, *, removing: bool) -> None:
    """Shared guardrail for anything that would demote/deactivate/delete an
    admin: can't do it to yourself, and can't do it if it would leave zero
    active, non-deleted admins."""
    if not removing:
        return
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You can't demote, deactivate, or delete your own account.")
    remaining_admins = db.query(User).filter(
        User.role == Role.admin, User.is_active.is_(True), User.deleted.is_(False), User.id != target.id
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
    for field in ("first_name", "last_name", "gender", "team"):
        value = getattr(body, field)
        if value is not None and value != getattr(user, field):
            setattr(user, field, value)
            changes.append(field)

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
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
        first_name=body.first_name,
        last_name=body.last_name,
        gender=body.gender,
        team=body.team,
    )
    db.add(user)
    db.commit()
    log_action(db, admin, "create_user", target=body.username, detail=f"role={body.role.value}")
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

    # Guardrails against an admin locking everyone (including themselves)
    # out: demoting, deactivating, or deleting the last active admin (or
    # yourself) is blocked, regardless of which of those three the request
    # is doing.
    would_remove = target.role == Role.admin and (
        (body.role is not None and body.role != Role.admin)
        or body.is_active is False
        or body.deleted is True
    )
    _guard_against_self_lockout(db, target, admin, removing=would_remove)

    changes = []
    if body.role is not None and body.role != target.role:
        changes.append(f"role {target.role.value}->{body.role.value}")
        target.role = body.role
    if body.is_active is not None and body.is_active != target.is_active:
        changes.append(f"is_active {target.is_active}->{body.is_active}")
        target.is_active = body.is_active
    if body.deleted is not None and body.deleted != target.deleted:
        target.deleted = body.deleted
        target.deleted_at = datetime.now(timezone.utc) if body.deleted else None
        changes.append("deleted" if body.deleted else "restored")
    if body.password:
        target.password_hash = hash_password(body.password)
        changes.append("password reset")
    for field in ("first_name", "last_name", "gender", "team"):
        value = getattr(body, field)
        if value is not None and value != getattr(target, field):
            setattr(target, field, value)
            changes.append(field)
    if body.created_at is not None and body.created_at != target.created_at:
        # Deliberately admin-editable (e.g. backdating an account created to
        # reflect a real-world join date imported from elsewhere) -- this is
        # purely a profile display field. It's distinct from AuditLog's own
        # `timestamp` column, which stays an immutable record of when each
        # action actually happened and is never editable through this API.
        changes.append(f"created_at {target.created_at.isoformat()}->{body.created_at.isoformat()}")
        target.created_at = body.created_at

    db.commit()
    if changes:
        log_action(db, admin, "update_user", target=target.username, detail="; ".join(changes))
    return _serialize(target)


@router.delete("/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Soft delete: the account is deactivated, hidden from the main user
    list, and can no longer log in, but the row and its audit history are
    kept and remain visible/restorable under GET /api/users/deleted. There
    is deliberately no hard-delete path."""
    target = db.get(User, user_id)
    if target is None or target.deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    _guard_against_self_lockout(db, target, admin, removing=(target.role == Role.admin))
    target.deleted = True
    target.deleted_at = datetime.now(timezone.utc)
    target.is_active = False
    db.commit()
    log_action(db, admin, "delete_user", target=target.username)
    return {"message": f"User '{target.username}' deleted (recoverable from the Deleted users list)."}
