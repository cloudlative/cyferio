from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..audit import log_action
from ..auth import hash_password, require_admin
from ..db import get_db
from ..models import Role, User

router = APIRouter(prefix="/api/users", tags=["users"])


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: Role = Role.viewer

    @field_validator("username")
    @classmethod
    def _valid_username(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) < 3 or len(v) > 64:
            raise ValueError("Username must be 3-64 characters.")
        return v

    @field_validator("password")
    @classmethod
    def _valid_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v


class UpdateUserRequest(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = None


def _serialize(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role.value,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


@router.get("")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [_serialize(u) for u in db.query(User).order_by(User.username).all()]


@router.get("/me")
def whoami(admin: User = Depends(require_admin)):
    # Kept under the admin-only router for consistency with the rest of user
    # management, but any logged-in user's identity is also implicitly
    # available to the frontend via the base template context.
    return _serialize(admin)


@router.post("", status_code=201)
def create_user(body: CreateUserRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first() is not None:
        raise HTTPException(status_code=409, detail=f"Username '{body.username}' already exists.")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.commit()
    log_action(db, admin, "create_user", target=body.username, detail=f"role={body.role.value}")
    return _serialize(user)


@router.patch("/{user_id}")
def update_user(user_id: int, body: UpdateUserRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    # Guardrails against an admin locking everyone (including themselves)
    # out: can't demote/deactivate yourself, and can't remove the last
    # remaining active admin.
    would_lose_admin = (
        target.role == Role.admin
        and (
            (body.role is not None and body.role != Role.admin)
            or (body.is_active is False)
        )
    )
    if would_lose_admin:
        if target.id == admin.id:
            raise HTTPException(status_code=400, detail="You can't demote or deactivate your own account.")
        remaining_admins = db.query(User).filter(
            User.role == Role.admin, User.is_active.is_(True), User.id != target.id
        ).count()
        if remaining_admins == 0:
            raise HTTPException(status_code=400, detail="Can't remove the last active admin account.")

    changes = []
    if body.role is not None and body.role != target.role:
        changes.append(f"role {target.role.value}->{body.role.value}")
        target.role = body.role
    if body.is_active is not None and body.is_active != target.is_active:
        changes.append(f"is_active {target.is_active}->{body.is_active}")
        target.is_active = body.is_active
    if body.password:
        if len(body.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
        target.password_hash = hash_password(body.password)
        changes.append("password reset")

    db.commit()
    if changes:
        log_action(db, admin, "update_user", target=target.username, detail="; ".join(changes))
    return _serialize(target)


@router.delete("/{user_id}")
def delete_user(user_id: int, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You can't delete your own account.")
    if target.role == Role.admin:
        remaining_admins = db.query(User).filter(
            User.role == Role.admin, User.is_active.is_(True), User.id != target.id
        ).count()
        if remaining_admins == 0:
            raise HTTPException(status_code=400, detail="Can't delete the last active admin account.")
    username = target.username
    db.delete(target)
    db.commit()
    log_action(db, admin, "delete_user", target=username)
    return {"message": f"User '{username}' deleted."}
