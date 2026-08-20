"""
Multi-Factor Authentication (TOTP) -- the pages and self-service API this
feature needs beyond routes/auth.py's login-flow branching (see that
file) and routes/users.py's admin reset/disable/force-enroll actions.
Colocates a page + its own /api/* actions in one router, matching this
app's existing convention for a small, self-contained feature (see
routes/support.py before the Support Ticketing System's own routers grew
past that point).

Every route here operates on EITHER:
  - the account named by a pending session key (mfa_setup_required_user_id
    / mfa_pending_user_id) -- set by routes/auth.py's login_submit, NOT a
    normal Depends(require_user) session, since by definition MFA isn't
    satisfied yet; or
  - request.user (Depends(require_user)) for the self-service disable/
    regenerate-codes actions reachable from a fully logged-in session's
    Profile page.
These are never mixed within one endpoint.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import app_settings, mailer
from .. import mfa as mfa_module
from ..app_settings import apply_settings_globals
from ..audit import log_action
from ..auth import _as_aware_utc, login_user, require_user, verify_password
from ..client_ip import get_client_ip
from ..db import get_db
from ..models import User

router = APIRouter()
templates = Jinja2Templates(directory="vpnadmin/templates")
apply_settings_globals(templates)


def _mfa_security_notice(db: Session, user: User, event_description: str) -> None:
    if user.email:
        mailer.send_mfa_security_notice(db=db, to_address=user.email, username=user.username, event_description=event_description)


def _pending_user(request: Request, db: Session, session_key: str) -> User | None:
    user_id = request.session.get(session_key)
    if user_id is None:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.deleted:
        request.session.pop(session_key, None)
        return None
    return user


def _check_mfa_lockout(user: User) -> str | None:
    """Returns an error message if `user` is currently OTP-locked-out,
    None otherwise. Reuses account_lockout_threshold/account_lockout_minutes
    (Settings -> Security) -- see models.User.mfa_failed_attempts' own
    docstring for why this is a separate counter from the password one,
    while still sharing the same threshold/duration settings."""
    if user.mfa_locked_until and _as_aware_utc(user.mfa_locked_until) > datetime.now(timezone.utc):
        remaining_minutes = max(1, int((_as_aware_utc(user.mfa_locked_until) - datetime.now(timezone.utc)).total_seconds() // 60) + 1)
        return f"Too many failed codes. Try again in about {remaining_minutes} minute(s)."
    return None


def _register_mfa_failure(user: User, db: Session, *, client_ip: str | None, user_agent: str, reason: str) -> None:
    user.mfa_failed_attempts += 1
    threshold = app_settings.runtime.account_lockout_threshold
    locked_now = False
    if threshold and user.mfa_failed_attempts >= threshold:
        user.mfa_locked_until = datetime.now(timezone.utc) + timedelta(minutes=app_settings.runtime.account_lockout_minutes)
        locked_now = True
    detail = f"IP {client_ip or 'unknown'}; UA {user_agent[:120]}; attempt {user.mfa_failed_attempts}; {reason}"
    if locked_now:
        detail += f"; account locked for {app_settings.runtime.account_lockout_minutes} minute(s)"
    log_action(db, user, "invalid_otp_attempt", target=user.username, detail=detail, success=False)
    db.commit()


# --- /mfa/verify -- second-factor challenge after a correct password -------

@router.get("/mfa/verify")
def mfa_verify_page(request: Request, db: Session = Depends(get_db)):
    user = _pending_user(request, db, "mfa_pending_user_id")
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "mfa_verify.html", {
        "error": None, "remember_days": app_settings.runtime.mfa_remember_device_days,
    })


@router.post("/mfa/verify")
async def mfa_verify_submit(
    request: Request,
    code: str = Form(""),
    recovery_code: str = Form(""),
    remember_device: bool = Form(False),
    db: Session = Depends(get_db),
):
    user = _pending_user(request, db, "mfa_pending_user_id")
    if user is None:
        return RedirectResponse("/login", status_code=303)

    remember_days = app_settings.runtime.mfa_remember_device_days
    ctx = {"error": None, "remember_days": remember_days}

    lockout_error = _check_mfa_lockout(user)
    if lockout_error:
        return templates.TemplateResponse(request, "mfa_verify.html", {**ctx, "error": lockout_error}, status_code=423)

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    used_recovery = False
    ok = False
    if recovery_code.strip():
        ok = mfa_module.consume_recovery_code(user, recovery_code, db)
        used_recovery = ok
    elif code.strip():
        secret = mfa_module.decrypt_secret(user.mfa_secret_encrypted) if user.mfa_secret_encrypted else None
        ok = bool(secret) and mfa_module.verify_totp(secret, code)

    if not ok:
        _register_mfa_failure(user, db, client_ip=client_ip, user_agent=user_agent,
                               reason="recovery code" if recovery_code.strip() else "TOTP code")
        return templates.TemplateResponse(
            request, "mfa_verify.html",
            {**ctx, "error": "That code isn't valid. Check your authenticator app's time, or use a recovery code instead."},
            status_code=401,
        )

    # Success -- clear any lockout state, same posture as the password
    # step's own equivalent reset in routes/auth.py's login_submit.
    user.mfa_failed_attempts = 0
    user.mfa_locked_until = None
    user.mfa_last_used_at = datetime.now(timezone.utc)
    request.session.pop("mfa_pending_user_id", None)
    login_user(request, user, db)
    log_action(db, user, "mfa_login_success", target=user.username,
               detail=f"IP {client_ip or 'unknown'}; UA {user_agent[:120]}; via {'recovery code' if used_recovery else 'TOTP'}",
               success=True)
    if used_recovery:
        log_action(db, user, "recovery_code_used", target=user.username, detail=f"IP {client_ip or 'unknown'}", success=True)

    response = RedirectResponse("/", status_code=303)
    if remember_device and remember_days > 0:
        token = mfa_module.issue_trusted_device_token(user, db, days=remember_days, user_agent=user_agent, ip=client_ip)
        from ..config import settings as env_settings
        response.set_cookie(
            mfa_module.TRUSTED_DEVICE_COOKIE_NAME, token, max_age=remember_days * 86400,
            httponly=True, secure=env_settings.SESSION_HTTPS_ONLY, samesite="lax",
        )
    return response


# --- /mfa/setup -- enrollment (self-service AND mandatory-pending) ---------

@router.get("/mfa/setup")
def mfa_setup_page(request: Request, db: Session = Depends(get_db)):
    mandatory_user = _pending_user(request, db, "mfa_setup_required_user_id")
    self_user = None
    if mandatory_user is None:
        from ..auth import get_current_user
        self_user = get_current_user(request, db)
    user = mandatory_user or self_user
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.mfa_enabled and mandatory_user is None:
        # Already enrolled and this isn't a forced re-enrollment -- nothing
        # to set up; send them back to their Security settings.
        return RedirectResponse("/profile", status_code=303)

    secret = mfa_module.generate_secret()
    # Stashed in the session (not the DB) until the confirming OTP check
    # below succeeds -- an abandoned setup attempt never leaves a
    # half-enrolled secret on the account.
    request.session["mfa_setup_secret"] = secret
    uri = mfa_module.provisioning_uri(user, secret)
    return templates.TemplateResponse(request, "mfa_setup.html", {
        "error": None, "qr_data_uri": mfa_module.qr_code_data_uri(uri), "secret": secret,
        "mandatory": mandatory_user is not None, "recovery_codes": None,
    })


@router.post("/mfa/setup")
def mfa_setup_submit(request: Request, code: str = Form(""), db: Session = Depends(get_db)):
    mandatory_user = _pending_user(request, db, "mfa_setup_required_user_id")
    self_user = None
    if mandatory_user is None:
        from ..auth import get_current_user
        self_user = get_current_user(request, db)
    user = mandatory_user or self_user
    if user is None:
        return RedirectResponse("/login", status_code=303)

    secret = request.session.get("mfa_setup_secret")
    if not secret or not mfa_module.verify_totp(secret, code):
        uri = mfa_module.provisioning_uri(user, secret) if secret else ""
        return templates.TemplateResponse(request, "mfa_setup.html", {
            "error": "That code doesn't match. Scan the QR code again and try the current 6-digit code.",
            "qr_data_uri": mfa_module.qr_code_data_uri(uri) if uri else None, "secret": secret,
            "mandatory": mandatory_user is not None, "recovery_codes": None,
        }, status_code=401)

    user.mfa_secret_encrypted = mfa_module.encrypt_secret(secret)
    user.mfa_enabled = True
    user.mfa_enrolled_at = datetime.now(timezone.utc)
    user.mfa_setup_required = False
    request.session.pop("mfa_setup_secret", None)
    codes = mfa_module.replace_recovery_codes(user, db)
    db.commit()
    log_action(db, user, "mfa_enrolled", target=user.username, success=True)
    log_action(db, user, "mfa_enabled", target=user.username, success=True)
    _mfa_security_notice(db, user, "Multi-factor authentication was enabled on your account.")

    if mandatory_user is not None:
        # Enrollment completion IS the second factor for this first login
        # -- see routes/auth.py's login_submit / the plan's design note.
        request.session.pop("mfa_setup_required_user_id", None)
        login_user(request, user, db)
        log_action(db, user, "login_success", target=user.username, success=True)

    return templates.TemplateResponse(request, "mfa_setup.html", {
        "error": None, "qr_data_uri": None, "secret": None,
        "mandatory": False, "recovery_codes": codes, "enrolled": True,
    })


# --- Self-service disable / regenerate recovery codes -----------------------

class MfaStepUpRequest(BaseModel):
    password: str


@router.post("/api/me/mfa/disable")
def disable_my_mfa(body: MfaStepUpRequest, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=403, detail="Incorrect password.")
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled on your account.")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    from ..models import MfaRecoveryCode
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id).delete()
    db.commit()
    log_action(db, user, "mfa_disabled", target=user.username, success=True)
    if mfa_module.is_privileged(user, db) and app_settings.runtime.notify_admin_on_mfa_disabled:
        mailer.send_admin_notification(
            db=db, subject="MFA disabled for a privileged account",
            body=f"{user.username} ({user.display_name}) just disabled multi-factor authentication on their own account.",
        )
    _mfa_security_notice(db, user, "Multi-factor authentication was disabled on your account.")
    return {"message": "MFA disabled."}


@router.post("/api/me/mfa/recovery-codes/regenerate")
def regenerate_my_recovery_codes(body: MfaStepUpRequest, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=403, detail="Incorrect password.")
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled on your account.")
    codes = mfa_module.replace_recovery_codes(user, db)
    log_action(db, user, "mfa_recovery_codes_regenerated", target=user.username, success=True)
    _mfa_security_notice(db, user, "Your MFA recovery codes were regenerated -- the old codes no longer work.")
    return {"recovery_codes": codes}


@router.get("/api/me/mfa")
def get_my_mfa_status(user: User = Depends(require_user), db: Session = Depends(get_db)):
    return {
        "mfa_enabled": user.mfa_enabled,
        "mfa_enrolled_at": user.mfa_enrolled_at.isoformat() if user.mfa_enrolled_at else None,
        "mfa_last_used_at": user.mfa_last_used_at.isoformat() if user.mfa_last_used_at else None,
        "recovery_codes_remaining": mfa_module.remaining_recovery_codes_count(user, db) if user.mfa_enabled else 0,
        "effective_policy": mfa_module.effective_policy(user, db),
    }
