import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import app_settings, captcha, geoip, mailer, slack_notifications
from .. import mfa as mfa_module
from ..app_settings import apply_settings_globals
from ..audit import log_action
from ..auth import (
    _as_aware_utc,
    clear_password_reset_token,
    get_current_user,
    get_user_by_reset_token,
    hash_password,
    issue_password_reset_token,
    login_user,
    logout_user,
    verify_password,
    PASSWORD_RESET_TOKEN_TTL_MINUTES,
)
from ..client_ip import get_client_ip, ip_matches_allowlist
from ..db import get_db
from ..models import User

router = APIRouter()
templates = Jinja2Templates(directory="vpnadmin/templates")
apply_settings_globals(templates)


def _captcha_error(request: Request, form: dict) -> bool:
    """True if CAPTCHA is configured and the submitted token failed
    verification -- False either when CAPTCHA isn't configured at all
    (nothing to check) or when it passed. Shared by login_submit,
    forgot_password_submit, and reset_password_submit below, all three of
    which reject on this the same way: re-render their own form with a
    generic "please complete the CAPTCHA challenge" error, same
    not-revealing-more-than-necessary posture as every other error message
    on this page (a real bot gets no signal about whether anything else it
    submitted was even close to valid)."""
    if not captcha.is_configured():
        return False
    token = captcha.extract_token(form)
    return not captcha.verify(token, remote_ip=get_client_ip(request))


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db) is not None:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None, "captcha": captcha.widget_context()})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    captcha_ctx = captcha.widget_context()
    if _captcha_error(request, dict(await request.form())):
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Please complete the CAPTCHA challenge and try again.", "captcha": captcha_ctx},
            status_code=400,
        )

    generic_error = templates.TemplateResponse(
        request, "login.html", {"error": "Invalid username or password.", "captcha": captcha_ctx}, status_code=401,
    )

    user = db.query(User).filter(User.username == username.strip().lower()).first()
    if user is None or not user.is_active or user.deleted:
        # Same generic message as a wrong password -- deliberately not
        # revealing whether the username itself exists (unchanged from
        # before this feature). Login-restriction checks below need a real
        # user row to read per-user allowed countries/IPs from, so there is
        # nothing meaningful to restriction-check yet for a username that
        # doesn't exist -- straight to the generic error.
        return generic_error

    # Maintenance mode (Settings -> System Administration): blocks every
    # role except admin/super_admin. Checked before restriction/lockout/
    # password checks -- a maintenance window shouldn't leak any of that
    # detail to a non-admin account that can't log in anyway right now.
    # Group-only permissions: "admin/super_admin" is no longer a single
    # role_slug to compare -- checks whether EITHER is among this user's
    # effective roles (union across their group membership).
    if app_settings.runtime.maintenance_mode and not (
        set(user.effective_role_slugs) & {"admin", "super_admin"}
    ):
        message = app_settings.runtime.maintenance_message or "This application is temporarily down for maintenance. Please try again shortly."
        return templates.TemplateResponse(request, "login.html", {"error": message, "captcha": captcha_ctx}, status_code=503)

    # Account lockout (Settings -> Security): a threshold of 0/None disables
    # this entirely (the pre-existing behavior). locked_until is set once
    # failed_login_attempts reaches the threshold (see the wrong-password
    # branch further down) and simply expires on its own -- no admin unlock
    # action needed for the common case.
    if user.locked_until and _as_aware_utc(user.locked_until) > datetime.now(timezone.utc):
        # _as_aware_utc: SQLite hands this column back tzinfo-naive on
        # read regardless of its DateTime(timezone=True) declaration --
        # see that helper's own docstring (auth.py) for why this is
        # necessary and harmless on Postgres. Pre-existing latent bug,
        # fixed alongside the same-shape issue found in the new
        # password-reset-token expiry check.
        remaining_minutes = max(1, int((_as_aware_utc(user.locked_until) - datetime.now(timezone.utc)).total_seconds() // 60) + 1)
        return templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many failed login attempts. Try again in about {remaining_minutes} minute(s).", "captcha": captcha_ctx},
            status_code=423,
        )

    # Country/City/ASN/IP restriction checks run BEFORE password
    # verification (see this task's own "Authentication Flow Requirements":
    # a request from a blocked country/city/network/IP should never reach
    # password-hashing at all) -- but they still need this user's OWN row
    # to know what to check against (restrictions are per-user, see
    # models.py), so a lookup happens first. That is a plain SELECT, not
    # "authentication logic" -- the actual sensitive/expensive step this
    # ordering avoids is verify_password's bcrypt hash comparison, which
    # only ever runs after all four checks below pass. Order (broadest to
    # narrowest signal): country, then city, then ASN/network, then exact
    # IP -- an admin restricting by IP already gets the most precise check
    # last, after the cheaper/coarser GeoIP lookups have had a chance to
    # reject first.
    client_ip = get_client_ip(request)

    if user.restrict_login_by_country:
        allowed_countries = json.loads(user.allowed_login_countries or "[]")
        if allowed_countries:
            country = geoip.lookup_country(client_ip)
            if country not in allowed_countries:
                log_action(
                    db, user, "login_blocked_country", target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; detected country {country or 'unknown'}; "
                           f"allowed: {', '.join(allowed_countries)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request, "login.html",
                    {"error": f"Login is not permitted from your current country "
                              f"({country or 'unknown'}, IP {client_ip or 'unknown'}).", "captcha": captcha_ctx},
                    status_code=403,
                )

    if user.restrict_login_by_city:
        allowed_cities = json.loads(user.allowed_login_cities or "[]")
        if allowed_cities:
            city = geoip.lookup_city(client_ip)
            allowed_lower = {c.lower() for c in allowed_cities}
            if (city or "").lower() not in allowed_lower:
                log_action(
                    db, user, "login_blocked_city", target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; detected city {city or 'unknown'}; "
                           f"allowed: {', '.join(allowed_cities)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request, "login.html",
                    {"error": f"Login is not permitted from your current city "
                              f"({city or 'unknown'}, IP {client_ip or 'unknown'}).", "captcha": captcha_ctx},
                    status_code=403,
                )

    if user.restrict_login_by_asn:
        allowed_asns = json.loads(user.allowed_login_asns or "[]")
        if allowed_asns:
            asn = geoip.lookup_asn(client_ip)
            asn_label = f"AS{asn}" if asn is not None else None
            if asn_label not in allowed_asns:
                log_action(
                    db, user, "login_blocked_asn", target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; detected ASN {asn_label or 'unknown'}; "
                           f"allowed: {', '.join(allowed_asns)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request, "login.html",
                    {"error": f"Login is not permitted from your current network "
                              f"({asn_label or 'unknown'}, IP {client_ip or 'unknown'}).", "captcha": captcha_ctx},
                    status_code=403,
                )

    if user.restrict_login_by_ip:
        allowed_ips = json.loads(user.allowed_login_ips or "[]")
        if allowed_ips:
            if not ip_matches_allowlist(client_ip, allowed_ips):
                log_action(
                    db, user, "login_blocked_ip", target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; allowed: {', '.join(allowed_ips)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request, "login.html",
                    {"error": f"Login is not permitted from your current IP address "
                              f"({client_ip or 'unknown'}).", "captcha": captcha_ctx},
                    status_code=403,
                )

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1
        threshold = app_settings.runtime.account_lockout_threshold
        locked_now = False
        if threshold and user.failed_login_attempts >= threshold:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=app_settings.runtime.account_lockout_minutes)
            locked_now = True
        if app_settings.runtime.log_failed_login_attempts:
            detail = f"IP {client_ip or 'unknown'}; attempt {user.failed_login_attempts}"
            if locked_now:
                detail += f"; account locked for {app_settings.runtime.account_lockout_minutes} minute(s)"
            log_action(db, user, "login_failed", target=user.username, detail=detail, success=False)
        db.commit()
        if locked_now:
            slack_notifications.notify(
                db, "account_lockout",
                f":lock: Account '{user.username}' locked out after {user.failed_login_attempts} failed login attempts "
                f"(IP {client_ip or 'unknown'}), locked for {app_settings.runtime.account_lockout_minutes} minute(s).",
            )
        elif user.failed_login_attempts == 3:
            # "Multiple failed login attempts" -- fired once the streak
            # first crosses 3 (not on every subsequent attempt below the
            # lockout threshold, which would spam a channel for an account
            # with no lockout configured at all) and again on lockout above.
            slack_notifications.notify(
                db, "failed_login_attempts",
                f":warning: {user.failed_login_attempts} failed login attempts for account '{user.username}' (IP {client_ip or 'unknown'}).",
            )
        return generic_error

    # Successful password check -- clear any lockout state so the next
    # failed streak (if any) starts fresh rather than compounding onto an
    # old one.
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    # --- Multi-Factor Authentication branching -----------------------------
    # See mfa.py's module docstring / the feature's plan for the full
    # design: a password-correct-but-MFA-pending state is held in SEPARATE
    # session keys (mfa_setup_required_user_id / mfa_pending_user_id) that
    # get_current_user() never reads -- login_user() (which sets
    # session["user_id"], the one key every permission dependency actually
    # checks) is simply not called until MFA is fully satisfied or the
    # effective policy says it doesn't apply. This is deliberately
    # evaluated BEFORE login_user() below, not after -- there's no
    # intermediate "logged in but MFA-pending" session state to accidentally
    # leave reachable.
    policy = mfa_module.effective_policy(user, db)
    if policy == "required" and not user.mfa_enabled:
        # Mandatory enrollment -- never bypassed by a trusted-device cookie
        # (see mfa.is_device_trusted's own docstring): a required-and-
        # unenrolled account has no completed second factor to trust a
        # device FOR yet.
        request.session["mfa_setup_required_user_id"] = user.id
        return RedirectResponse("/mfa/setup", status_code=303)
    if policy != "exempt":
        trusted_token = request.cookies.get(mfa_module.TRUSTED_DEVICE_COOKIE_NAME)
        device_trusted = bool(trusted_token) and mfa_module.is_device_trusted(user, trusted_token, db)
        if not device_trusted and (policy == "required" or (policy == "optional" and user.mfa_enabled)):
            request.session["mfa_pending_user_id"] = user.id
            return RedirectResponse("/mfa/verify", status_code=303)

    login_user(request, user, db)
    # Same log_action helper/naming convention as "login_failed"/
    # "login_blocked_ip" above, just for the success case -- powers User
    # Activity Analytics' Login Activity chart (routes/reports.py). Subject
    # to the same audit_retention_days pruning as every other AuditLog
    # entry (app_settings.prune_audit_log), no separate cleanup needed.
    # Starts accumulating from this deploy forward only -- there is no
    # retroactive login history, since successful logins were never
    # audit-logged before this.
    log_action(db, user, "login_success", target=user.username, success=True)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    logout_user(request)
    return RedirectResponse("/login", status_code=303)


# Generic response text for every outcome of a forgot-password SUBMISSION
# (unknown email, inactive/deleted account, SMTP misconfigured/send
# failure, real success) -- deliberately identical either way. Telling a
# submitter "no account with that email" would let anyone enumerate which
# emails have portal accounts at all; this app's login form already
# withholds the equivalent signal ("Invalid username or password", not
# "no such user"), so this matches that existing posture rather than
# introducing a new one.
_FORGOT_PASSWORD_GENERIC_MESSAGE = "If an account with that email address exists, we've sent instructions to reset the password."


@router.get("/forgot-password")
def forgot_password_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db) is not None:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "forgot_password.html", {"error": None, "message": None, "captcha": captcha.widget_context()})


@router.post("/forgot-password")
async def forgot_password_submit(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    captcha_ctx = captcha.widget_context()
    if _captcha_error(request, dict(await request.form())):
        return templates.TemplateResponse(
            request, "forgot_password.html",
            {"error": "Please complete the CAPTCHA challenge and try again.", "message": None, "captcha": captcha_ctx},
            status_code=400,
        )

    email = email.strip()
    if not mailer.is_valid_email(email):
        # The ONE case that's safe to be specific about -- "that's not a
        # valid email address" reveals nothing about which accounts exist,
        # unlike every other outcome below.
        return templates.TemplateResponse(
            request, "forgot_password.html",
            {"error": "Please enter a valid email address.", "message": None, "captcha": captcha_ctx},
            status_code=400,
        )

    # Case-insensitive match against User.email -- the column itself has
    # no uniqueness constraint (see models.py: "purely informational" when
    # it was added) and no normalization-on-write, so this compares
    # lowercased on both sides rather than assuming stored values are
    # already normalized.
    user = (
        db.query(User)
        .filter(User.email.isnot(None), User.deleted.is_(False), User.is_active.is_(True))
        .filter(func.lower(User.email) == email.lower())
        .first()
    )
    if user is not None:
        token = issue_password_reset_token(user, db)
        base_url = (app_settings.runtime.portal_url or str(request.base_url).rstrip("/")).rstrip("/")
        reset_url = f"{base_url}/reset-password?token={token}"
        try:
            mailer.send_password_reset_email(
                db=db, to_address=user.email, username=user.username, reset_url=reset_url,
                ttl_minutes=PASSWORD_RESET_TOKEN_TTL_MINUTES,
            )
            log_action(db, user, "password_reset_requested", target=user.username, success=True)
        except Exception as e:
            # Same fail-soft posture as every other outbound-email path in
            # this app (see mailer.send_admin_notification's own docstring)
            # -- an SMTP outage shouldn't turn into a 500, and specifically
            # here it must NOT change what the submitter sees (see
            # _FORGOT_PASSWORD_GENERIC_MESSAGE above), only what's audit-
            # logged for an admin to notice and fix.
            log_action(db, user, "password_reset_requested", target=user.username, detail=str(e), success=False)

    return templates.TemplateResponse(
        request, "forgot_password.html",
        {"error": None, "message": _FORGOT_PASSWORD_GENERIC_MESSAGE, "captcha": captcha_ctx},
    )


@router.get("/reset-password")
def reset_password_page(request: Request, token: str = "", db: Session = Depends(get_db)):
    if get_current_user(request, db) is not None:
        return RedirectResponse("/", status_code=303)
    user = get_user_by_reset_token(token, db) if token else None
    return templates.TemplateResponse(
        request, "reset_password.html",
        {"error": None, "token": token, "token_valid": user is not None},
    )


@router.post("/reset-password")
def reset_password_submit(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    # No CAPTCHA on this step (unlike /forgot-password above) -- the
    # unguessable, single-use, time-limited token itself is a far stronger
    # gate than a CAPTCHA could add: reaching this form at all already
    # requires possessing a link this app only ever sent to one specific
    # inbox, which a bot can't brute-force its way into regardless of
    # whether it can solve a challenge.
    user = get_user_by_reset_token(token, db)
    if user is None:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "This reset link is invalid or has expired. Request a new one below.", "token": token, "token_valid": False},
            status_code=400,
        )

    if new_password != confirm_password:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": "Those passwords don't match.", "token": token, "token_valid": True},
            status_code=400,
        )

    # Same complexity policy (and reuse check) as every other path that
    # ever sets User.password_hash (account creation, admin reset, self-
    # service change) -- see routes/users.py's _valid_password /
    # _check_password_reuse docstrings.
    from .users import _check_password_reuse, _record_password_history, _valid_password

    try:
        _valid_password(new_password)
        _check_password_reuse(user, new_password)
    except ValueError as e:
        return templates.TemplateResponse(
            request, "reset_password.html",
            {"error": str(e), "token": token, "token_valid": True},
            status_code=400,
        )

    _record_password_history(user)
    user.password_hash = hash_password(new_password)
    # A self-service reset is exactly as strong a proof of "the account
    # holder is in control right now" as a self-service change -- clears
    # the same flag update_my_profile does, not just must_reset_password's
    # narrower original set-by-admin case (see models.py's docstring).
    user.must_reset_password = False
    user.failed_login_attempts = 0
    user.locked_until = None
    clear_password_reset_token(user, db)
    log_action(db, user, "password_reset_completed", target=user.username, success=True)

    return templates.TemplateResponse(
        request, "login.html",
        {"error": None, "message": "Your password has been reset. You can now log in.", "captcha": captcha.widget_context()},
    )
