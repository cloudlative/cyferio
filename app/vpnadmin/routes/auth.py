import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import app_settings, geoip
from ..app_settings import apply_settings_globals
from ..audit import log_action
from ..auth import get_current_user, login_user, logout_user, verify_password
from ..client_ip import get_client_ip, ip_matches_allowlist
from ..db import get_db
from ..models import User

router = APIRouter()
templates = Jinja2Templates(directory="vpnadmin/templates")
apply_settings_globals(templates)


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db) is not None:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    generic_error = templates.TemplateResponse(
        request,
        "login.html",
        {"error": "Invalid username or password."},
        status_code=401,
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
    if app_settings.runtime.maintenance_mode and user.role_slug not in ("admin", "super_admin"):
        message = app_settings.runtime.maintenance_message or "This application is temporarily down for maintenance. Please try again shortly."
        return templates.TemplateResponse(request, "login.html", {"error": message}, status_code=503)

    # Account lockout (Settings -> Security): a threshold of 0/None disables
    # this entirely (the pre-existing behavior). locked_until is set once
    # failed_login_attempts reaches the threshold (see the wrong-password
    # branch further down) and simply expires on its own -- no admin unlock
    # action needed for the common case.
    if user.locked_until and user.locked_until > datetime.now(UTC):
        remaining_minutes = max(1, int((user.locked_until - datetime.now(UTC)).total_seconds() // 60) + 1)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": f"Too many failed login attempts. Try again in about {remaining_minutes} minute(s)."},
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
                    db,
                    user,
                    "login_blocked_country",
                    target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; detected country {country or 'unknown'}; allowed: {', '.join(allowed_countries)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {"error": f"Login is not permitted from your current country ({country or 'unknown'}, IP {client_ip or 'unknown'})."},
                    status_code=403,
                )

    if user.restrict_login_by_city:
        allowed_cities = json.loads(user.allowed_login_cities or "[]")
        if allowed_cities:
            city = geoip.lookup_city(client_ip)
            allowed_lower = {c.lower() for c in allowed_cities}
            if (city or "").lower() not in allowed_lower:
                log_action(
                    db,
                    user,
                    "login_blocked_city",
                    target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; detected city {city or 'unknown'}; allowed: {', '.join(allowed_cities)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {"error": f"Login is not permitted from your current city ({city or 'unknown'}, IP {client_ip or 'unknown'})."},
                    status_code=403,
                )

    if user.restrict_login_by_asn:
        allowed_asns = json.loads(user.allowed_login_asns or "[]")
        if allowed_asns:
            asn = geoip.lookup_asn(client_ip)
            asn_label = f"AS{asn}" if asn is not None else None
            if asn_label not in allowed_asns:
                log_action(
                    db,
                    user,
                    "login_blocked_asn",
                    target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; detected ASN {asn_label or 'unknown'}; allowed: {', '.join(allowed_asns)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {"error": f"Login is not permitted from your current network ({asn_label or 'unknown'}, IP {client_ip or 'unknown'})."},
                    status_code=403,
                )

    if user.restrict_login_by_ip:
        allowed_ips = json.loads(user.allowed_login_ips or "[]")
        if allowed_ips:
            if not ip_matches_allowlist(client_ip, allowed_ips):
                log_action(
                    db,
                    user,
                    "login_blocked_ip",
                    target=user.username,
                    detail=f"IP {client_ip or 'unknown'}; allowed: {', '.join(allowed_ips)}",
                    success=False,
                )
                return templates.TemplateResponse(
                    request,
                    "login.html",
                    {"error": f"Login is not permitted from your current IP address ({client_ip or 'unknown'})."},
                    status_code=403,
                )

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1
        threshold = app_settings.runtime.account_lockout_threshold
        locked_now = False
        if threshold and user.failed_login_attempts >= threshold:
            user.locked_until = datetime.now(UTC) + timedelta(minutes=app_settings.runtime.account_lockout_minutes)
            locked_now = True
        if app_settings.runtime.log_failed_login_attempts:
            detail = f"IP {client_ip or 'unknown'}; attempt {user.failed_login_attempts}"
            if locked_now:
                detail += f"; account locked for {app_settings.runtime.account_lockout_minutes} minute(s)"
            log_action(db, user, "login_failed", target=user.username, detail=detail, success=False)
        db.commit()
        return generic_error

    # Successful password check -- clear any lockout state so the next
    # failed streak (if any) starts fresh rather than compounding onto an
    # old one.
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

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
