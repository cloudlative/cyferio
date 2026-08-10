import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .. import geoip
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
        request, "login.html", {"error": "Invalid username or password."}, status_code=401,
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

    # Country/IP restriction checks run BEFORE password verification (see
    # this task's own "Authentication Flow Requirements": a request from a
    # blocked country/IP should never reach password-hashing at all) --
    # but they still need this user's OWN row to know what to check against
    # (restrictions are per-user, see models.py), so a lookup happens
    # first. That is a plain SELECT, not "authentication logic" -- the
    # actual sensitive/expensive step this ordering avoids is
    # verify_password's bcrypt hash comparison, which only ever runs after
    # both checks below pass.
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
                    {"error": "Login is not permitted from your current country."},
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
                    {"error": "Login is not permitted from your current IP address."},
                    status_code=403,
                )

    if not verify_password(password, user.password_hash):
        return generic_error

    login_user(request, user, db)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    logout_user(request)
    return RedirectResponse("/login", status_code=303)
