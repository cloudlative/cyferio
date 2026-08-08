from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import get_current_user
from ..config import apply_branding_globals
from ..models import Role, User

router = APIRouter()
templates = Jinja2Templates(directory="vpnadmin/templates")
# Branding is env-driven (see config.py) but rendered in many templates
# (sidebar header, login page, footer) -- exposing it as Jinja globals here
# means every template gets it for free without every route handler having
# to thread it through its own context dict.
apply_branding_globals(templates)


def _ctx(user: User, **extra) -> dict:
    return {"user": user, "is_admin": user.role == Role.admin, **extra}


@router.get("/")
def dashboard(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", _ctx(user))


@router.get("/clients")
def clients_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "clients.html", _ctx(user))


@router.get("/clients/revoked")
def revoked_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "revoked.html", _ctx(user))


@router.get("/diagnostics")
def diagnostics_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "diagnostics.html", _ctx(user))


@router.get("/users")
def users_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "users.html", _ctx(user))


@router.get("/profile")
def profile_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "profile.html", _ctx(user))


@router.get("/teams")
def teams_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "teams.html", _ctx(user))
