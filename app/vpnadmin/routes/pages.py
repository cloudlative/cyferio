from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..app_settings import apply_settings_globals
from ..auth import get_current_user
from ..models import Role, User

router = APIRouter()
templates = Jinja2Templates(directory="vpnadmin/templates")
# Runtime settings (branding etc, admin-editable via the Settings page) are
# rendered in many templates (sidebar header, login page, footer) --
# exposing them as a Jinja global here means every template gets them for
# free without every route handler having to thread them through its own
# context dict. See app_settings.py's docstring for the full picture.
apply_settings_globals(templates)


def _ctx(user: User, **extra) -> dict:
    return {
        "user": user,
        "is_admin": user.role == Role.admin,
        # Client/MAC management (add/revoke/restore/purge a client, MAC
        # add/remove, email .ovpn) -- admin or editor. Everything else
        # admin-gated in templates keeps using is_admin.
        "can_manage_clients": user.role in (Role.admin, Role.editor),
        **extra,
    }


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


@router.get("/health")
def health_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "health.html", _ctx(user))


@router.get("/connection-history")
def connection_history_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "connection_history.html", _ctx(user))


@router.get("/users")
def users_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "users.html", _ctx(user))


@router.get("/users/activity")
def users_activity_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "users_activity.html", _ctx(user))


@router.get("/profile")
def profile_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "profile.html", _ctx(user))


@router.get("/teams")
def teams_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "teams.html", _ctx(user))


@router.get("/settings")
def settings_page(request: Request, user: User | None = Depends(get_current_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if user.role != Role.admin:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "settings.html", _ctx(user))
