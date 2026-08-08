from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import get_current_user
from ..models import Role, User

router = APIRouter()
templates = Jinja2Templates(directory="vpnadmin/templates")


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
