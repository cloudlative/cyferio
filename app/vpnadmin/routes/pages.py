from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..app_settings import apply_settings_globals
from ..auth import get_current_user
from ..db import get_db
from ..models import User
from ..permissions import has_permission, has_permission_any_scope

router = APIRouter()
templates = Jinja2Templates(directory="vpnadmin/templates")
# Runtime settings (branding etc, admin-editable via the Settings page) are
# rendered in many templates (sidebar header, login page, footer) --
# exposing them as a Jinja global here means every template gets them for
# free without every route handler having to thread them through its own
# context dict. See app_settings.py's docstring for the full picture.
apply_settings_globals(templates)


def _ctx(user: User, db: Session, **extra) -> dict:
    return {
        "user": user,
        # "is_admin" name kept for template compatibility -- now means
        # "can manage user accounts" (dynamic RBAC's require_permission
        # ("users", "manage")) rather than a hardcoded role check.
        "is_admin": has_permission(db, user, "users", "manage"),
        "can_manage_roles": has_permission(db, user, "roles", "manage"),
        # Client/MAC management (add/revoke/restore/purge a client, MAC
        # add/remove, email .ovpn) -- former require_client_manager scope,
        # now require_permission("vpn_profiles", "execute").
        "can_manage_clients": has_permission(db, user, "vpn_profiles", "execute"),
        # Nav visibility for "My VPN Profile" -- shown to any account with a
        # linked profile, not just the "User" self-service role (an editor/admin who
        # happens to also own a personal device, e.g. from the migration,
        # benefits from it too), and hidden for everyone else rather than
        # gated by role alone.
        "has_own_vpn_profile": user.vpn_profile_link is not None,
        # Nav-visibility flags for the "System Administration"-flavored
        # pages that the "User" self-service role must not see (own-scoped on
        # vpn_profiles/dashboard/health doesn't grant these) -- server-side
        # routes above already enforce this via has_permission_any_scope;
        # these just keep the sidebar from showing dead links.
        "can_view_dashboard": has_permission_any_scope(db, user, "dashboard", "view"),
        "can_view_clients": has_permission_any_scope(db, user, "vpn_profiles", "view"),
        "can_view_health": has_permission_any_scope(db, user, "health", "view"),
        # Phase 1 Python service layer's web-triggered install/uninstall
        # page (see routes/openvpn_install.py) -- own object, admin-only by
        # default (see permissions.py's OBJECTS comment for why).
        "can_manage_openvpn_install": has_permission(db, user, "openvpn_install", "execute"),
        **extra,
    }


@router.get("/")
def dashboard(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    # "System Administration Page" from the "User" self-service role's perspective
    # (aggregate counts across every client) -- any_scope excludes it, same
    # as the /api/dashboard route it reads from.
    if not has_permission_any_scope(db, user, "dashboard", "view"):
        return RedirectResponse("/my-vpn-profile" if user.vpn_profile_link is not None else "/profile", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", _ctx(user, db))


@router.get("/clients")
def clients_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission_any_scope(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "clients.html", _ctx(user, db))


@router.get("/clients/revoked")
def revoked_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission_any_scope(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "revoked.html", _ctx(user, db))


@router.get("/diagnostics")
def diagnostics_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission_any_scope(db, user, "health", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "diagnostics.html", _ctx(user, db))


@router.get("/health")
def health_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission_any_scope(db, user, "health", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "health.html", _ctx(user, db))


@router.get("/connection-history")
def connection_history_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission_any_scope(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "connection_history.html", _ctx(user, db))


@router.get("/users")
def users_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(db, user, "users", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "users.html", _ctx(user, db))


@router.get("/users/activity")
def users_activity_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(db, user, "audit_log", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "users_activity.html", _ctx(user, db))


@router.get("/profile")
def profile_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "profile.html", _ctx(user, db))


@router.get("/teams")
def teams_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(db, user, "teams", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "teams.html", _ctx(user, db))


@router.get("/settings")
def settings_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(db, user, "settings", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "settings.html", _ctx(user, db))


@router.get("/my-vpn-profile")
def my_vpn_profile_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "my_vpn_profile.html", _ctx(user, db))


@router.get("/roles")
def roles_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(db, user, "roles", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "roles.html", _ctx(user, db))


@router.get("/openvpn-install")
def openvpn_install_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not has_permission(db, user, "openvpn_install", "execute"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "openvpn_install.html", _ctx(user, db))


