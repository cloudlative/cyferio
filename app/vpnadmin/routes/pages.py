from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from . import openvpn_install
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


def _password_reset_redirect(user: User, request: Request) -> RedirectResponse | None:
    """Every page route below (except /change-password itself) calls this
    right after its own `if user is None` check -- forces a redirect to
    /change-password until the account holder has proven they know the
    current password via a successful self-service change (see
    models.py's User.must_reset_password docstring for the full list of
    what sets/clears this flag: every newly-created account, an admin's
    manual password reset, vs. cleared only by update_my_profile).
    Deliberately per-route (matching this file's existing `if user is
    None: redirect` convention, repeated in every route rather than
    factored into shared middleware -- see the architecture note in the
    PR this shipped with) rather than a global Starlette middleware, which
    would be the only new access-control pattern in a codebase that
    otherwise does every gate via FastAPI Depends()."""
    if user.must_reset_password and request.url.path != "/change-password":
        return RedirectResponse("/change-password", status_code=303)
    return None


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
        "can_view_reports": has_permission_any_scope(db, user, "reports", "view"),
        # Database Reporting -- a stricter, separate gate than "reports"
        # itself (see permissions.py's OBJECTS entry for "db_reporting"),
        # so Reports' own nav link/page stays visible under "can_view_reports"
        # even to accounts that can't see this specific section within it.
        "can_view_db_reporting": has_permission_any_scope(db, user, "db_reporting", "view"),
        # Phase 1 Python service layer's web-triggered install/uninstall
        # page (see routes/openvpn_install.py) -- own object, admin-only by
        # default (see permissions.py's OBJECTS comment for why). Also
        # bootstrap-admin-only (see routes/openvpn_install.py's module
        # docstring) -- no role/permission grant opens this up further, so
        # the nav link stays hidden from every other account too.
        "can_manage_openvpn_install": has_permission(db, user, "openvpn_install", "execute") and user.is_bootstrap_admin,
        **extra,
    }


@router.get("/")
def dashboard(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
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
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission_any_scope(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "clients.html", _ctx(user, db))


@router.get("/clients/revoked")
def revoked_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission_any_scope(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "revoked.html", _ctx(user, db))


@router.get("/diagnostics")
def diagnostics_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission_any_scope(db, user, "health", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "diagnostics.html", _ctx(user, db))


@router.get("/health")
def health_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission_any_scope(db, user, "health", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "health.html", _ctx(user, db))


@router.get("/reports")
def reports_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission_any_scope(db, user, "reports", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "reports.html", _ctx(user, db))


@router.get("/connection-history")
def connection_history_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission_any_scope(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "connection_history.html", _ctx(user, db))


@router.get("/users")
def users_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission(db, user, "users", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "users.html", _ctx(user, db))


@router.get("/users/activity")
def users_activity_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission(db, user, "audit_log", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "users_activity.html", _ctx(user, db))


@router.get("/profile")
def profile_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(request, "profile.html", _ctx(user, db))


@router.get("/teams")
def teams_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission(db, user, "teams", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "teams.html", _ctx(user, db))


@router.get("/settings")
def settings_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission(db, user, "settings", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "settings.html", _ctx(user, db))


@router.get("/my-vpn-profile")
def my_vpn_profile_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "my_vpn_profile.html", _ctx(user, db))


@router.get("/my-reports")
def my_reports_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    # Same gate as /my-vpn-profile above -- plain has_permission (not
    # any_scope), since this is inherently "own" data by construction (the
    # backing endpoint, GET /api/me/vpn-profile/report, never takes an id
    # param -- see me_vpn.py's module docstring). No linked profile means
    # nothing to report, so fall back to /my-vpn-profile, which already
    # handles that same "no profile yet" case with its own empty state.
    if not has_permission(db, user, "vpn_profiles", "view"):
        return RedirectResponse("/", status_code=303)
    if user.vpn_profile_link is None:
        return RedirectResponse("/my-vpn-profile", status_code=303)
    return templates.TemplateResponse(request, "my_reports.html", _ctx(user, db))


@router.get("/roles")
def roles_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    if not has_permission(db, user, "roles", "manage"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "roles.html", _ctx(user, db))


@router.get("/openvpn-install")
def openvpn_install_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    # Bootstrap-admin-only, not just openvpn_install/execute -- see
    # routes/openvpn_install.py's module docstring for why.
    if not has_permission(db, user, "openvpn_install", "execute") or not user.is_bootstrap_admin:
        return RedirectResponse("/", status_code=303)
    # Step-up re-auth: rendered even when not yet elevated -- the template
    # shows a "confirm your password" gate card instead of the real
    # Status/Install/Uninstall content in that case (see openvpn_install.py's
    # is_elevated()/ELEVATED_TTL_MINUTES).
    needs_verification = not openvpn_install.is_elevated(request)
    return templates.TemplateResponse(
        request, "openvpn_install.html",
        _ctx(
            user, db, needs_verification=needs_verification,
            elevated_ttl_minutes=openvpn_install.ELEVATED_TTL_MINUTES,
        ),
    )


@router.get("/faq")
def faq_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    # No permission gate beyond being logged in -- every account, any role,
    # should be able to reach this (it's written for the least technical
    # user in the building, and gating it behind a permission would be
    # exactly backwards: the self-service "User" role is the audience most
    # likely to need it).
    if user is None:
        return RedirectResponse("/login", status_code=303)
    redirect = _password_reset_redirect(user, request)
    if redirect is not None:
        return redirect
    return templates.TemplateResponse(request, "faq.html", _ctx(user, db))


@router.get("/change-password")
def change_password_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    # Deliberately does NOT call _password_reset_redirect -- this IS the
    # destination it redirects to; calling it here would be a no-op at
    # best (the helper already excludes this exact path) and confusing to
    # read at worst. No permission gate beyond being logged in -- every
    # account, any role, must be able to reach this page regardless of
    # what else they can/can't do, or a locked-out account would have no
    # way to ever unlock itself.
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "change_password.html", _ctx(user, db))


