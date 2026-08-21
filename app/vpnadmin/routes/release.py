"""Release Availability Indicator/Popup -- the lazy, on-demand counterpart
to release_check.py's caching layer (see that module's docstring, and
main.py's own note on why this is deliberately NOT an eager background
loop). The header indicator (base.html/static/app.js) polls GET
/api/release/status on a timer while an admin is logged in; that route
below is what actually triggers a refresh once the cached result goes
stale, and auto-files the Upgrade Assignment Workflow ticket the first
time a given release is seen.

Admin-only, matching this feature's "err toward admin-only visibility"
decision for the indicator itself -- reuses the "settings" object's "view"
action (any admin-capable role that can see Settings can see this; there's
no separate "release_check" RBAC object, same reasoning as the Slack
section reusing "settings" rather than inventing a new one)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import release_check
from ..config import settings as env_settings
from ..db import get_db
from ..models import User
from ..permissions import require_permission

router = APIRouter(prefix="/api/release", tags=["release"])

require_viewer = require_permission("settings", "view")


def _serialize(result: dict) -> dict:
    return {
        "installed_version": env_settings.APP_VERSION,
        "latest_version": result.get("latest_tag"),
        "status": result.get("status", "up_to_date"),
        "release_name": result.get("latest_name"),
        "release_notes": result.get("latest_body"),
        "release_url": result.get("latest_html_url"),
        "published_at": result.get("published_at"),
        "checked_at": result["checked_at"].isoformat() if result.get("checked_at") else None,
        "error": result.get("error"),
    }


@router.get("/status")
def get_release_status(_: User = Depends(require_viewer), db: Session = Depends(get_db)):
    result = release_check.check_for_new_release()
    if result["status"] in ("update_available", "critical_update"):
        # Best-effort, idempotent per release tag (see file_upgrade_ticket's
        # own docstring) -- a status check must never fail over the
        # ticket-filing side effect.
        try:
            release_check.file_upgrade_ticket(db)
        except Exception:
            pass
    return _serialize(result)
