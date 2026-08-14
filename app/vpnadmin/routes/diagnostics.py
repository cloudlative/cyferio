from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from ..cli_wrapper import ScriptError
from ..db import get_db, get_db_engine_info
from ..models import User
from ..permissions import require_permission_any_scope

# Reused rather than duplicated -- see that function's own docstring for
# why this is deliberately an admin-wide view, unlike routes/notifications.py's
# self-scoped list_my_notifications().
from .reports import _recent_quota_warnings

router = APIRouter(prefix="/api", tags=["diagnostics"])

# System-administration data (PKI/MAC-db consistency, stale entries) --
# any_scope so "User" (self-service role) is excluded, same as clients.py's
# _require_client_viewer / status.py's _require_status_viewer.
_require_diagnostics_viewer = require_permission_any_scope("health", "view")


@router.get("/check")
def get_check(_: User = Depends(_require_diagnostics_viewer)):
    """This checks PKI-vs-MAC-db consistency (see check_consistency), not
    the app's own SQL database -- db_engine is included here anyway (rather
    than a separate endpoint) purely because the Health page's card
    happens to be titled "MAC-DB Consistency" and that's the natural spot
    for "which database is this app itself using" to be visible at a
    glance."""
    try:
        result = dict(cli.get_check_consistency_snapshot())
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
    result["db_engine"] = get_db_engine_info()
    return result


@router.get("/lint-db")
def get_lint_db(_: User = Depends(_require_diagnostics_viewer)):
    try:
        return cli.get_lint_db_snapshot()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/diagnostics/quota-warnings")
def get_quota_warnings(
    limit: int = Query(50, ge=1, le=200),
    _: User = Depends(_require_diagnostics_viewer),
    db: Session = Depends(get_db),
):
    """Admin-wide bandwidth-quota warning/critical rows, for Diagnostics'
    "Active Quota Warnings" panel -- makes Diagnostics the single place to
    see every active policy/restriction violation, per that page's own
    "central place for policy and compliance violations" goal, rather than
    quota warnings staying visible only to the affected user's own
    notification bell. Same "health"/view any-scope gate as everything
    else on this page -- see _require_diagnostics_viewer above."""
    return _recent_quota_warnings(db, limit)
