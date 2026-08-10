from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import AuditLog, User
from ..permissions import require_permission, require_permission_any_scope

router = APIRouter(prefix="/api/status", tags=["status"])

require_admin = require_permission("audit_log", "manage")  # former auth.require_admin, see permissions.py
# Every-client status/session data -- any_scope so VPN Self-Service User
# (view=True on "vpn_profiles" but scoped "own") can't see other users'
# connection activity through these. See clients.py's _require_client_viewer
# for the same pattern.
_require_status_viewer = require_permission_any_scope("vpn_profiles", "view")


@router.get("")
def get_connected(_: User = Depends(_require_status_viewer)):
    try:
        return cli.get_status_connected_snapshot()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/all")
def get_all(_: User = Depends(_require_status_viewer)):
    try:
        return cli.get_status_all_snapshot()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/rejected")
def get_rejected(limit: int = Query(20, ge=1, le=500), _: User = Depends(_require_status_viewer)):
    try:
        return cli.get_status_rejected_snapshot(limit)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@router.get("/session-history")
def get_session_history(limit: int = Query(20, ge=1, le=500), _: User = Depends(_require_status_viewer)):
    """Connection History page. Same access level as /rejected (any
    logged-in user, admin or viewer) -- this is read-only historical data,
    not a mutating endpoint, matching Diagnostics' own require_user gate.
    Filtering by client name is done client-side against this same window,
    same as Diagnostics' rejected-connections filters (see that page's
    populateRejectedFilters/renderRejectedTable for the pattern this
    mirrors)."""
    try:
        return cli.status_session_history(limit)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


# Deliberately outside the /api/status prefix -- this is a cross-cutting
# summary (status + revoked clients), not purely a "status" resource. Kept
# in this module since it's a thin composition of the functions above.
dashboard_router = APIRouter(prefix="/api", tags=["status"])


_require_dashboard_viewer = require_permission_any_scope("dashboard", "view")


@dashboard_router.get("/dashboard")
def get_dashboard(_: User = Depends(_require_dashboard_viewer)):
    """Everything the dashboard page needs in one round-trip, instead of 4
    separate fetches -- each underlying script call is still individually
    cached/serialized (see cli_wrapper), this just saves HTTP overhead and
    gives the frontend one loading state to manage instead of four.

    Serves the periodically-background-refreshed snapshot (near-instant)
    rather than computing dashboard_summary() fresh per request -- see
    cli_wrapper.py's get_dashboard_snapshot()/refresh_dashboard_snapshot()
    and main.py's lifespan for the refresh loop. Falls back to a direct
    (blocking) call only if the background loop hasn't completed its first
    tick yet -- e.g. the very first request right after a fresh restart --
    so a request is never served nothing."""
    snapshot = cli.get_dashboard_snapshot()
    if snapshot is not None:
        return snapshot
    try:
        return cli.refresh_dashboard_snapshot()
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)


@dashboard_router.get("/audit")
def get_audit_log(limit: int = Query(20, ge=1, le=200), admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Most recent audit-log entries, newest first -- admin-only, since this
    is the same accountability trail as the (also admin-only) audit-log
    retention setting on the Settings page. Powers the Dashboard's Recent
    Activity section; not cached like the CLI-backed endpoints above since
    it's a cheap indexed DB query, not a subprocess call."""
    entries = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "username": e.username,
            "action": e.action,
            "target": e.target,
            "detail": e.detail,
            "success": e.success,
        }
        for e in entries
    ]
