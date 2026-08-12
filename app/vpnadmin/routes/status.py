from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import AuditLog, User, VpnProfileLink
from ..permissions import require_permission, require_permission_any_scope

router = APIRouter(prefix="/api/status", tags=["status"])

require_admin = require_permission("audit_log", "manage")  # former auth.require_admin, see permissions.py
# Every-client status/session data -- any_scope so "User" (self-service role)
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
def get_session_history(
    limit: int = Query(20, ge=1, le=500),
    client: str | None = Query(None, description="Server-side filter to one VPN client's own session history"),
    _: User = Depends(_require_status_viewer),
    db: Session = Depends(get_db),
):
    """Connection History page. Same access level as /rejected (any
    logged-in user, admin or viewer) -- this is read-only historical data,
    not a mutating endpoint, matching Diagnostics' own require_user gate.
    Filtering by client name is, by default, done client-side against this
    same window, same as Diagnostics' rejected-connections filters (see
    that page's populateRejectedFilters/renderRejectedTable for the pattern
    this mirrors) -- `client` is an OPT-IN server-side filter added for
    Per-User Analytics (routes/reports.py), which needs one user's own
    history without shipping the full 500-row window just to filter one
    name out of it; connection_history.html's own page-wide search still
    uses the unfiltered fetch + client-side filtering as before.

    Each row is enriched here with the linked portal user's identity
    (`portal_username`/`portal_display_name`, both null if this VPN client
    was never linked to a portal account) so the page's search box can match
    against a portal user's name/username, not just the raw VPN profile
    name -- this doesn't widen this endpoint's own access level, since
    any_scope vpn_profiles/view already exposes every client's session
    history here, just not who it's linked to."""
    try:
        rows = cli.status_session_history(limit, client)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)

    links = (
        db.query(VpnProfileLink.vpn_client_name, User.username, User.first_name, User.last_name)
        .join(User, User.id == VpnProfileLink.user_id)
        .all()
    )
    by_client = {
        client_name: {"portal_username": username, "portal_display_name": f"{first} {last}".strip() if last else first}
        for client_name, username, first, last in links
    }
    for row in rows:
        link = by_client.get(row.get("client"))
        row["portal_username"] = link["portal_username"] if link else None
        row["portal_display_name"] = link["portal_display_name"] if link else None
    return rows


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
