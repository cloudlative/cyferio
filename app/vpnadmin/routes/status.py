from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import app_settings
from .. import cli_wrapper as cli
from .. import policy_store
# Aliased for the same reason main.py aliases this import -- routes/health.py
# (the API router module) and vpnadmin/health.py (this data-gathering
# module) share the bare name "health"; this file doesn't import
# routes/health.py directly today, but aliasing here too keeps the
# convention consistent and avoids a silent collision if that ever changes.
from .. import health as health_data
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import AuditLog, User, VpnProfileLink
from ..permissions import has_permission, require_permission, require_permission_any_scope
from .reports import _active_quota_warnings, _load_rows

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


@dashboard_router.get("/dashboard/critical-devices")
def get_critical_devices_widget(_: User = Depends(_require_dashboard_viewer), db: Session = Depends(get_db)):
    """VPN Device Availability Monitoring's "Critical VPN Devices" widget --
    Online/Offline/Warning counts plus a table of every monitored device,
    read from device_monitoring.widget_snapshot() (VpnDeviceStatus rows,
    at most one background-check-interval stale -- same trade-off as the
    rest of this dashboard). Same viewer gate as GET /api/dashboard itself
    -- anyone who can see the dashboard can see this widget; configuring
    monitoring still requires vpn_profiles execute (routes/clients.py)."""
    from .. import device_monitoring
    return device_monitoring.widget_snapshot(db)


def _health_status_summary() -> dict:
    """Rolls up the 4 independent health.py checks into one ok/degraded
    signal for the Dashboard's System Insights card -- no aggregate
    concept exists in health.py itself (confirmed: each of get_app_health/
    get_database_health/get_host_health/get_traefik_health is fully
    independent), so this mirrors health.html's own per-check badge logic
    (okBadge()/unavailableBadge()) just combined into one summary instead
    of 4 separate badges. "Unavailable" (host/traefik health data simply
    not reachable, e.g. local dev with no traefik container) is NOT
    counted as a failure here, same distinction health.html's own badges
    already draw -- only a check that ran and reported a real problem
    counts against the rollup."""
    failing = []
    try:
        if not health_data.get_database_health().get("ok"):
            failing.append("database")
    except Exception:
        failing.append("database")
    try:
        traefik = health_data.get_traefik_health()
        if traefik.get("available"):
            router_issues = any(r.get("status") != "enabled" or r.get("errors") for r in traefik.get("routers", []))
            if not traefik.get("ping_ok") or router_issues:
                failing.append("traefik")
    except Exception:
        pass  # traefik health is a bonus signal -- an error reaching it isn't itself a reported failure
    return {"ok": len(failing) == 0, "failing_checks": failing}


def _parseable_timestamp(iso: str | None) -> bool:
    if not iso:
        return False
    try:
        datetime.fromisoformat(iso)
        return True
    except ValueError:
        return False


def _is_today(iso: str | None) -> bool:
    if not iso:
        return False
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).date() == datetime.now(timezone.utc).date()


def _has_any_restriction(policy: dict) -> bool:
    return bool(
        policy.get("allowed_os") or policy.get("bandwidth_monthly_gb")
        or policy.get("allowed_countries") or policy.get("allowed_cities")
        or policy.get("allowed_asns") or policy.get("allowed_ips")
    )


@dashboard_router.get("/dashboard/overview")
def get_dashboard_overview(user: User = Depends(_require_dashboard_viewer), db: Session = Depends(get_db)):
    """A second, DB-backed dashboard aggregation, complementary to GET
    /dashboard above (which is a pure subprocess-snapshot cache with no DB
    session at all) -- computed fresh per request rather than
    background-cached, since every piece here is either a cheap indexed DB
    query or a call already cached one layer down (cli_wrapper's own
    _script_lock/cache). Reuses existing aggregation wherever it already
    exists (routes.reports._load_rows/_active_quota_warnings) rather than
    duplicating that math."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(days=7)

    users_total = db.query(User).filter(User.deleted.is_(False)).count()
    users_active = db.query(User).filter(User.deleted.is_(False), User.is_active.is_(True)).count()
    users_disabled = db.query(User).filter(User.deleted.is_(False), User.is_active.is_(False)).count()
    users_recently_created = db.query(User).filter(User.deleted.is_(False), User.created_at >= recent_cutoff).count()

    rows = _load_rows(db)
    warning_pct = app_settings.runtime.quota_notify_warning_pct
    critical_pct = app_settings.runtime.quota_notify_critical_pct
    users_near_quota = sum(1 for r in rows if r["pct_used"] is not None and r["pct_used"] >= warning_pct)
    profiles_exceeding_threshold = sum(1 for r in rows if r["pct_used"] is not None and r["pct_used"] >= critical_pct)

    try:
        connected = cli.status_connected()
    except ScriptError:
        connected = []
    connected_names = {c.get("name") for c in connected if c.get("name")}
    linked_names = {name for (name,) in db.query(VpnProfileLink.vpn_client_name).all()}
    users_currently_connected = len(connected_names & linked_names)

    try:
        clients = cli.list_clients()
    except ScriptError:
        clients = []
    try:
        revoked = cli.list_revoked()
    except ScriptError:
        revoked = []
    policies = policy_store.get_all_policies()

    try:
        session_history = cli.status_session_history(500)
    except ScriptError:
        session_history = []
    try:
        rejected = cli.get_status_rejected_snapshot(500)
    except ScriptError:
        rejected = []

    connections_today = sum(1 for r in session_history if _is_today(r.get("connected_at")))
    failed_connections_today = sum(1 for r in rejected if _is_today(r.get("timestamp")))

    top_consumers = sorted(rows, key=lambda r: r["used_gb"], reverse=True)[:5]
    durations = [r["duration_seconds"] for r in session_history if r.get("duration_seconds")]
    session_counts = Counter(r["client"] for r in session_history if r.get("client"))

    recent_alerts = None
    if has_permission(db, user, "audit_log", "manage"):  # same gate as GET /api/audit above
        entries = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()
        recent_alerts = [
            {"timestamp": e.timestamp.isoformat() if e.timestamp else None, "username": e.username,
             "action": e.action, "target": e.target, "success": e.success}
            for e in entries
        ]

    return {
        "users": {
            "total": users_total,
            "active": users_active,
            "disabled": users_disabled,
            "recently_created": users_recently_created,
            "near_quota": users_near_quota,
            "currently_connected": users_currently_connected,
        },
        "vpn_profiles": {
            "total": len(clients),
            "active": sum(1 for c in clients if c.get("in_db")),
            "revoked": len(revoked),
            "with_restrictions": sum(1 for p in policies.values() if _has_any_restriction(p)),
            "exceeding_threshold": profiles_exceeding_threshold,
        },
        "vpn_activity": {
            "active_sessions": len(connected),
            "connections_today": connections_today,
            "failed_connections_today": failed_connections_today,
            "top_bandwidth_consumers": [{"username": r["username"], "used_gb": r["used_gb"]} for r in top_consumers],
            "avg_session_duration_seconds": round(sum(durations) / len(durations), 1) if durations else None,
            "most_active_clients": [{"vpn_client_name": name, "session_count": count} for name, count in session_counts.most_common(5)],
        },
        "system_insights": {
            "recent_alerts": recent_alerts,  # null (not []) if the caller lacks audit_log:manage -- distinguishes "no permission" from "no alerts"
            # vpn-status.py's rejected-connections snapshot legitimately
            # includes non-timestamped "unknown"/"n/a" aggregate entries
            # (e.g. a rolled-up bucket for a name/MAC seen many times) mixed
            # in with real per-attempt rows that DO have a real ISO
            # timestamp -- sorting naively by the raw string would put
            # "unknown" above every real "2026-..." timestamp (plain
            # alphabetical: 'u' > '2'), burying genuinely recent violations
            # under bogus "most recent" entries. Only rows with a real,
            # parseable timestamp are eligible for this "recent" list at
            # all -- the unparseable aggregate rows are simply excluded
            # here (they have no real "when" to rank against), not just
            # sorted last.
            "recent_violations": [
                {"timestamp": r.get("timestamp"), "claimed_name": r.get("claimed_name"), "reason": r.get("reason")}
                for r in sorted(
                    (r for r in rejected if _parseable_timestamp(r.get("timestamp"))),
                    key=lambda r: r["timestamp"], reverse=True,
                )
            ][:10],
            "quota_warnings": _active_quota_warnings(db, 5),
            "health_status": _health_status_summary(),
        },
    }


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
