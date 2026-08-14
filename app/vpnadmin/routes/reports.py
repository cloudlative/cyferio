"""Bandwidth reporting -- per-user, per-team, and global rollups over the
same two sources every other bandwidth feature in this app already reads:
policy_store.get_all_policies() (quotas) and policy_store.get_all_usage()
(this-month bytes used, written by host-scripts/openvpn-client-disconnect.py
on every session end -- same "as of last disconnect, not live" caveat as
the Clients page's own usage bars and My VPN Profile's self-service card).

No new data collection here -- this is read-only aggregation, joined
against User/Team/VpnProfileLink for the "which portal user/team does this
VPN client belong to" mapping. See the architecture review this feature
shipped with for why on-read aggregation (rather than a periodic rollup
job) is the right choice at this deployment's scale.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload

from .. import cli_wrapper as cli
from .. import geoip, health, policy_store
from ..cli_wrapper import ScriptError
from ..db import engine, get_db
from ..models import AuditLog, DbStatSnapshot, QuotaNotification, Team, User
from ..permissions import require_permission_any_scope

router = APIRouter(prefix="/api/reports", tags=["reports"])

require_reports_view = require_permission_any_scope("reports", "view")
# Deliberately a separate, stricter gate than require_reports_view above --
# see permissions.py's OBJECTS entry for "db_reporting" for why (per-table
# sizes, live lock/long-running-query counts, and connection details are
# more sensitive than anything else "reports" exposes; excluded from the
# Viewer role by default, unlike "reports" itself).
require_db_reporting_view = require_permission_any_scope("db_reporting", "view")


def _per_client_row(user: User, client_name: str | None, policies: dict, usage: dict) -> dict:
    policy = policies.get(client_name, {}) if client_name else {}
    quota_gb = policy.get("bandwidth_monthly_gb")
    usage_row = usage.get(client_name, {}) if client_name else {}
    used_bytes = usage_row.get("bytes_used", 0)
    used_gb = used_bytes / (1024**3)
    pct_used = round((used_gb / quota_gb) * 100, 1) if quota_gb else None
    remaining_gb = round(max(0, quota_gb - used_gb), 3) if quota_gb else None
    return {
        "user_id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "vpn_client_name": client_name,
        "quota_gb": quota_gb,
        "used_gb": round(used_gb, 3),
        "remaining_gb": remaining_gb,
        "pct_used": pct_used,
        "team_names": [t.name for t in user.teams],
    }


def _source_ip_summary(sessions: list[dict]) -> dict:
    """Top source IPs + country/city/ASN distribution for one user's own
    session-history rows (Per-User Analytics' Source IP Analytics
    section). Resolves each DISTINCT source_ip via geoip.py's
    lookup_country/lookup_city/lookup_asn exactly ONCE (not once per
    session row) -- a user with hundreds of sessions from a handful of
    real-world locations shouldn't cost hundreds of mmdb lookups.
    Distribution counts are in SESSIONS (how often a location was
    connected from), not distinct IPs -- "most frequently used" is about
    frequency of use, not IP cardinality."""
    ip_counts: dict[str, int] = {}
    for s in sessions:
        ip = s.get("source_ip")
        if ip and ip != "n/a":
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    geo_by_ip = {ip: (geoip.lookup_country(ip), geoip.lookup_city(ip), geoip.lookup_asn(ip)) for ip in ip_counts}

    def _bucket(index: int) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ip, count in ip_counts.items():
            key = geo_by_ip[ip][index]
            if key is None:
                continue
            counts[str(key)] = counts.get(str(key), 0) + count
        return counts

    top_ips = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "country_distribution": sorted([{"country": k, "count": v} for k, v in _bucket(0).items()], key=lambda r: r["count"], reverse=True),
        "city_distribution": sorted([{"city": k, "count": v} for k, v in _bucket(1).items()], key=lambda r: r["count"], reverse=True)[:10],
        "asn_distribution": sorted([{"asn": k, "count": v} for k, v in _bucket(2).items()], key=lambda r: r["count"], reverse=True)[:10],
    }


def _recent_quota_warnings(db: Session, limit: int = 50) -> list[dict]:
    """Every user's recent bandwidth-quota-threshold QuotaNotification rows
    (main.py's _quota_notification_loop), newest first -- an ADMIN-WIDE
    view across every user, unlike routes/notifications.py's own
    list_my_notifications() which is deliberately scoped to just the
    caller's own rows. Used by Diagnostics' "Active Quota Warnings" panel
    and the Dashboard's System Insights card -- both want "which users are
    near/over quota right now", just at different levels of detail."""
    rows = db.query(QuotaNotification).options(selectinload(QuotaNotification.user)).order_by(QuotaNotification.created_at.desc()).limit(limit).all()
    return [
        {
            "id": n.id,
            "username": n.user.username if n.user else None,
            "display_name": n.user.display_name if n.user else None,
            "vpn_client_name": n.vpn_client_name,
            "level": n.level,
            "pct_used": n.pct_used,
            "message": n.message,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in rows
    ]


def _load_rows(db: Session) -> list[dict]:
    """Every active, non-deleted user with a linked VPN profile, joined
    against the current policy/usage snapshot -- the common data set every
    endpoint below slices differently. A user with no linked profile has
    nothing to report (no client_policy.json entry could exist for them),
    so they're excluded here rather than shown with every field null."""
    users = (
        db.query(User)
        .options(selectinload(User.teams), selectinload(User.vpn_profile_link))
        .filter(User.deleted.is_(False), User.is_active.is_(True))
        .order_by(User.username)
        .all()
    )
    policies = policy_store.get_all_policies()
    usage = policy_store.get_all_usage()
    rows = []
    for user in users:
        if user.vpn_profile_link is None:
            continue
        rows.append(_per_client_row(user, user.vpn_profile_link.vpn_client_name, policies, usage))
    return rows


@router.get("/users")
def get_user_report(_: User = Depends(require_reports_view), db: Session = Depends(get_db)):
    """Per-user: username, VPN profile, quota, usage, remaining, % used --
    exactly the "Per User" report shape requested. A user with no quota
    set shows quota_gb/remaining_gb/pct_used as null (unlimited), same
    "blank = unlimited" convention as everywhere else quotas appear."""
    return _load_rows(db)


@router.get("/teams")
def get_team_report(db: Session = Depends(get_db), _: User = Depends(require_reports_view)):
    """Team-based: total quota/usage/utilization per team, plus each
    team's top consumer. A user belonging to several teams counts toward
    each of them (teams are a many-to-many membership, not a partition --
    see models.py's Team docstring), same as every other team-scoped view
    in this app. Users with no team at all are summarized separately under
    "Unassigned" so their usage isn't silently invisible from this report."""
    rows = _load_rows(db)
    teams = db.query(Team).order_by(Team.name).all()

    def _summarize(label: str, members: list[dict]) -> dict:
        with_quota = [r for r in members if r["quota_gb"]]
        total_quota = round(sum(r["quota_gb"] for r in with_quota), 3) if with_quota else None
        total_used = round(sum(r["used_gb"] for r in members), 3)
        pct = round((total_used / total_quota) * 100, 1) if total_quota else None
        top = sorted(members, key=lambda r: r["used_gb"], reverse=True)[:5]
        return {
            "team": label,
            "member_count": len(members),
            "total_quota_gb": total_quota,
            "total_used_gb": total_used,
            "pct_used": pct,
            "top_consumers": [{"username": t["username"], "display_name": t["display_name"], "used_gb": t["used_gb"]} for t in top],
        }

    result = []
    for team in teams:
        members = [r for r in rows if team.name in r["team_names"]]
        result.append(_summarize(team.name, members))
    unassigned = [r for r in rows if not r["team_names"]]
    if unassigned:
        result.append(_summarize("Unassigned", unassigned))
    return result


@router.get("/global")
def get_global_report(db: Session = Depends(get_db), _: User = Depends(require_reports_view)):
    """Global: total consumed/allocated, top consumers overall, and two
    threshold buckets ("approaching" = 80-99% of quota, "exceeding" =
    100%+) -- exactly the "Users approaching quota limits" / "Users
    exceeding thresholds" items requested. The 80% threshold is a fixed
    constant for now (not yet admin-configurable -- a reasonable first
    cut, revisit if it needs to be a setting)."""
    rows = _load_rows(db)
    with_quota = [r for r in rows if r["quota_gb"]]
    total_quota = round(sum(r["quota_gb"] for r in with_quota), 3) if with_quota else None
    total_used = round(sum(r["used_gb"] for r in rows), 3)
    top = sorted(rows, key=lambda r: r["used_gb"], reverse=True)[:10]
    approaching = [r for r in with_quota if r["pct_used"] is not None and 80 <= r["pct_used"] < 100]
    exceeding = [r for r in with_quota if r["pct_used"] is not None and r["pct_used"] >= 100]
    return {
        "total_users_reported": len(rows),
        "total_quota_gb": total_quota,
        "total_used_gb": total_used,
        "pct_used": round((total_used / total_quota) * 100, 1) if total_quota else None,
        "top_consumers": top,
        "approaching_threshold": sorted(approaching, key=lambda r: r["pct_used"], reverse=True),
        "exceeding_threshold": sorted(exceeding, key=lambda r: r["pct_used"], reverse=True),
    }


# --- Per-User Analytics (Phase 2) ----------------------------------------


@router.get("/user-options")
def get_user_options(_: User = Depends(require_reports_view), db: Session = Depends(get_db)):
    """Backs the Per-User Analytics picker -- every active, non-deleted
    user WITH a linked VPN profile (the same set _load_rows() reports
    over), just id/username/display_name/vpn_client_name, not the full
    quota/usage row. Deliberately its own endpoint rather than reusing
    GET /api/users (gated on the stricter users:manage) -- an account with
    reports:view but not users:manage would otherwise 403 populating this
    picker, even though it already sees this same user's bandwidth/quota
    numbers elsewhere on this same page."""
    users = db.query(User).options(selectinload(User.vpn_profile_link)).filter(User.deleted.is_(False), User.is_active.is_(True)).order_by(User.username).all()
    return [
        {"id": u.id, "username": u.username, "display_name": u.display_name, "vpn_client_name": u.vpn_profile_link.vpn_client_name}
        for u in users
        if u.vpn_profile_link is not None
    ]


@router.get("/users/{user_id}")
def get_user_analytics(user_id: int, _: User = Depends(require_reports_view), db: Session = Depends(get_db)):
    """Per-User Analytics' data source: this one user's quota/usage summary
    (reusing _per_client_row() verbatim, same fields as GET /users' list
    rows) plus their raw session-history rows (bandwidth/connection/
    source-IP/duration charts all derive from this) and their rejected-
    connection attempts (successful-vs-failed chart). 404 if the user
    doesn't exist, is deleted/inactive, or has no linked VPN profile --
    same "excluded, not null-filled" convention _load_rows() already uses
    for the list reports, so a picker built from /user-options above can
    never hit this 404 for an option it actually offered."""
    user = (
        db.query(User)
        .options(selectinload(User.teams), selectinload(User.vpn_profile_link))
        .filter(User.id == user_id, User.deleted.is_(False), User.is_active.is_(True))
        .one_or_none()
    )
    if user is None or user.vpn_profile_link is None:
        raise HTTPException(status_code=404, detail="No reportable user with that id.")
    client_name = user.vpn_profile_link.vpn_client_name

    summary = _per_client_row(user, client_name, policy_store.get_all_policies(), policy_store.get_all_usage())

    try:
        sessions = cli.status_session_history(500, client_name)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)

    # Rejected-connection attempts for this client -- vpn-status.py's
    # --rejected-connections has no --client flag of its own (unlike
    # --session-history's, see cli_wrapper.status_session_history), so
    # this filters the already-fetched/cached snapshot here in Python
    # rather than adding server-side filtering to that script. Matching on
    # `claimed_name` is safe/non-spoofable: by the time a client-connect
    # script logs a rejection, mutual TLS auth has already succeeded, so
    # claimed_name IS the cert's own verified common_name, not a claim an
    # attacker controls.
    try:
        rejected_all = cli.get_status_rejected_snapshot(500)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
    rejected = [r for r in rejected_all if r.get("claimed_name") == client_name]

    return {**summary, "sessions": sessions, "rejected": rejected, "source_ip_summary": _source_ip_summary(sessions)}


# --- User Activity Analytics (Phase 2) -----------------------------------


@router.get("/login-activity")
def get_login_activity(
    days: int = Query(90, ge=1, le=365),
    _: User = Depends(require_reports_view),
    db: Session = Depends(get_db),
):
    """Raw login_success audit-log entries (timestamp + username) over the
    last `days` days, for User Activity Analytics' Login Activity chart --
    bucketing by day/week/month happens client-side, same convention as
    every other Analytics chart on this page. See routes/auth.py's
    login_submit for where these are written -- this only reflects logins
    since that logging started (this feature's own deploy date); there is
    no retroactive login history, which the page's own copy calls out
    rather than silently implying a longer history exists."""
    cutoff = datetime.now(UTC) - timedelta(days=days)
    rows = (
        db.query(AuditLog.timestamp, AuditLog.username)
        .filter(AuditLog.action == "login_success", AuditLog.timestamp >= cutoff)
        .order_by(AuditLog.timestamp)
        .all()
    )
    return [{"timestamp": ts.isoformat() if ts else None, "username": username} for ts, username in rows]


# --- Database Reporting (Phase 3) -----------------------------------------


def _history_with_deltas(rows: list[DbStatSnapshot]) -> list[dict]:
    """Converts consecutive DbStatSnapshot rows' RAW CUMULATIVE
    xact_commit/xact_rollback/blks_hit/blks_read counters into what the
    Transaction Rate / Cache Hit Ratio charts actually need per point:
    commits/rollbacks per minute and a cache-hit percentage, each computed
    against the PREVIOUS row in this same result set. The everything-else
    fields (db_size_bytes, connections, locks, long-running-query count)
    are already point-in-time facts, not counters, so they pass through
    as-is -- no delta needed.

    The first row in the returned list always has rate/ratio fields of
    None (there is no earlier row within this window to diff against --
    same "can't rate the very first point" limitation any rate-over-a-
    windowed-fetch computation has). A negative delta (Postgres stats
    reset, or the snapshot rows are somehow out of order) is floored at 0
    rather than shown as a negative rate, which would misread as "the
    database went backwards" rather than "the counter reset"."""
    result = []
    prev = None
    for row in rows:
        entry = {
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "db_size_bytes": row.db_size_bytes,
            "active_connections": row.active_connections,
            "idle_connections": row.idle_connections,
            "waiting_locks_count": row.waiting_locks_count,
            "long_running_query_count": row.long_running_query_count,
            "commits_per_min": None,
            "rollbacks_per_min": None,
            "cache_hit_ratio": None,
        }
        if prev is not None and row.timestamp and prev.timestamp:
            elapsed_min = (row.timestamp - prev.timestamp).total_seconds() / 60
            if elapsed_min > 0 and row.xact_commit is not None and prev.xact_commit is not None:
                d_commit = max(0, row.xact_commit - prev.xact_commit)
                d_rollback = max(0, (row.xact_rollback or 0) - (prev.xact_rollback or 0))
                entry["commits_per_min"] = round(d_commit / elapsed_min, 2)
                entry["rollbacks_per_min"] = round(d_rollback / elapsed_min, 2)
            if row.blks_hit is not None and prev.blks_hit is not None:
                d_hit = max(0, row.blks_hit - prev.blks_hit)
                d_read = max(0, (row.blks_read or 0) - (prev.blks_read or 0))
                total = d_hit + d_read
                if total > 0:
                    entry["cache_hit_ratio"] = round(100 * d_hit / total, 2)
        result.append(entry)
        prev = row
    return result


@router.get("/database")
def get_database_report(
    days: int = Query(30, ge=1, le=365),
    _: User = Depends(require_db_reporting_view),
    db: Session = Depends(get_db),
):
    """Database Reporting's data source -- "current" is a live,
    point-in-time reading (health.py's gather_db_stats/get_top_tables,
    the same functions the periodic snapshot writer uses for consistency,
    see that module), "history" is DbStatSnapshot rows written
    periodically by main.py's _db_snapshot_loop, pre-differenced into
    rates/ratios (see _history_with_deltas above). Postgres-only --
    available=False on SQLite, same "not applicable here" convention
    health.py's get_host_health()/get_traefik_health() already use."""
    if engine.dialect.name != "postgresql":
        return {
            "available": False,
            "reason": "Database Reporting requires PostgreSQL (this deployment is running SQLite).",
            "current": None,
            "history": [],
        }

    with engine.connect() as conn:
        current = health.gather_db_stats(conn)
    current["top_tables"] = health.get_top_tables(10)

    cutoff = datetime.now(UTC) - timedelta(days=days)
    rows = db.query(DbStatSnapshot).filter(DbStatSnapshot.timestamp >= cutoff).order_by(DbStatSnapshot.timestamp).all()
    return {"available": True, "reason": None, "current": current, "history": _history_with_deltas(rows)}
