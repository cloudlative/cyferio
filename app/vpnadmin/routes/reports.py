"""Bandwidth reporting -- per-user, per-group, and global rollups over the
same two sources every other bandwidth feature in this app already reads:
policy_store.get_all_policies() (quotas) and policy_store.get_all_usage()
(this-month bytes used, written by host-scripts/openvpn-client-disconnect.py
on every session end -- same "as of last disconnect, not live" caveat as
the Clients page's own usage bars and My VPN Profile's self-service card).

No new data collection here -- this is read-only aggregation, joined
against User/Group/VpnProfileLink for the "which portal user/group does this
VPN client belong to" mapping. See the architecture review this feature
shipped with for why on-read aggregation (rather than a periodic rollup
job) is the right choice at this deployment's scale.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload

from .. import app_settings
from .. import cli_wrapper as cli
from .. import geoip, health, policy_store
from ..cli_wrapper import ScriptError
from ..db import engine, get_db
from ..models import AuditLog, ConnectionRejectionLog, DbStatSnapshot, Group, User, VpnProfileLink
from ..permissions import require_permission_any_scope

router = APIRouter(prefix="/api/reports", tags=["reports"])

require_reports_view = require_permission_any_scope("reports", "view")
# Deliberately a separate, stricter gate than require_reports_view above --
# see permissions.py's OBJECTS entry for "db_reporting" for why (per-table
# sizes, live lock/long-running-query counts, and connection details are
# more sensitive than anything else "reports" exposes; excluded from the
# Viewer role by default, unlike "reports" itself).
require_db_reporting_view = require_permission_any_scope("db_reporting", "view")
# Connection Failures (below) is gated on "health", matching Diagnostics'
# own page-level gate (routes/pages.py's diagnostics_page) rather than
# "reports" -- it's additive data for that same page, not a new report an
# admin without health:view but with reports:view should be able to reach.
require_health_view = require_permission_any_scope("health", "view")


def _per_client_row(user: User, client_name: str | None, policies: dict, usage: dict) -> dict:
    policy = policies.get(client_name, {}) if client_name else {}
    quota_gb = policy.get("bandwidth_monthly_gb")
    usage_row = usage.get(client_name, {}) if client_name else {}
    used_bytes = usage_row.get("bytes_used", 0)
    used_gb = used_bytes / (1024 ** 3)
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
        "group_names": [t.name for t in user.groups],
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
        "country_distribution": sorted(
            [{"country": k, "count": v} for k, v in _bucket(0).items()], key=lambda r: r["count"], reverse=True),
        "city_distribution": sorted(
            [{"city": k, "count": v} for k, v in _bucket(1).items()], key=lambda r: r["count"], reverse=True)[:10],
        "asn_distribution": sorted(
            [{"asn": k, "count": v} for k, v in _bucket(2).items()], key=lambda r: r["count"], reverse=True)[:10],
    }


def _load_rows(db: Session) -> list[dict]:
    """Every active, non-deleted user with a linked VPN profile, joined
    against the current policy/usage snapshot -- the common data set every
    endpoint below slices differently. A user with no linked profile has
    nothing to report (no client_policy.json entry could exist for them),
    so they're excluded here rather than shown with every field null."""
    users = (
        db.query(User)
        .options(selectinload(User.groups), selectinload(User.vpn_profile_link))
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


def _active_quota_warnings(db: Session, limit: int = 50) -> list[dict]:
    """Every user CURRENTLY at/over the configured warning/critical
    bandwidth-quota threshold, computed live from _load_rows() -- i.e. this
    reflects usage/quota as they stand RIGHT NOW, not "ever crossed a
    threshold at some point". Used by Diagnostics' "Active Quota Warnings"
    panel and the Dashboard's System Insights card, both of which want
    exactly that live view -- NOT QuotaNotification (models.py), which is
    an append-only, never-updated EVENT log of past threshold crossings
    (main.py's _quota_notification_loop), correct for its own job backing
    the notification bell (routes/notifications.py's list_my_notifications,
    which deliberately shows history: "you were warned on this date"), but
    wrong for a panel titled "Active" -- resetting a user's usage after
    they'd crossed "critical" left their old QuotaNotification row sitting
    there forever with no way to tell it had been resolved, so this panel
    kept showing them as critical long after the reset (found live
    2026-08-21). This function is what actually earns that "Active" label;
    QuotaNotification/the bell are untouched."""
    warning_pct = app_settings.runtime.quota_notify_warning_pct
    critical_pct = app_settings.runtime.quota_notify_critical_pct
    out = []
    for r in _load_rows(db):
        pct = r["pct_used"]
        if pct is None or pct < warning_pct:
            continue
        level = "critical" if pct >= critical_pct else "warning"
        out.append({
            "username": r["username"],
            "display_name": r["display_name"],
            "vpn_client_name": r["vpn_client_name"],
            "level": level,
            "pct_used": pct,
            "message": f"{pct}% of this month's bandwidth quota used ({r['used_gb']} / {r['quota_gb']} GB).",
        })
    out.sort(key=lambda w: w["pct_used"], reverse=True)
    return out[:limit]


@router.get("/users")
def get_user_report(_: User = Depends(require_reports_view), db: Session = Depends(get_db)):
    """Per-user: username, VPN profile, quota, usage, remaining, % used --
    exactly the "Per User" report shape requested. A user with no quota
    set shows quota_gb/remaining_gb/pct_used as null (unlimited), same
    "blank = unlimited" convention as everywhere else quotas appear."""
    return _load_rows(db)


@router.get("/groups")
def get_group_report(db: Session = Depends(get_db), _: User = Depends(require_reports_view)):
    """Group-based: total quota/usage/utilization per group, plus each
    group's top consumer. A user belonging to several groups counts toward
    each of them (groups are a many-to-many membership, not a partition --
    see models.py's Group docstring), same as every other group-scoped view
    in this app. Users with no group at all are summarized separately under
    "Unassigned" so their usage isn't silently invisible from this report."""
    rows = _load_rows(db)
    groups = db.query(Group).order_by(Group.name).all()

    def _summarize(label: str, members: list[dict]) -> dict:
        with_quota = [r for r in members if r["quota_gb"]]
        total_quota = round(sum(r["quota_gb"] for r in with_quota), 3) if with_quota else None
        total_used = round(sum(r["used_gb"] for r in members), 3)
        pct = round((total_used / total_quota) * 100, 1) if total_quota else None
        top = sorted(members, key=lambda r: r["used_gb"], reverse=True)[:5]
        return {
            "group": label,
            "member_count": len(members),
            "total_quota_gb": total_quota,
            "total_used_gb": total_used,
            "pct_used": pct,
            "top_consumers": [{"username": t["username"], "display_name": t["display_name"], "used_gb": t["used_gb"]} for t in top],
        }

    result = []
    for group in groups:
        members = [r for r in rows if group.name in r["group_names"]]
        result.append(_summarize(group.name, members))
    unassigned = [r for r in rows if not r["group_names"]]
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


@router.get("/mfa")
def get_mfa_report(db: Session = Depends(get_db), _: User = Depends(require_reports_view)):
    """Multi-Factor Authentication adoption/activity -- see the feature's
    plan for why this is one card on the existing Reports page rather than
    a new page: same read-only-aggregation posture as get_global_report
    above, just over User.mfa_* columns and AuditLog instead of
    policy_store. "Pending enrollment" iterates active users in Python
    (mfa.effective_policy per user) rather than a SQL WHERE clause --
    small scale (this app's whole user list, not per-session data), and
    the policy precedence logic already lives in one place (mfa.py), not
    worth duplicating as a query."""
    from .. import mfa as mfa_module

    active_users = db.query(User).filter(User.deleted.is_(False)).all()
    total = len(active_users)
    enabled = sum(1 for u in active_users if u.mfa_enabled)
    pending_enrollment = sum(
        1 for u in active_users if not u.mfa_enabled and mfa_module.effective_policy(u, db) == "required"
    )
    window_start = datetime.now(timezone.utc) - timedelta(days=30)
    recent = db.query(AuditLog).filter(AuditLog.timestamp >= window_start)
    invalid_otp_attempts = recent.filter(AuditLog.action == "invalid_otp_attempt").count()
    mfa_login_successes = recent.filter(AuditLog.action == "mfa_login_success").count()
    recovery_code_uses = recent.filter(AuditLog.action == "recovery_code_used").count()
    return {
        "total_users": total,
        "mfa_enabled_users": enabled,
        "mfa_disabled_users": total - enabled,
        "adoption_rate_pct": round((enabled / total) * 100, 1) if total else 0,
        "pending_enrollment": pending_enrollment,
        "last_30_days": {
            "invalid_otp_attempts": invalid_otp_attempts,
            "mfa_login_successes": mfa_login_successes,
            "recovery_code_uses": recovery_code_uses,
        },
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
    users = (
        db.query(User)
        .options(selectinload(User.vpn_profile_link))
        .filter(User.deleted.is_(False), User.is_active.is_(True))
        .order_by(User.username)
        .all()
    )
    return [
        {"id": u.id, "username": u.username, "display_name": u.display_name, "vpn_client_name": u.vpn_profile_link.vpn_client_name}
        for u in users if u.vpn_profile_link is not None
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
        .options(selectinload(User.groups), selectinload(User.vpn_profile_link))
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
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(AuditLog.timestamp, AuditLog.username)
        .filter(AuditLog.action == "login_success", AuditLog.timestamp >= cutoff)
        .order_by(AuditLog.timestamp)
        .all()
    )
    return [{"timestamp": ts.isoformat() if ts else None, "username": username} for ts, username in rows]


# --- Connection Failures (VPN Client Management / Connection Failure
# Tracking) -----------------------------------------------------------------
# Data source is ConnectionRejectionLog, not the flat openvpn.log file
# Diagnostics' own /api/status/rejected table reads -- that flat-file path
# (host-scripts/openvpn-mac-addr-check.py's per-attempt env dump, parsed by
# vpn-status.py) never captured detected_country/detected_city/detected_asn
# at all (reject() only ever wrote `reason`/`registered_mac_at_time` lines
# to the log file itself; the detected_* fields were always POST-only, see
# report_rejection()). This is genuinely the only place that data exists,
# so it's the only source rich enough for failure-type/geographic/ASN
# breakdowns -- Diagnostics' table stays on the flat file (it has its own
# OS/repeat-count columns this table doesn't track), this is additive.

# reason -> human label, same mapping (and same intentional fallback to the
# raw string for anything unlisted) as diagnostics.html's own
# REJECTION_REASON_LABELS -- duplicated rather than shared since one lives
# in Python (this response) and the other in the template's own JS, and
# both need to independently keep working if only one is ever updated.
_FAILURE_REASON_LABELS = {
    "mac_mismatch": "MAC Address Mismatch / Unregistered Device",
    "os_not_allowed": "Device OS Restriction",
    "country_not_allowed": "Country Restriction",
    "country_lookup_failed": "Country Lookup Failed",
    "city_not_allowed": "City Restriction",
    "city_lookup_failed": "City Lookup Failed",
    "asn_not_allowed": "Network (ASN) Restriction",
    "asn_lookup_failed": "Network (ASN) Lookup Failed",
    "ip_not_allowed": "IP Address Restriction",
    "bandwidth_exceeded": "Bandwidth Quota Exceeded",
}


def _counts_dict(items, *, skip_blank: bool = True) -> dict[str, int]:
    """value -> occurrence count, over any iterable of (possibly None)
    strings. `skip_blank=False` folds a missing value into an explicit
    "n/a" bucket instead of dropping it -- used for by_reason/by_client
    below, where "how many rows have no value here" is itself meaningful;
    the geo/IP breakdowns (skip_blank=True, the default) just omit rows
    with nothing detected rather than clutter a chart with an "n/a" slice."""
    counts: dict[str, int] = {}
    for v in items:
        if not v and skip_blank:
            continue
        key = v or "n/a"
        counts[key] = counts.get(key, 0) + 1
    return counts


def _top_counts(items: list[str | None], limit: int = 10) -> list[dict]:
    counts = _counts_dict(items)
    return [{"key": k, "count": c} for k, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]]


@router.get("/connection-failures")
def get_connection_failures(
    days: int = Query(30, ge=1, le=365),
    reason: str | None = Query(None),
    client: str | None = Query(None, description="Filter to one vpn_client_name"),
    country: str | None = Query(None, description="Filter to one detected_country code"),
    limit: int = Query(200, ge=1, le=1000),
    _: User = Depends(require_health_view),
    db: Session = Depends(get_db),
):
    """Failed Connection Analytics -- every rejected connect attempt
    (device/location/network/quota policy violations) in the window,
    aggregated for the summary cards/charts plus a capped list of the raw
    rows themselves. `reason`/`client`/`country` narrow the SAME window
    used for both the aggregates and the row list, so a filtered chart and
    a filtered table are always looking at the same data -- unlike
    Diagnostics' page-level filters, which narrow client-side after one
    unfiltered fetch, this narrows the query itself (there can be far more
    rejection history than the 500-row cap that page works within)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(ConnectionRejectionLog).filter(ConnectionRejectionLog.timestamp >= cutoff)
    if reason:
        q = q.filter(ConnectionRejectionLog.reason == reason)
    if client:
        q = q.filter(ConnectionRejectionLog.vpn_client_name == client)
    if country:
        q = q.filter(ConnectionRejectionLog.detected_country == country)
    rows = q.order_by(ConnectionRejectionLog.timestamp.desc()).all()

    # Portal identity for whichever vpn_client_names actually show up here
    # -- same join-by-name pattern routes/status.py's get_session_history
    # uses, not a per-row query.
    client_names = {r.vpn_client_name for r in rows}
    links = (
        db.query(VpnProfileLink.vpn_client_name, User.username, User.first_name, User.last_name)
        .join(User, User.id == VpnProfileLink.user_id)
        .filter(VpnProfileLink.vpn_client_name.in_(client_names))
        .all()
    ) if client_names else []
    identity_by_client = {
        name: {"username": username, "display_name": f"{first} {last}".strip() if last else first}
        for name, username, first, last in links
    }

    # Daily bucket counts, zero-filled for every day in [cutoff, now] so a
    # quiet day reads as an honest 0 on the trend chart rather than simply
    # being absent from the series (which a line chart would otherwise draw
    # as a straight line across, implying data that isn't there).
    by_day: dict[str, int] = {}
    day_cursor = cutoff.date()
    today = datetime.now(timezone.utc).date()
    while day_cursor <= today:
        by_day[day_cursor.isoformat()] = 0
        day_cursor += timedelta(days=1)
    for r in rows:
        key = r.timestamp.date().isoformat() if r.timestamp else None
        if key in by_day:
            by_day[key] += 1

    return {
        "total": len(rows),
        "unique_clients_affected": len(client_names),
        "by_reason": [
            {"reason": k, "label": _FAILURE_REASON_LABELS.get(k, k), "count": v}
            for k, v in sorted(_counts_dict((r.reason for r in rows), skip_blank=False).items(), key=lambda kv: kv[1], reverse=True)
        ],
        "by_country": _top_counts([r.detected_country for r in rows]),
        "by_city": _top_counts([r.detected_city for r in rows]),
        "by_asn": _top_counts([f"{r.detected_asn} ({r.detected_asn_name})" if r.detected_asn_name else r.detected_asn for r in rows]),
        "by_source_ip": _top_counts([r.source_ip for r in rows]),
        "by_client": [
            {"vpn_client_name": k, "username": identity_by_client.get(k, {}).get("username"),
             "display_name": identity_by_client.get(k, {}).get("display_name"), "count": v}
            for k, v in sorted(_counts_dict(r.vpn_client_name for r in rows).items(), key=lambda kv: kv[1], reverse=True)[:10]
        ],
        "time_series": [{"date": k, "count": v} for k, v in sorted(by_day.items())],
        "rows": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "vpn_client_name": r.vpn_client_name,
                "username": identity_by_client.get(r.vpn_client_name, {}).get("username"),
                "display_name": identity_by_client.get(r.vpn_client_name, {}).get("display_name"),
                "reason": r.reason,
                "reason_label": _FAILURE_REASON_LABELS.get(r.reason, r.reason),
                "message": r.message,
                "source_ip": r.source_ip,
                "detected_mac": r.detected_mac,
                "detected_country": r.detected_country,
                "detected_city": r.detected_city,
                "detected_asn": r.detected_asn,
                "detected_asn_name": r.detected_asn_name,
                "detected_os": r.detected_os,
                "registered_mac_at_time": r.registered_mac_at_time,
            }
            for r in rows[:limit]
        ],
    }


@router.get("/dropped-sessions")
def get_dropped_sessions(
    days: int = Query(30, ge=1, le=365),
    client: str | None = Query(None),
    limit: int = Query(200, ge=1, le=500),
    _: User = Depends(require_health_view),
):
    """The complement of Connection History -- sessions that connected and
    disconnected too fast (see AppSettings.min_session_duration_seconds) to
    count as real usage, excluded from status_session_history() and every
    session-based report. These are NOT policy rejections (no `reason`,
    ConnectionRejectionLog has no row for them) -- the client-connect gates
    all passed -- so they're kept as their own small section rather than
    folded into get_connection_failures() above, which would otherwise
    imply a policy reason that doesn't exist for these rows."""
    try:
        rows = cli.status_dropped_sessions(500, client)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    in_range = []
    for r in rows:
        ts = r.get("disconnected_at") or r.get("connected_at")
        try:
            when = datetime.fromisoformat(ts) if ts else None
        except ValueError:
            when = None
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when is None or when >= cutoff:
            in_range.append(r)
    return {"total": len(in_range), "rows": in_range[:limit]}


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

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.query(DbStatSnapshot)
        .filter(DbStatSnapshot.timestamp >= cutoff)
        .order_by(DbStatSnapshot.timestamp)
        .all()
    )
    return {"available": True, "reason": None, "current": current, "history": _history_with_deltas(rows)}


@router.get("/device-availability")
def get_device_availability_report(
    days: int = Query(30, ge=1, le=365),
    _: User = Depends(require_reports_view),
    db: Session = Depends(get_db),
):
    """VPN Device Availability Monitoring's Device Availability report --
    uptime %, downtime %, outage count, and average outage duration per
    monitored device over the trailing `days`, sorted worst-availability-
    first (doubles as the "Most Unstable Devices" view -- see
    device_monitoring.availability_report's own docstring for why no
    separate query is needed for that). Same "reports" gate as every other
    report on this page."""
    from .. import device_monitoring
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return {"days": days, "devices": device_monitoring.availability_report(db, start, end)}
