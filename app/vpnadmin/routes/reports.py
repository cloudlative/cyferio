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
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session, selectinload

from .. import policy_store
from ..db import get_db
from ..models import Team, User, VpnProfileLink
from ..permissions import require_permission_any_scope

router = APIRouter(prefix="/api/reports", tags=["reports"])

require_reports_view = require_permission_any_scope("reports", "view")


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
        "team_names": [t.name for t in user.teams],
    }


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
