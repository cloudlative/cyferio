"""
Phase 6 of the dynamic-RBAC rollout: the self-service "My VPN Profile"
endpoints -- see docs/rbac_identity_design.md §3/§6 and the
joyful-sauteeing-cookie plan.

Deliberately always operates on request.user's own VpnProfileLink, never on
an id/username taken from the request -- so there's no separate "own vs
any" scope check to perform here the way require_own_or_permission handles
for endpoints that take a path param (there is no path param here to
mis-scope). require_permission("vpn_profiles", action) is enough: it's
already "my own record" by construction.

No self-enrollment (see docs/rbac_identity_design.md §7 item 4, an explicit
open assumption confirmed by proceeding): a VPN profile is always admin-
provisioned -- either automatically as part of creating the portal user
(routes/users.py's create_user, the standard path since the User<->VPN
Profile lifecycle unification) or by attaching an existing, unassigned
profile via routes/users.py's link_vpn_profile. This router only ever
views/updates a profile that's already linked, regardless of which of
those two ways it got linked."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from .. import cli_wrapper as cli
from .. import policy_store
from ..audit import log_action
from ..cli_wrapper import ScriptError
from ..db import get_db
from ..models import User
from ..permissions import require_permission
# _source_ip_summary is a pure, user-agnostic helper (takes a plain session
# list, does its own geoip resolution) -- reused verbatim rather than
# duplicated. reports.py doesn't import anything from this module, so this
# is a plain one-way import, not a cycle.
from .reports import _source_ip_summary

router = APIRouter(prefix="/api/me/vpn-profile", tags=["me"])


def _require_link(user: User) -> "VpnProfileLink":  # noqa: F821 -- forward ref, avoids importing the model just for typing
    link = user.vpn_profile_link
    if link is None:
        raise HTTPException(status_code=404, detail="No VPN profile is linked to your account yet -- ask an admin.")
    return link


@router.get("")
def get_my_vpn_profile(user: User = Depends(require_permission("vpn_profiles", "view")), db: Session = Depends(get_db)):
    link = _require_link(user)
    try:
        macs = cli.list_macs(link.vpn_client_name)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
    # Cross-reference the live client snapshot for status/created info, same
    # data routes/clients.py's get_clients already exposes admin-side --
    # self-service just gets exactly its own row instead of the full list.
    # NOTE: get_clients_snapshot() is install-script-backed MAC-DB metadata
    # only ({name, in_db, mac_count}) -- see get_dashboard_snapshot()'s own
    # docstring on why it's NOT interchangeable with the status/vpn-status.py
    # -backed calls below. client_info.in_db is what "Active"/"Not
    # registered" already reads (see my_vpn_profile.html) -- kept as-is.
    client_info = None
    try:
        for c in cli.get_clients_snapshot():
            if c.get("name") == link.vpn_client_name:
                client_info = c
                break
    except ScriptError:
        pass  # non-fatal -- MAC info above is the important part, status is a bonus
    # Current-session visibility (status/source IP/OS/connected-since/
    # duration/RX-TX/last-seen) -- these fields already exist in vpn-status.py's
    # own output, just not previously read by this endpoint. Deliberately
    # NOT using /api/clients/sessions (routes/clients.py, the admin Clients
    # page's live management-socket source for source_ip/connected_since/
    # RX-TX) -- that endpoint is any-scope-gated (admin/staff only, see its
    # require_permission_any_scope("vpn_profiles","view") gate) and would
    # 403 for an own-scope "User" role account. get_status_all_snapshot()/
    # get_status_connected_snapshot() are both vpn-status.py-backed and
    # already reachable under this endpoint's own scope, at the cost of a
    # slightly less authoritative source_ip per management_client.py's
    # parse_source_ip() docstring -- an acceptable tradeoff for self-service
    # display, not a security decision made unattended.
    session_info = None
    try:
        status_row = next((c for c in cli.get_status_all_snapshot() if c.get("name") == link.vpn_client_name), None)
        connected_row = next((c for c in cli.get_status_connected_snapshot() if c.get("name") == link.vpn_client_name), None)
        if status_row is not None:
            live = connected_row or status_row
            session_info = {
                "status": status_row.get("status"),
                "os": status_row.get("os"),
                "last_seen": status_row.get("last_seen"),
                "source_ip": live.get("source_ip"),
                "connected_since": connected_row.get("connected_since") if connected_row else None,
                "duration": live.get("duration"),
                "bytes_received_h": live.get("bytes_received_h"),
                "bytes_sent_h": live.get("bytes_sent_h"),
            }
    except ScriptError:
        pass  # non-fatal -- same "bonus, not required" stance as client_info above
    return {
        "vpn_client_name": link.vpn_client_name,
        "linked_at": link.linked_at.isoformat() if link.linked_at else None,
        "macs": (macs or {}).get("macs", []),
        "client_info": client_info,
        "session": session_info,
        # View-only bandwidth visibility (task feedback: "VPN users with
        # standard User permissions should also be able to see current
        # usage, allocated bandwidth, remaining bandwidth" from their
        # self-service portal) -- same policy_store calls the admin-side
        # GET /api/clients/{name}/policy makes, just scoped to the caller's
        # own linked client rather than an admin-chosen name. No edit
        # controls here -- this router doesn't expose a policy PUT.
        "policy": policy_store.get_policy(link.vpn_client_name),
        "usage": policy_store.get_usage(link.vpn_client_name),
    }


@router.get("/report")
def get_my_vpn_report(user: User = Depends(require_permission("vpn_profiles", "view")), db: Session = Depends(get_db)):
    """Self-service analytics -- the "My Reports" page's data source.
    Deliberately mirrors routes/reports.py's get_user_analytics() (Per-User
    Analytics' admin-facing equivalent) field-for-field, minus the user_id
    lookup step: same require_permission("vpn_profiles", "view") gate and
    "always resolve request.user's own VpnProfileLink" pattern as every
    other endpoint in this router (see module docstring) -- there's no id
    param to mis-scope, so no separate scope check is needed here, unlike
    get_user_analytics()'s require_permission_any_scope("reports", "view")
    gate for the analogous admin view."""
    link = _require_link(user)
    client_name = link.vpn_client_name
    try:
        sessions = cli.status_session_history(500, client_name)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
    # Same claimed_name filter as get_user_analytics() -- see that
    # function's docstring for why matching on claimed_name is safe/
    # non-spoofable (mutual TLS already succeeded by the time a rejection
    # gets logged, so claimed_name is the cert's own verified common_name).
    try:
        rejected_all = cli.get_status_rejected_snapshot(500)
    except ScriptError as e:
        raise HTTPException(status_code=502, detail=e.message)
    rejected = [r for r in rejected_all if r.get("claimed_name") == client_name]
    return {
        "vpn_client_name": client_name,
        "policy": policy_store.get_policy(client_name),
        "usage": policy_store.get_usage(client_name),
        "sessions": sessions,
        "rejected": rejected,
        "source_ip_summary": _source_ip_summary(sessions),
    }


class UpdateMacRequest(BaseModel):
    mac: str

    @field_validator("mac")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("MAC address is required.")
        return v.strip()


@router.post("/macs", status_code=201)
def add_my_mac(
    body: UpdateMacRequest,
    user: User = Depends(require_permission("vpn_profiles", "update")),
    db: Session = Depends(get_db),
):
    link = _require_link(user)
    try:
        result = cli.add_mac(link.vpn_client_name, body.mac)
    except ScriptError as e:
        log_action(db, user, "self_add_mac", target=link.vpn_client_name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "self_add_mac", target=link.vpn_client_name, detail=result, success=True)
    return {"message": result}


@router.delete("/macs/{mac}")
def remove_my_mac(
    mac: str,
    user: User = Depends(require_permission("vpn_profiles", "update")),
    db: Session = Depends(get_db),
):
    link = _require_link(user)
    try:
        result = cli.remove_mac(link.vpn_client_name, mac)
    except ScriptError as e:
        log_action(db, user, "self_remove_mac", target=link.vpn_client_name, detail=e.message, success=False)
        raise HTTPException(status_code=400, detail=e.message)
    log_action(db, user, "self_remove_mac", target=link.vpn_client_name, detail=result, success=True)
    return {"message": result}


@router.get("/ovpn")
def get_my_ovpn(user: User = Depends(require_permission("vpn_profiles", "view")), db: Session = Depends(get_db)):
    link = _require_link(user)
    try:
        content = cli.show_ovpn(link.vpn_client_name)
    except ScriptError as e:
        raise HTTPException(status_code=400, detail=e.message)
    return {"name": link.vpn_client_name, "ovpn": content}
