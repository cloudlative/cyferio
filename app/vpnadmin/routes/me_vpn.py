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
    client_info = None
    try:
        for c in cli.get_clients_snapshot():
            if c.get("name") == link.vpn_client_name:
                client_info = c
                break
    except ScriptError:
        pass  # non-fatal -- MAC info above is the important part, status is a bonus
    return {
        "vpn_client_name": link.vpn_client_name,
        "linked_at": link.linked_at.isoformat() if link.linked_at else None,
        "macs": (macs or {}).get("macs", []),
        "client_info": client_info,
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
