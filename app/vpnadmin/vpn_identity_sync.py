"""
VPN profile <-> portal user identity lifecycle sync (Phase 3 of the dynamic-
RBAC rollout -- see docs/rbac_identity_design.md §4 and the
joyful-sauteeing-cookie plan). Called from routes/clients.py (VPN-side
lifecycle: add/revoke/restore/purge) and routes/users.py (portal-side:
suspend/reactivate/delete).

Hard rule, enforced here and nowhere else needs to re-check it:
VpnProfileLink.protected_from_auto_revoke gates every call this module makes
into cli_wrapper. A cert marked protected (every migration-created link,
permanently) is NEVER revoked/restored/purged by anything in this file --
only a human clicking Revoke/Restore in the Clients UI (routes/clients.py's
own require_permission-gated endpoints, unaffected by this module) can touch
it. See VpnProfileLink's docstring in models.py for the full guarantee.
"""
import secrets
import string

from sqlalchemy.orm import Session

from . import cli_wrapper as cli
from .auth import hash_password
from .cli_wrapper import ScriptError
from .models import AuditLog, Role, RoleDef, User, VpnProfileLink

# audit.py's log_action() requires a real User (it reads user.username) --
# these hooks run as a side effect of a request some *other* user made, not
# as their own action, so a fixed "system" actor is used instead, same
# pattern as this app already applies AuditLog.username as a plain string
# snapshot for (rather than requiring a live User row for) every entry.
_SYSTEM_ACTOR = "system"

_TEMP_PW_ALPHABET = string.ascii_letters + string.digits


def generate_temp_password(length: int = 20) -> str:
    return "".join(secrets.choice(_TEMP_PW_ALPHABET) for _ in range(length))


def _log_sync_failure(db: Session, action: str, target: str, error: ScriptError) -> None:
    """Every hook below wraps its cli_wrapper call in try/except and routes
    failures here -- the portal-side DB change this hook accompanies has
    already been committed by its caller and is NOT rolled back over a
    downstream cli_wrapper failure (see each call site). A failed sync is
    surfaced in the audit log for an admin to notice and reconcile by hand,
    not silently swallowed and not allowed to undo a portal action that
    already succeeded."""
    db.add(AuditLog(
        username=_SYSTEM_ACTOR, action="vpn_sync_failed", target=target,
        detail=f"{action}: {error.message}"[:2000], success=False,
    ))
    db.commit()


def _log_sync_skipped_protected(db: Session, action: str, target: str) -> None:
    db.add(AuditLog(
        username=_SYSTEM_ACTOR, action="vpn_revoke_skipped_protected", target=target,
        detail=(
            f"{action} was requested but this profile is protected_from_auto_revoke "
            "-- the VPN cert was left running untouched."
        )[:2000],
        success=True,
    ))
    db.commit()


def auto_link_new_client(db: Session, client_name: str) -> dict | None:
    """Called right after routes/clients.py's add_client succeeds. If the
    new client name isn't already linked to a portal user:
      - an existing, unlinked portal user with that exact username gets
        linked to it (no new account -- matches the migration's own
        exact-match behavior, see docs/rbac_identity_design.md §5), or
      - a brand-new "User" (self-service) portal account is created and linked.
    Returns {"username", "temp_password"} when a new account was created (so
    the caller can show the temp password once), or None otherwise (already
    linked, linked an existing account, or RBAC not seeded yet -- this never
    raises; a failure here must never block a VPN cert that was already
    successfully created)."""
    normalized = client_name.strip().lower()
    if db.query(VpnProfileLink).filter_by(vpn_client_name=client_name).first() is not None:
        return None

    existing_user = db.query(User).filter(User.username == normalized).first()
    if existing_user is not None:
        if existing_user.vpn_profile_link is not None:
            return None  # already linked to a different profile -- leave it, don't touch add_client's success
        db.add(VpnProfileLink(
            user_id=existing_user.id, vpn_client_name=client_name,
            link_source="created_with_profile", protected_from_auto_revoke=False,
        ))
        db.commit()
        return None

    vss_role = db.query(RoleDef).filter_by(slug="user").first()
    if vss_role is None:
        return None  # RBAC not seeded yet somehow -- fail soft

    temp_password = generate_temp_password()
    user = User(
        username=normalized,
        password_hash=hash_password(temp_password),
        role=Role.viewer,  # legacy enum column has no "user"/self-service member -- see users.py's _resolve_role comment
        role_id=vss_role.id,
        first_name=client_name,
        must_reset_password=True,
    )
    db.add(user)
    db.flush()
    db.add(VpnProfileLink(
        user_id=user.id, vpn_client_name=client_name,
        link_source="created_with_profile", protected_from_auto_revoke=False,
    ))
    db.commit()
    return {"username": user.username, "temp_password": temp_password}


def sync_after_client_revoke(db: Session, client_name: str) -> None:
    """A human revoked a VPN client through the Clients UI on purpose --
    this direction is unaffected by protected_from_auto_revoke (see this
    module's docstring): a real admin action on a real cert should always
    suspend the matching portal account."""
    link = db.query(VpnProfileLink).filter_by(vpn_client_name=client_name).first()
    if link is None or not link.user.is_active:
        return
    link.user.is_active = False
    db.commit()


def sync_after_client_restore(db: Session, client_name: str) -> None:
    link = db.query(VpnProfileLink).filter_by(vpn_client_name=client_name).first()
    if link is None or link.user.is_active:
        return
    link.user.is_active = True
    db.commit()


def sync_after_client_purge(db: Session, client_name: str) -> None:
    """Irreversible on the VPN side (purge_revoked deletes PKI/.ovpn files
    for good) -- mirrors with a soft-delete on the portal side, never a hard
    delete, matching this app's existing no-hard-delete-path policy for
    users."""
    from datetime import datetime, timezone
    link = db.query(VpnProfileLink).filter_by(vpn_client_name=client_name).first()
    if link is None or link.user.deleted:
        return
    link.user.deleted = True
    link.user.deleted_at = datetime.now(timezone.utc)
    link.user.is_active = False
    db.commit()


def sync_after_portal_suspend(db: Session, user: User) -> None:
    """Called from routes/users.py when an admin sets is_active=False on a
    linked user. Guarded by protected_from_auto_revoke -- see this module's
    docstring for why."""
    link = user.vpn_profile_link
    if link is None:
        return
    if link.protected_from_auto_revoke:
        _log_sync_skipped_protected(db, "suspend", link.vpn_client_name)
        return
    try:
        cli.revoke_client(link.vpn_client_name)
    except ScriptError as e:
        _log_sync_failure(db, "suspend->revoke_client", link.vpn_client_name, e)


def sync_after_portal_reactivate(db: Session, user: User) -> None:
    """Called when an admin flips is_active back to True. Only meaningful
    if this app was the one that revoked the cert (i.e. it was reachable in
    the revoked list) -- restore_client re-issues a brand-new certificate
    (see cli_wrapper.restore_client's own docstring), so calling it on a
    cert that was never actually revoked would be a no-op error from the
    script, not a silent success; the protected check below still applies
    since a protected link is never revoked by this module in the first
    place, so there's nothing here to restore."""
    link = user.vpn_profile_link
    if link is None or link.protected_from_auto_revoke:
        return
    try:
        macs_result = cli.list_macs(link.vpn_client_name)  # {"name","count","macs": [...]}, see openvpn-install.sh do_list_macs
        registered = (macs_result or {}).get("macs") or []
        mac = registered[0] if registered else None
        if not mac:
            _log_sync_failure(
                db, "reactivate->restore_client", link.vpn_client_name,
                ScriptError("No MAC on file to restore with -- restore the client manually from the Clients page."),
            )
            return
        cli.restore_client(link.vpn_client_name, mac)
    except ScriptError as e:
        _log_sync_failure(db, "reactivate->restore_client", link.vpn_client_name, e)


def sync_after_portal_delete(db: Session, user: User) -> None:
    """Portal user soft-deleted -- same protected-flag guard as suspend."""
    link = user.vpn_profile_link
    if link is None:
        return
    if link.protected_from_auto_revoke:
        _log_sync_skipped_protected(db, "delete", link.vpn_client_name)
        return
    try:
        cli.revoke_client(link.vpn_client_name)
    except ScriptError as e:
        _log_sync_failure(db, "delete->revoke_client", link.vpn_client_name, e)


def sync_before_portal_permanent_delete(db: Session, user: User) -> None:
    """Called from routes/users.py's permanently_delete_user, before the
    User row (and its cascade-deleted VpnProfileLink) is removed.

    By the time a permanent delete is reachable, the soft-delete step
    already called sync_after_portal_delete above -- so in the common case
    the linked cert is already revoked and this is a safety-net no-op
    (revoking an already-revoked cert is a harmless ScriptError, caught and
    ignored here, not surfaced). The gap this actually closes: if that
    earlier revoke attempt failed (e.g. a transient error) and was never
    retried, permanent delete would otherwise silently cascade-delete the
    VpnProfileLink row and leave the cert itself untouched -- live, but
    with no owning portal user, a real orphaned-access gap. Best-effort
    revoke + purge here closes it without blocking the delete itself on
    any failure (same log-and-continue pattern as every other hook in this
    module -- this is cleanup, not a precondition for the delete to
    proceed). Still fully skipped for a protected link, same as every
    other hook -- see this module's docstring."""
    link = user.vpn_profile_link
    if link is None or link.protected_from_auto_revoke:
        if link is not None:
            _log_sync_skipped_protected(db, "permanent_delete", link.vpn_client_name)
        return
    try:
        cli.revoke_client(link.vpn_client_name)
    except ScriptError:
        pass  # most likely already revoked by the earlier soft-delete -- not an error worth logging
    try:
        cli.purge_revoked(link.vpn_client_name)
    except ScriptError as e:
        _log_sync_failure(db, "permanent_delete->purge_revoked", link.vpn_client_name, e)
