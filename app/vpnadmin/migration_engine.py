"""
The one-time (per-deployment) migration that links pre-existing VPN clients
to pre-existing portal users -- see docs/rbac_identity_design.md §5 and the
joyful-sauteeing-cookie plan.

Deliberately NOT exposed as a web page/API (see that decision's rationale in
the plan doc) -- this is a one-off task run by whoever operates the
deployment, once, via migrate_vpn_profiles.py at the repo root. Kept as its
own module (not inlined in that script) so the matching/write logic is
independently testable without spinning up a CLI process, same reasoning as
any other business logic living in vpnadmin/ rather than in a route or
script file.

Hard rule: this module NEVER calls anything in cli_wrapper that mutates a
VPN client (add_client/revoke_client/restore_client/purge_revoked) -- only
cli.list_clients() (read-only). Every VpnProfileLink it creates gets
protected_from_auto_revoke=True, permanently (see VpnProfileLink's
docstring in models.py) -- confirmed twice by the user as a hard
production-safety constraint, not just a migration-time nicety.

preview() and apply() share the exact same matching algorithm (compute_report)
so what a preview shows is guaranteed to be what apply() actually does --
apply() just additionally writes the rows.
"""
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import cli_wrapper as cli
from .auth import hash_password
from .cli_wrapper import ScriptError
from .models import MigrationReport, Role, RoleDef, User, VpnProfileLink
from .vpn_identity_sync import generate_temp_password


def _role_slug(u: User) -> str:
    return u.role_def.slug if u.role_def is not None else u.role.value


def compute_report(db: Session) -> dict:
    """Read-only: never writes to the DB, never calls a mutating
    cli_wrapper function. Returns the exact shape documented in
    docs/rbac_identity_design.md §5."""
    try:
        clients = cli.list_clients()
    except ScriptError as e:
        return {"error": e.message, "linked_existing": [], "created_new_accounts": [],
                "unmatched_portal_users": [], "conflicts": []}

    client_names = [c["name"] for c in (clients or []) if "name" in c]
    already_linked = {link.vpn_client_name for link in db.query(VpnProfileLink).all()}
    users_by_username = {u.username: u for u in db.query(User).filter(User.deleted.is_(False)).all()}
    matched_usernames: set[str] = set()

    linked_existing = []
    created_new_accounts = []
    conflicts = []

    for name in client_names:
        if name in already_linked:
            continue  # already handled (either from a previous migration run or add_client's own auto-link)
        normalized = name.strip().lower()  # same normalization as User._normalize_username
        user = users_by_username.get(normalized)
        if user is None:
            created_new_accounts.append({"vpn_client_name": name, "username": normalized})
            continue
        if user.vpn_profile_link is not None:
            conflicts.append({
                "vpn_client_name": name,
                "reason": f"username '{normalized}' matches this client but is already linked to "
                          f"a different VPN profile ('{user.vpn_profile_link.vpn_client_name}').",
            })
            continue
        linked_existing.append({"username": user.username, "vpn_client_name": name, "role": _role_slug(user)})
        matched_usernames.add(normalized)

    unmatched_portal_users = [
        {"username": u.username, "role": _role_slug(u)}
        for u in users_by_username.values()
        if u.vpn_profile_link is None and u.username not in matched_usernames
    ]

    return {
        "linked_existing": linked_existing,
        "created_new_accounts": created_new_accounts,
        "unmatched_portal_users": unmatched_portal_users,
        "conflicts": conflicts,
    }


def apply_migration(db: Session, *, run_by: str) -> dict:
    """Writes: creates VpnProfileLink rows (protected_from_auto_revoke=True,
    no exceptions -- see this module's docstring) for both buckets, creates
    new vpn_self_service User rows for unmatched clients, and persists the
    resulting report to MigrationReport. `run_by` is a free-text actor
    label (a portal username if run on behalf of one, or an operator
    identifier like "cli:<unix-username>" -- see migrate_vpn_profiles.py) --
    stored the same way AuditLog.username already is, a snapshot string,
    not a foreign key."""
    report = compute_report(db)

    vss_role = db.query(RoleDef).filter_by(slug="vpn_self_service").first()
    created_accounts_out = []
    for entry in report["created_new_accounts"]:
        temp_password = generate_temp_password()
        user = User(
            username=entry["username"],
            password_hash=hash_password(temp_password),
            role=Role.viewer,  # legacy enum has no vpn_self_service member -- see users.py's _resolve_role comment
            role_id=vss_role.id if vss_role is not None else None,
            first_name=entry["vpn_client_name"],
            must_reset_password=True,
        )
        db.add(user)
        db.flush()
        db.add(VpnProfileLink(
            user_id=user.id, vpn_client_name=entry["vpn_client_name"],
            link_source="migration_exact_match", protected_from_auto_revoke=True,
            linked_by=run_by,
        ))
        created_accounts_out.append({**entry, "temp_password": temp_password})

    for entry in report["linked_existing"]:
        user = db.query(User).filter_by(username=entry["username"]).first()
        db.add(VpnProfileLink(
            user_id=user.id, vpn_client_name=entry["vpn_client_name"],
            link_source="migration_exact_match", protected_from_auto_revoke=True,
            linked_by=run_by,
        ))

    db.commit()

    final_report = {**report, "created_new_accounts": created_accounts_out}
    # Persist a redacted copy -- temp passwords must be shown exactly once,
    # at the terminal that ran this, and nowhere else afterward (not this
    # DB row, not get_last_report(), not any future UI). Strip them before
    # they ever reach the DB rather than trying to redact on the way out.
    redacted_created = [{k: v for k, v in e.items() if k != "temp_password"} for e in created_accounts_out]
    persisted_report = {**report, "created_new_accounts": redacted_created}
    db.add(MigrationReport(run_by=run_by, is_preview=False, report_json=json.dumps(persisted_report)))
    db.commit()
    return final_report


def get_last_report(db: Session) -> dict | None:
    row = db.query(MigrationReport).order_by(MigrationReport.run_at.desc()).first()
    if row is None:
        return None
    return {
        "run_at": row.run_at.isoformat(),
        "run_by": row.run_by,
        "is_preview": row.is_preview,
        **json.loads(row.report_json),
    }


def has_pending_work(db: Session) -> bool:
    """True if a preview would report anything actionable (new accounts to
    create or existing ones to link) -- not used by any UI (there isn't
    one), but useful for an ops script/cron/healthcheck to decide whether
    migrate_vpn_profiles.py needs a run, without printing the full report."""
    report = compute_report(db)
    return bool(report.get("created_new_accounts") or report.get("linked_existing"))
