"""Super Admin Recovery Mechanism -- the ONLY path back onto the bootstrap
admin account (User.is_bootstrap_admin) once its password/MFA/lockout state
is lost, since every in-app write path (routes/users.py:1249,1629,1654,
routes/groups.py:335) deliberately refuses to touch that account, and no
other account can hold the super_admin role to act on its behalf (see
permissions.py's ensure_super_admin_group/promote_bootstrap_admin_to_
super_admin -- the bootstrap account IS how that role ever gets seeded in
the first place).

Deliberately NOT an API endpoint, local-only or otherwise -- see the
approved design proposal's own "why CLI-over-shell" section. This module is
invoked exclusively via `recover-admin.sh` (repo root, alongside upgrade.sh/
add-machine.sh), which runs `docker exec` into the live app container --
same "already has root/shell on the box" trust boundary as every other
irreversible operation in this repo, and the one boundary that isn't itself
guarded by the RBAC system this tool exists to recover from.

Every action here bypasses routes/users.py and routes/mfa_routes.py
entirely (that's the point -- those are exactly what's locked), writing
directly to the ORM. Reuses the SAME primitives those routes call
(hash_password, mfa.replace_recovery_codes) so a recovered account is in
exactly the state a normal admin-console action would have left it in --
never a parallel, weaker code path. Every action is still audit-logged, via
a direct AuditLog insert (same "no real actor User row for this" pattern as
vpn_identity_sync.py's own _SYSTEM_ACTOR) rather than audit.log_action
(which requires one) -- so a recovery run shows up in the admin console's
own Audit Log like any other action, even though it went around the API.

Usage (always via the wrapper script, never called directly in normal use):
    python -m vpnadmin.cli_recover_admin --yes [--reset-password] [--clear-mfa] [--unlock] [--regenerate-recovery-codes]
"""
import argparse
import getpass
import os
import socket
import sys

from .auth import hash_password
from .db import SessionLocal
from .mfa import replace_recovery_codes
from .models import AuditLog, MfaRecoveryCode, User
from .vpn_identity_sync import generate_temp_password


def _actor() -> str:
    """Who ran this -- captured for the audit trail the same way upgrade.sh
    itself is attributed nowhere else in this app (it isn't a request, so
    there's no session/username to read). $SUDO_USER covers the common
    `sudo ./recover-admin.sh` invocation; falls back to whoever the shell
    thinks is running otherwise."""
    who = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        host = socket.gethostname()
    except OSError:
        host = "unknown-host"
    return f"{who}@{host}"


def _audit(db, action: str, target: User, detail: str) -> None:
    db.add(AuditLog(username=f"cli:recover-admin.sh ({_actor()})", action=action, target=target.username, detail=detail, success=True))
    db.commit()


def _get_bootstrap_admin(db) -> User:
    admin = db.query(User).filter(User.is_bootstrap_admin.is_(True)).one_or_none()
    if admin is None:
        raise SystemExit(
            "No bootstrap admin account exists in this database -- there's nothing for this tool to recover. "
            "If this is a fresh install, restart the app once (it seeds one on first boot); if the account "
            "was deleted, that's beyond what this tool restores -- see auth.ensure_bootstrap_admin_flag."
        )
    if admin.deleted:
        # Recovering access is meaningless if the row itself is still
        # soft-deleted -- restore it as part of any recovery run, same as
        # every action below leaves the account in the state a normal
        # admin-console action would have. Committed here (rather than
        # left for whichever flag's own commit happens to run) since
        # --regenerate-recovery-codes on a non-MFA account returns before
        # committing anything else.
        admin.deleted = False
        admin.deleted_at = None
        db.commit()
    return admin


def reset_password(db, admin: User) -> None:
    new_password = generate_temp_password()
    admin.password_hash = hash_password(new_password)
    # See models.py's must_reset_password docstring -- forces a real,
    # policy-checked password through the normal login flow at the very
    # next sign-in rather than leaving this generated one live indefinitely.
    admin.must_reset_password = True
    admin.failed_login_attempts = 0
    admin.locked_until = None
    db.commit()
    _audit(db, "bootstrap_admin_recovered", admin, "password reset via recover-admin.sh")
    print(f"New temporary password for '{admin.username}': {new_password}")
    print("This is shown once and not stored anywhere -- copy it now. You'll be required to set a new one at next login.")


def clear_mfa(db, admin: User) -> None:
    admin.mfa_enabled = False
    admin.mfa_secret_encrypted = None
    admin.mfa_setup_required = True
    admin.mfa_failed_attempts = 0
    admin.mfa_locked_until = None
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == admin.id).delete()
    db.commit()
    _audit(db, "bootstrap_admin_recovered", admin, "MFA cleared via recover-admin.sh; re-enrollment required at next login")
    print(f"MFA cleared for '{admin.username}' -- they'll be asked to re-enroll at next login.")


def unlock(db, admin: User) -> None:
    admin.failed_login_attempts = 0
    admin.locked_until = None
    admin.mfa_failed_attempts = 0
    admin.mfa_locked_until = None
    db.commit()
    _audit(db, "bootstrap_admin_recovered", admin, "lockout cleared via recover-admin.sh")
    print(f"'{admin.username}' is unlocked (password and MFA lockout counters both cleared).")


def regenerate_recovery_codes(db, admin: User) -> None:
    if not admin.mfa_enabled:
        print(f"'{admin.username}' doesn't currently have MFA enabled -- recovery codes only make sense for an enrolled account. Skipped.")
        return
    codes = replace_recovery_codes(admin, db)
    db.commit()
    _audit(db, "bootstrap_admin_recovered", admin, "recovery codes regenerated via recover-admin.sh")
    print(f"New recovery codes for '{admin.username}' (each usable once -- shown only now, not stored anywhere):")
    for code in codes:
        print(f"  {code}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m vpnadmin.cli_recover_admin",
        description="Break-glass recovery for the bootstrap super admin account. Always run via recover-admin.sh, not directly.",
    )
    parser.add_argument("--reset-password", action="store_true")
    parser.add_argument("--clear-mfa", action="store_true")
    parser.add_argument("--unlock", action="store_true")
    parser.add_argument("--regenerate-recovery-codes", action="store_true")
    parser.add_argument("--yes", action="store_true", help="Required -- confirms this is an intentional recovery run, not an accidental invocation.")
    args = parser.parse_args(argv)

    actions = [args.reset_password, args.clear_mfa, args.unlock, args.regenerate_recovery_codes]
    if not any(actions):
        parser.error("Nothing to do -- pass at least one of --reset-password, --clear-mfa, --unlock, --regenerate-recovery-codes.")
    if not args.yes:
        parser.error("Refusing to act without --yes (recover-admin.sh already asks for interactive confirmation before it gets here).")

    db = SessionLocal()
    try:
        admin = _get_bootstrap_admin(db)
        print(f"Recovering bootstrap admin account: {admin.username}")
        if args.unlock:
            unlock(db, admin)
        if args.clear_mfa:
            clear_mfa(db, admin)
        if args.regenerate_recovery_codes:
            regenerate_recovery_codes(db, admin)
        if args.reset_password:
            reset_password(db, admin)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
