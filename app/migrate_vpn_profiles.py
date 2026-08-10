#!/usr/bin/env python3
"""
migrate_vpn_profiles.py -- one-time (per-deployment) alignment of
pre-existing VPN client certificates with pre-existing portal user
accounts. See docs/rbac_identity_design.md §5 and the
joyful-sauteeing-cookie plan for the full design.

This is deliberately a standalone script, not a web page -- the task only
ever needs to run once per deployment (right after upgrading to a build
that includes the dynamic-RBAC/VPN-identity-sync feature), so a permanent
nav item and page for it would be dead weight in the UI forever after.
Run it manually, from inside the app container:

    docker compose exec app python migrate_vpn_profiles.py preview
    docker compose exec app python migrate_vpn_profiles.py run
    docker compose exec app python migrate_vpn_profiles.py last-report

(or `python migrate_vpn_profiles.py ...` directly if running outside
Docker with the app's venv and DATABASE_URL/etc. pointed at the real DB.)

Hard rule, unchanged from the original design: this script's `run` command
NEVER revokes, restores, or purges a VPN certificate -- it only reads the
current client list (cli_wrapper.list_clients(), read-only) and creates/
links portal accounts. Every link it creates is permanently
protected_from_auto_revoke=True (see VpnProfileLink's docstring in
models.py) -- confirmed twice by the user as a hard production-safety
constraint.
"""
import argparse
import getpass
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0] or ".")

from vpnadmin.db import SessionLocal, init_db  # noqa: E402
from vpnadmin import migration_engine  # noqa: E402


def _print_report(report: dict) -> None:
    if report.get("error"):
        print(f"Could not read the VPN client list: {report['error']}", file=sys.stderr)
        return

    linked = report.get("linked_existing", [])
    created = report.get("created_new_accounts", [])
    unmatched = report.get("unmatched_portal_users", [])
    conflicts = report.get("conflicts", [])

    print(f"\nAlready-matching accounts to link ({len(linked)}):")
    for e in linked:
        print(f"  {e['username']:24s} <-> {e['vpn_client_name']}  (role: {e['role']})")
    if not linked:
        print("  (none)")

    print(f"\nNew self-service accounts to create ({len(created)}):")
    for e in created:
        pw = f"  temp password: {e['temp_password']}" if "temp_password" in e else ""
        print(f"  {e['username']:24s} <-> {e['vpn_client_name']}{pw}")
    if not created:
        print("  (none)")

    print(f"\nPortal users with no matching VPN profile ({len(unmatched)}):")
    for e in unmatched:
        print(f"  {e['username']:24s} (role: {e['role']})")
    if not unmatched:
        print("  (none)")

    print(f"\nConflicts needing manual review ({len(conflicts)}):")
    for e in conflicts:
        print(f"  {e['vpn_client_name']:24s} {e['reason']}")
    if not conflicts:
        print("  (none)")
    print()


def cmd_preview(_args) -> int:
    init_db()  # ensures the schema/seeded roles exist, same as the app's own startup
    db = SessionLocal()
    try:
        report = migration_engine.compute_report(db)
    finally:
        db.close()
    print("=== PREVIEW -- nothing has been changed ===")
    _print_report(report)
    if report.get("created_new_accounts") or report.get("linked_existing"):
        print("Run with the 'run' command to apply this.")
    else:
        print("Nothing to do -- every active VPN client already has a linked portal account.")
    return 0


def cmd_run(args) -> int:
    init_db()
    db = SessionLocal()
    try:
        preview = migration_engine.compute_report(db)
        if preview.get("error"):
            print(f"Could not read the VPN client list: {preview['error']}", file=sys.stderr)
            return 1
        if not (preview.get("created_new_accounts") or preview.get("linked_existing")):
            print("Nothing to do -- every active VPN client already has a linked portal account.")
            return 0

        print("=== The following will be applied ===")
        _print_report(preview)
        if not args.yes:
            answer = input("Apply this? Type 'yes' to continue: ").strip().lower()
            if answer != "yes":
                print("Aborted -- nothing was changed.")
                return 1

        run_by = f"cli:{getpass.getuser()}"
        report = migration_engine.apply_migration(db, run_by=run_by)
    finally:
        db.close()

    print("\n=== Done ===")
    _print_report(report)
    created = report.get("created_new_accounts", [])
    if created:
        print(
            "IMPORTANT: the temp passwords above are shown ONLY here, right now -- "
            "they are not recoverable later (not even via 'last-report'). "
            "Relay them to each user out-of-band before closing this terminal."
        )
    return 0


def cmd_last_report(_args) -> int:
    init_db()
    db = SessionLocal()
    try:
        report = migration_engine.get_last_report(db)
    finally:
        db.close()
    if report is None:
        print("No migration has been run yet.")
        return 0
    print(f"Last run: {report['run_at']} by {report['run_by']} (preview={report['is_preview']})")
    _print_report(report)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1] if __doc__ else "")
    sub = parser.add_subparsers(dest="command", required=True)

    p_preview = sub.add_parser("preview", help="Show what a run would do -- read-only, changes nothing.")
    p_preview.set_defaults(func=cmd_preview)

    p_run = sub.add_parser("run", help="Apply the migration (creates/links portal accounts).")
    p_run.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt.")
    p_run.set_defaults(func=cmd_run)

    p_last = sub.add_parser("last-report", help="Show the most recently persisted migration report.")
    p_last.set_defaults(func=cmd_last_report)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
