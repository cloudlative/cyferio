#!/usr/bin/env python3
"""
drop_legacy_branding_columns.py -- one-time (per-deployment) cleanup that
drops the app_settings.app_name / app_tagline / app_footer_credit columns,
left behind after the Cyferio rebrand removed them as admin-configurable
settings (see app_settings.py: app_name is now a fixed "Cyferio" constant,
tagline/footer credit are gone entirely). This repo has no Alembic --
db.py's init_db()/_sync_missing_columns() reconciler only ever ADDs columns,
never drops them -- so this script exists purely to finish that one-time
schema cleanup on an already-provisioned database. Safe to skip forever:
leaving these three nullable, unread columns in place breaks nothing.

Run it manually, from inside the app container:

    docker compose exec app python drop_legacy_branding_columns.py preview
    docker compose exec app python drop_legacy_branding_columns.py run

(or `python drop_legacy_branding_columns.py ...` directly if running outside
Docker with the app's venv and DATABASE_URL/etc. pointed at the real DB.)

Idempotent: `run` skips any column that's already gone, so it's safe to run
again (e.g. against a database that already had this applied).
"""

import argparse
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0] or ".")

from sqlalchemy import inspect, text  # noqa: E402

from vpnadmin.db import engine  # noqa: E402

_COLUMNS = ("app_name", "app_tagline", "app_footer_credit")


def _existing_columns() -> set[str]:
    inspector = inspect(engine)
    if not inspector.has_table("app_settings"):
        return set()
    return {c["name"] for c in inspector.get_columns("app_settings")}


def cmd_preview(_args) -> int:
    existing = _existing_columns()
    present = [c for c in _COLUMNS if c in existing]
    print("=== PREVIEW -- nothing has been changed ===")
    if not present:
        print("Nothing to do -- none of the legacy branding columns are present.")
        return 0
    print(f"Columns to drop from app_settings ({len(present)}):")
    for c in present:
        print(f"  {c}")
    print("\nRun with the 'run' command to apply this.")
    return 0


def cmd_run(args) -> int:
    existing = _existing_columns()
    present = [c for c in _COLUMNS if c in existing]
    if not present:
        print("Nothing to do -- none of the legacy branding columns are present.")
        return 0

    print(f"The following columns will be dropped from app_settings: {', '.join(present)}")
    if not args.yes:
        answer = input("Apply this? Type 'yes' to continue: ").strip().lower()
        if answer != "yes":
            print("Aborted -- nothing was changed.")
            return 1

    for column in present:
        with engine.begin() as conn:
            # column is always one of the hardcoded _COLUMNS tuple above, not user input
            conn.execute(text(f"ALTER TABLE app_settings DROP COLUMN {column}"))  # nosemgrep: avoid-sqlalchemy-text
        print(f"  dropped {column}")
    print("Done.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1] if __doc__ else "")
    sub = parser.add_subparsers(dest="command", required=True)

    p_preview = sub.add_parser("preview", help="Show what a run would do -- read-only, changes nothing.")
    p_preview.set_defaults(func=cmd_preview)

    p_run = sub.add_parser("run", help="Apply the column drop.")
    p_run.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt.")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
