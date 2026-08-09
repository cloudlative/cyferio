#!/usr/bin/env python3
"""
One-time data migration: copy every row from an existing SQLite
openvpn-toolkit database into a fresh Postgres database, preserving IDs,
foreign keys, and timestamps exactly.

Reuses the app's own SQLAlchemy models (vpnadmin.models) against BOTH
databases -- table/column definitions come from one place (the ORM), never
hand-translated SQL -- so this only has to move rows, not guess at types.

Usage:
    python3 scripts/migrate_sqlite_to_postgres.py \
        --sqlite-url sqlite:////opt/openvpn-toolkit/app/data/app.db \
        --postgres-url postgresql://vpnadmin:***@localhost:5432/vpnadmin

Safe to re-run: Postgres tables are created if missing (create_all), and
insertion is wrapped per-table so a table that already has rows in Postgres
is reported, not silently duplicated (see --verify-only and the
already-populated guard below).

This script only reads from SQLite -- it never modifies or deletes the
source file.
"""
import argparse
import sys
from pathlib import Path

# Make `vpnadmin` importable when run as `python3 scripts/this_file.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from vpnadmin.db import Base
from vpnadmin import models  # noqa: F401 -- registers all tables on Base


# Migration order matters: Team before User (user_teams FKs both), User
# before user_teams. AuditLog/AppSettings have no FK dependencies on
# anything else in this list, safe to do last.
TABLE_ORDER = ["teams", "users", "user_teams", "audit_log", "app_settings"]


def _session(url):
    engine = create_engine(url, future=True)
    return engine, sessionmaker(bind=engine, future=True)()


def _row_counts(engine):
    counts = {}
    inspector = inspect(engine)
    with engine.connect() as conn:
        for table in TABLE_ORDER:
            if not inspector.has_table(table):
                counts[table] = None  # table doesn't exist yet
                continue
            counts[table] = conn.exec_driver_sql(f"SELECT COUNT(*) FROM {table}").scalar()
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite-url", required=True, help="e.g. sqlite:////opt/openvpn-toolkit/app/data/app.db")
    parser.add_argument("--postgres-url", required=True, help="e.g. postgresql://user:pass@host:5432/dbname")
    parser.add_argument("--verify-only", action="store_true", help="Only print row counts on both sides, migrate nothing")
    args = parser.parse_args()

    src_engine, src_session = _session(args.sqlite_url)
    dst_engine, dst_session = _session(args.postgres_url)

    print("== Source (SQLite) row counts ==")
    src_counts = _row_counts(src_engine)
    for t, c in src_counts.items():
        print(f"  {t}: {c}")

    if args.verify_only:
        print("\n== Destination (Postgres) row counts ==")
        for t, c in _row_counts(dst_engine).items():
            print(f"  {t}: {c}")
        return

    # Create every table (teams, users, user_teams, audit_log, app_settings)
    # in Postgres via the same models the app itself uses.
    Base.metadata.create_all(bind=dst_engine)

    dst_counts_before = _row_counts(dst_engine)
    already_populated = [t for t, c in dst_counts_before.items() if c]
    if already_populated:
        print(f"\nRefusing to migrate: destination already has rows in {already_populated}. "
              f"Wipe those tables first if you intend to re-run this migration.", file=sys.stderr)
        sys.exit(1)

    model_by_table = {m.__tablename__: m for m in (models.Team, models.User, models.AuditLog, models.AppSettings)}

    print("\n== Migrating ==")
    for table_name in TABLE_ORDER:
        if table_name == "user_teams":
            # Pure association table -- no ORM model class, copy via Core.
            assoc = models.user_teams
            rows = src_session.execute(assoc.select()).mappings().all()
            for row in rows:
                dst_session.execute(assoc.insert().values(**dict(row)))
            dst_session.commit()
            print(f"  user_teams: {len(rows)} row(s) copied")
            continue

        model = model_by_table[table_name]
        objs = src_session.query(model).order_by(model.id).all()
        for obj in objs:
            data = {c.name: getattr(obj, c.name) for c in model.__table__.columns}
            dst_session.execute(model.__table__.insert().values(**data))
        dst_session.commit()
        print(f"  {table_name}: {len(objs)} row(s) copied")

        # Postgres SERIAL/IDENTITY sequences don't know about the explicit
        # ids we just inserted -- advance the sequence so the *next*
        # app-generated insert doesn't collide with a migrated id.
        if objs:
            max_id = max(o.id for o in objs)
            seq_name = f"{table_name}_id_seq"
            dst_session.execute(
                __import__("sqlalchemy").text(
                    f"SELECT setval('{seq_name}', :max_id)"
                ),
                {"max_id": max_id},
            )
            dst_session.commit()

    print("\n== Verification: row counts ==")
    src_final = _row_counts(src_engine)
    dst_final = _row_counts(dst_engine)
    all_match = True
    for t in TABLE_ORDER:
        match = src_final[t] == dst_final[t]
        all_match = all_match and match
        flag = "OK" if match else "MISMATCH"
        print(f"  {t}: sqlite={src_final[t]} postgres={dst_final[t]}  [{flag}]")

    if not all_match:
        print("\nRow count mismatch -- do NOT cut over DATABASE_URL yet.", file=sys.stderr)
        sys.exit(1)

    print("\nAll row counts match. Safe to point DATABASE_URL at Postgres.")


if __name__ == "__main__":
    main()
