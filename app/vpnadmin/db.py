"""
Database engine/session setup. Works transparently with either SQLite or
PostgreSQL depending on DATABASE_URL -- SQLAlchemy abstracts the dialect
difference, the models and queries elsewhere never need to know which one
is in use.
"""
import os

from sqlalchemy import Enum as SAEnum, create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import settings

_connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    # Needed because FastAPI/uvicorn may access the same connection from
    # different threads within a single async request lifecycle.
    _connect_args = {"check_same_thread": False}
    # Ensure the directory for a relative sqlite file (e.g. ./data/app.db)
    # exists before SQLAlchemy tries to open it.
    db_path = settings.DATABASE_URL.replace("sqlite:///", "", 1)
    if db_path and db_path != ":memory:":
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_engine_info() -> str:
    """Human-readable label for whichever database this deployment is
    actually using (e.g. 'PostgreSQL 16.10' or 'SQLite 3.45.1') -- surfaced
    on the Diagnostics page so an operator can see it at a glance instead of
    having to check .env. Falls back to just the dialect name if a version
    query fails for any reason (never raises -- this is diagnostic sugar,
    not something that should be able to break the page)."""
    try:
        if engine.dialect.name == "sqlite":
            with engine.connect() as conn:
                version = conn.exec_driver_sql("SELECT sqlite_version()").scalar()
            return f"SQLite {version}" if version else "SQLite"
        if engine.dialect.name == "postgresql":
            with engine.connect() as conn:
                version = conn.exec_driver_sql("SHOW server_version").scalar()
            return f"PostgreSQL {version}" if version else "PostgreSQL"
        return engine.dialect.name
    except Exception:
        return engine.dialect.name


def init_db():
    """Create all tables if they don't already exist, then reconcile any
    columns a model has that an already-existing table doesn't (e.g. after
    pulling an update that added a profile field to User). No real migration
    framework yet (see README) -- fine for v1's simple "add nullable column"
    changes on both SQLite and Postgres, worth replacing with Alembic if the
    schema ever needs something more involved (renames, backfills, drops)."""
    from . import models  # noqa: F401  (ensure models are registered on Base)
    Base.metadata.create_all(bind=engine)
    _sync_missing_columns()
    _sync_enum_values()
    _seed_rbac()


def _seed_rbac():
    """Phase 1 of the dynamic-RBAC rollout (see docs/rbac_identity_design.md
    and the joyful-sauteeing-cookie plan): seed the 4 system roles so
    role_id has something to point at. Split into its own function (rather
    than inlined in init_db) so Phase 2's migrate_user_roles() backfill can
    be added right after this call without further restructuring."""
    from .permissions import migrate_user_roles, rename_legacy_vpn_self_service_role, seed_system_roles
    db = SessionLocal()
    try:
        # Must run before seed_system_roles() -- see its own docstring for
        # why (a renamed-in-code slug would otherwise get re-seeded as a
        # duplicate row alongside the old one on an already-provisioned DB).
        rename_legacy_vpn_self_service_role(db)
        seed_system_roles(db)
        migrate_user_roles(db)  # Phase 2 backfill -- see permissions.py's docstring
    finally:
        db.close()


def _sync_missing_columns():
    # Each ALTER TABLE (+ its backfill UPDATE, see below) runs in its own
    # short transaction (engine.begin() per column) rather than one shared
    # transaction for every table/column -- SQLite implicitly manages
    # schema-changing DDL in a way that, chained many-deep inside a single
    # transaction alongside DML, has been observed to silently drop later
    # statements in that same transaction on newer sqlite3/Python builds
    # (no exception raised, no error logged -- the column addition just
    # doesn't stick). Committing after each column sidesteps that entirely
    # and is free either way: this function is already idempotent/safe to
    # call repeatedly (see test_sync_is_idempotent), so smaller transactions
    # change nothing about its semantics, only its reliability.
    inspector = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue  # brand new table, create_all already handled it
        existing = {col["name"] for col in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            ddl_type = column.type.compile(dialect=engine.dialect)
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {column.name} {ddl_type}"))
                # ALTER TABLE ADD COLUMN always leaves existing rows NULL
                # regardless of the model's `default=` (that's an
                # insert-time default, not applied retroactively) -- for
                # columns the model treats as non-nullable with a concrete
                # scalar default (e.g. deleted=False, gender=unspecified),
                # backfill those NULLs now so existing rows behave the same
                # as newly-created ones (e.g. `User.deleted.is_(False)`
                # filters would otherwise silently miss legacy rows, since
                # SQL NULL never equals False).
                default = getattr(column, "default", None)
                if default is not None and not getattr(default, "is_callable", False):
                    value = getattr(default, "arg", None)
                    if hasattr(value, "value"):  # enum member -> its stored value
                        value = value.value
                    if value is not None:
                        conn.execute(
                            text(f"UPDATE {table.name} SET {column.name} = :v WHERE {column.name} IS NULL"),
                            {"v": value},
                        )


def _sync_enum_values():
    """Adds any Python-side enum member missing from an existing PostgreSQL
    native enum TYPE (e.g. Role gaining 'editor' after Role.admin/viewer
    were already in production) -- caught the hard way: promoting a user
    to a role added after the DB was first created failed with
    psycopg2.errors.InvalidTextRepresentation, because create_all() only
    creates a TYPE once and never alters it afterward, and
    _sync_missing_columns() above only handles missing *columns*, not new
    *values* on an already-existing enum type.

    SQLite has no native enum type (SQLAlchemy renders Enum columns there
    as plain VARCHAR, nothing to alter), so this is a no-op there --
    intentionally scoped to postgresql only.

    ALTER TYPE ... ADD VALUE cannot run inside a transaction block, so this
    uses its own autocommit connection rather than engine.begin()."""
    if engine.dialect.name != "postgresql":
        return
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if not isinstance(column.type, SAEnum):
                continue
            pg_type_name = column.type.name
            if not pg_type_name:
                continue
            with engine.connect() as conn:
                existing = {
                    row[0] for row in conn.execute(
                        text(
                            "SELECT enumlabel FROM pg_enum "
                            "JOIN pg_type ON pg_enum.enumtypid = pg_type.oid "
                            "WHERE pg_type.typname = :type_name"
                        ),
                        {"type_name": pg_type_name},
                    )
                }
            if not existing:
                continue  # type doesn't exist yet -- create_all() will make it fresh, nothing to add
            if column.type.enum_class:
                missing = [m.value for m in column.type.enum_class if m.value not in existing]
            else:
                missing = [v for v in column.type.enums if v not in existing]
            for value in missing:
                # ADD VALUE takes a string literal, not a bind parameter --
                # safe to inline here since `value` always comes from our
                # own Python Enum definition, never user input. Escape any
                # embedded quote defensively anyway.
                escaped = value.replace("'", "''")
                with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                    conn.execute(text(f"ALTER TYPE {pg_type_name} ADD VALUE IF NOT EXISTS '{escaped}'"))
