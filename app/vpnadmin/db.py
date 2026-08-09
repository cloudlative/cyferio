"""
Database engine/session setup. Works transparently with either SQLite or
PostgreSQL depending on DATABASE_URL -- SQLAlchemy abstracts the dialect
difference, the models and queries elsewhere never need to know which one
is in use.
"""
import os

from sqlalchemy import create_engine, inspect, text
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
