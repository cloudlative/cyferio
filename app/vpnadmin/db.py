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
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue  # brand new table, create_all already handled it
            existing = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                ddl_type = column.type.compile(dialect=engine.dialect)
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
