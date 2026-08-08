"""
Database engine/session setup. Works transparently with either SQLite or
PostgreSQL depending on DATABASE_URL -- SQLAlchemy abstracts the dialect
difference, the models and queries elsewhere never need to know which one
is in use.
"""
import os

from sqlalchemy import create_engine
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
    """Create all tables if they don't already exist. No migration framework
    yet (see README) -- fine for v1, worth revisiting (Alembic) once the
    schema needs to evolve on an existing deployment's data."""
    from . import models  # noqa: F401  (ensure models are registered on Base)
    Base.metadata.create_all(bind=engine)
