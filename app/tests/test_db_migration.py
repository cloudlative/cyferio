"""
Tests for db._sync_missing_columns(), the lightweight auto-migration that
adds columns a model gained after a table already existed in production
(e.g. this exact repo's users table, deployed before first_name/gender/
team/deleted/etc. existed). Uses a separate in-memory engine seeded with a
deliberately old-shaped `users` table -- not the full ORM model -- so this
actually exercises the "existing deployment, new code" scenario rather than
a table that was always up to date.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

from vpnadmin.db import _sync_missing_columns as sync_missing_columns


def _make_old_schema_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as conn:
        # Mirrors the pre-profile-fields users table shape.
        conn.execute(
            text("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username VARCHAR(64) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(16) NOT NULL,
                is_active BOOLEAN NOT NULL,
                created_at DATETIME NOT NULL
            )
        """)
        )
        conn.execute(
            text("INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES ('legacyadmin', 'hash', 'admin', 1, '2026-01-01 00:00:00')")
        )
        conn.execute(text("CREATE TABLE audit_log (id INTEGER PRIMARY KEY)"))
    return engine


def test_sync_adds_missing_columns(monkeypatch):
    import vpnadmin.db as db_mod

    engine = _make_old_schema_engine()
    monkeypatch.setattr(db_mod, "engine", engine)

    from sqlalchemy import inspect

    before = {c["name"] for c in inspect(engine).get_columns("users")}
    assert "gender" not in before
    assert "deleted" not in before

    sync_missing_columns()

    after = {c["name"] for c in inspect(engine).get_columns("users")}
    for col in ("first_name", "last_name", "gender", "team_id", "last_login_at", "deleted", "deleted_at"):
        assert col in after


def test_sync_backfills_nonnull_defaults_on_existing_rows(monkeypatch):
    import vpnadmin.db as db_mod

    engine = _make_old_schema_engine()
    monkeypatch.setattr(db_mod, "engine", engine)

    sync_missing_columns()

    with engine.connect() as conn:
        row = conn.execute(text("SELECT deleted, gender FROM users WHERE username='legacyadmin'")).one()
    # Must be backfilled to concrete values, not left NULL -- a NULL
    # `deleted` would silently break `User.deleted.is_(False)` filters used
    # throughout routes/users.py (SQL NULL never equals False).
    assert row[0] in (0, False)
    assert row[1] == "unspecified"


def test_sync_is_idempotent(monkeypatch):
    import vpnadmin.db as db_mod

    engine = _make_old_schema_engine()
    monkeypatch.setattr(db_mod, "engine", engine)

    sync_missing_columns()
    sync_missing_columns()  # must not error on already-migrated columns
