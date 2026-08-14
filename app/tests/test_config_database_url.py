"""Tests for config.py's _default_database_url() -- Postgres-by-default
fallback logic (see its own docstring for the full reasoning)."""

from vpnadmin.config import _default_database_url


class TestDefaultDatabaseUrl:
    def test_explicit_database_url_always_wins(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "sqlite:///./custom.db")
        monkeypatch.setenv("POSTGRES_PASSWORD", "somepassword")
        assert _default_database_url() == "sqlite:///./custom.db"

    def test_explicit_database_url_wins_even_without_postgres_configured(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://custom:pw@otherhost/db")
        monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
        assert _default_database_url() == "postgresql://custom:pw@otherhost/db"

    def test_postgres_password_present_builds_postgres_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("POSTGRES_PASSWORD", "s3cret")
        monkeypatch.delenv("POSTGRES_USER", raising=False)
        monkeypatch.delenv("POSTGRES_DB", raising=False)
        assert _default_database_url() == "postgresql://vpnadmin:s3cret@postgres:5432/vpnadmin"

    def test_postgres_user_and_db_overrides_respected(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("POSTGRES_PASSWORD", "s3cret")
        monkeypatch.setenv("POSTGRES_USER", "customuser")
        monkeypatch.setenv("POSTGRES_DB", "customdb")
        assert _default_database_url() == "postgresql://customuser:s3cret@postgres:5432/customdb"

    def test_neither_set_falls_back_to_sqlite(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
        assert _default_database_url() == "sqlite:///./data/app.db"
