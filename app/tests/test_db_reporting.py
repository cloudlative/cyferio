"""Tests for Database Reporting (Phase 3): the DbStatSnapshot writer, the
history delta/cache-hit-ratio math, GET /api/reports/database's permission
gate, and the new db_reporting permission object's seeded viewer exclusion.

The test suite always runs against SQLite (see conftest.py's db_session
fixture) -- write_db_stat_snapshot()/GET /api/reports/database's
Postgres-only paths are exercised here only via their documented
fail-soft/available=False behavior on a non-Postgres engine, not against
a real Postgres instance."""

from datetime import UTC, datetime, timedelta

from vpnadmin.health import write_db_stat_snapshot
from vpnadmin.models import DbStatSnapshot
from vpnadmin.permissions import has_permission_any_scope
from vpnadmin.routes.reports import _history_with_deltas

from .conftest import login


class TestWriteDbStatSnapshot:
    def test_inserts_a_row_even_on_sqlite(self, db_session):
        write_db_stat_snapshot(db_session)
        rows = db_session.query(DbStatSnapshot).all()
        assert len(rows) == 1
        # Every numeric stat stays None on a non-Postgres engine -- same
        # "NULL, not missing/broken" stance get_database_health() already
        # takes, not an error.
        assert rows[0].db_size_bytes is None
        assert rows[0].active_connections is None
        assert rows[0].timestamp is not None  # the row itself always gets written


class TestHistoryWithDeltas:
    def test_first_row_has_no_rate(self):
        t0 = datetime(2026, 8, 1, tzinfo=UTC)
        rows = [DbStatSnapshot(timestamp=t0, xact_commit=100, xact_rollback=5, blks_hit=900, blks_read=100)]
        result = _history_with_deltas(rows)
        assert result[0]["commits_per_min"] is None
        assert result[0]["cache_hit_ratio"] is None

    def test_computes_rate_and_cache_hit_ratio_between_consecutive_rows(self):
        t0 = datetime(2026, 8, 1, tzinfo=UTC)
        rows = [
            DbStatSnapshot(timestamp=t0, xact_commit=100, xact_rollback=5, blks_hit=900, blks_read=100),
            DbStatSnapshot(timestamp=t0 + timedelta(minutes=10), xact_commit=200, xact_rollback=10, blks_hit=1900, blks_read=200),
        ]
        result = _history_with_deltas(rows)
        assert result[1]["commits_per_min"] == 10.0  # (200-100)/10min
        assert result[1]["rollbacks_per_min"] == 0.5  # (10-5)/10min
        assert result[1]["cache_hit_ratio"] == round(100 * 1000 / 1100, 2)  # d_hit=1000, d_read=100

    def test_counter_reset_floors_at_zero_not_negative(self):
        t0 = datetime(2026, 8, 1, tzinfo=UTC)
        rows = [
            DbStatSnapshot(timestamp=t0, xact_commit=500, xact_rollback=50, blks_hit=5000, blks_read=500),
            DbStatSnapshot(timestamp=t0 + timedelta(minutes=10), xact_commit=10, xact_rollback=2, blks_hit=100, blks_read=10),
        ]
        result = _history_with_deltas(rows)
        assert result[1]["commits_per_min"] == 0.0
        assert result[1]["rollbacks_per_min"] == 0.0

    def test_point_in_time_fields_pass_through_unchanged(self):
        t0 = datetime(2026, 8, 1, tzinfo=UTC)
        rows = [DbStatSnapshot(timestamp=t0, db_size_bytes=12345, active_connections=3, idle_connections=7, waiting_locks_count=1, long_running_query_count=2)]
        result = _history_with_deltas(rows)
        assert result[0]["db_size_bytes"] == 12345
        assert result[0]["active_connections"] == 3
        assert result[0]["idle_connections"] == 7
        assert result[0]["waiting_locks_count"] == 1
        assert result[0]["long_running_query_count"] == 2


class TestDatabaseReportEndpoint:
    def test_admin_gets_unavailable_on_sqlite(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/reports/database")
        assert r.status_code == 200
        data = r.json()
        assert data["available"] is False
        assert "PostgreSQL" in data["reason"]
        assert data["current"] is None
        assert data["history"] == []

    def test_viewer_is_forbidden(self, app_client, db_session):
        # db_reporting is deliberately excluded from the seeded Viewer
        # role -- see permissions.py's OBJECTS entry and viewer's
        # exclusion tuple.
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/reports/database")
        assert r.status_code == 403

    def test_unauthenticated_is_401(self, app_client, db_session):
        r = app_client.get("/api/reports/database")
        assert r.status_code == 401


class TestDbReportingPermissionSeeding:
    def test_viewer_role_excludes_db_reporting(self, app_client, db_session):
        from vpnadmin.models import User

        viewer_user = db_session.query(User).filter_by(username="viewer").one()
        assert has_permission_any_scope(db_session, viewer_user, "db_reporting", "view") is False

    def test_admin_role_includes_db_reporting(self, app_client, db_session):
        from vpnadmin.models import User

        admin_user = db_session.query(User).filter_by(username="admin").one()
        assert has_permission_any_scope(db_session, admin_user, "db_reporting", "view") is True
