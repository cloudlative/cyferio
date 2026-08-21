"""Tests for the Release Availability Indicator/Popup -- release_check.py's
caching/classification logic, routes/release.py's lazy status endpoint,
and the Upgrade Assignment Workflow's auto-ticket-filing. Every test mocks
the actual GitHub HTTP call (release_check._fetch_latest_release) --
never hits the real GitHub API."""
from datetime import datetime, timezone

from vpnadmin import release_check
from vpnadmin.models import SupportTicket

from .conftest import login


class TestClassify:
    def test_same_version_is_up_to_date(self):
        assert release_check.classify("v1.2.0", "v1.2.0", None, None, critical_on_major_bump=True) == "up_to_date"

    def test_older_latest_is_up_to_date(self):
        assert release_check.classify("v2.0.0", "v1.9.0", None, None, critical_on_major_bump=True) == "up_to_date"

    def test_patch_bump_is_update_available(self):
        assert release_check.classify("v1.2.0", "v1.2.1", None, None, critical_on_major_bump=True) == "update_available"

    def test_minor_bump_is_update_available(self):
        assert release_check.classify("v1.2.0", "v1.3.0", None, None, critical_on_major_bump=True) == "update_available"

    def test_major_bump_is_critical_when_enabled(self):
        assert release_check.classify("v1.2.0", "v2.0.0", None, None, critical_on_major_bump=True) == "critical_update"

    def test_major_bump_is_not_critical_when_disabled(self):
        assert release_check.classify("v1.2.0", "v2.0.0", None, None, critical_on_major_bump=False) == "update_available"

    def test_security_keyword_in_body_is_critical(self):
        assert release_check.classify("v1.2.0", "v1.2.1", "Routine fixes", "This patches a SECURITY vulnerability.",
                                       critical_on_major_bump=True) == "critical_update"

    def test_critical_keyword_in_name_is_critical(self):
        assert release_check.classify("v1.2.0", "v1.2.1", "Critical hotfix", None, critical_on_major_bump=True) == "critical_update"

    def test_unparseable_tag_is_up_to_date(self):
        assert release_check.classify("v1.2.0", "not-a-version", None, None, critical_on_major_bump=True) == "up_to_date"


class TestCaching:
    def test_disabled_returns_cache_without_fetching(self, monkeypatch):
        from vpnadmin import app_settings
        called = []
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: called.append(1))
        app_settings.runtime.release_check_enabled = False
        try:
            result = release_check.check_for_new_release()
        finally:
            app_settings.runtime.release_check_enabled = True
        assert called == []
        assert result["status"] == "up_to_date"

    def test_fresh_check_populates_cache(self, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: {
            "tag_name": "v9.9.9", "name": "Big release", "body": "notes",
            "html_url": "https://github.com/x/y/releases/tag/v9.9.9", "published_at": "2026-01-01T00:00:00Z",
        })
        result = release_check.check_for_new_release(force=True)
        assert result["latest_tag"] == "v9.9.9"
        assert result["status"] in ("update_available", "critical_update")

    def test_second_call_within_interval_does_not_refetch(self, monkeypatch):
        calls = []

        def _fetch(*a, **k):
            calls.append(1)
            return {"tag_name": "v9.9.9", "name": None, "body": None, "html_url": None, "published_at": None}
        monkeypatch.setattr(release_check, "_fetch_latest_release", _fetch)
        release_check.check_for_new_release(force=True)
        release_check.check_for_new_release()  # not forced, cache is fresh -- no second fetch
        assert len(calls) == 1

    def test_failed_fetch_keeps_last_known_state(self, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: {
            "tag_name": "v9.9.9", "name": None, "body": None, "html_url": None, "published_at": None,
        })
        release_check.check_for_new_release(force=True)

        def _boom(*a, **k):
            raise RuntimeError("network down")
        monkeypatch.setattr(release_check, "_fetch_latest_release", _boom)
        result = release_check.check_for_new_release(force=True)
        assert result["latest_tag"] == "v9.9.9"  # unchanged from before the failure
        assert result["error"] == "network down"

    def test_no_releases_published_is_up_to_date(self, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: None)
        result = release_check.check_for_new_release(force=True)
        assert result["status"] == "up_to_date"
        assert result["latest_tag"] is None


class TestFileUpgradeTicket:
    def test_files_a_ticket_for_a_new_release(self, db_session, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: {
            "tag_name": "v9.9.9", "name": "Big release", "body": "Some notes",
            "html_url": "https://github.com/x/y/releases/tag/v9.9.9", "published_at": "2026-01-01T00:00:00Z",
        })
        from vpnadmin.auth import hash_password
        from vpnadmin.models import Role, User
        admin = User(username="admin", password_hash=hash_password("adminpass123"), role=Role.admin)
        db_session.add(admin)
        db_session.commit()

        release_check.check_for_new_release(force=True)
        ticket = release_check.file_upgrade_ticket(db_session)
        assert ticket is not None
        assert ticket.category == "sysmaint_application_upgrade"
        assert "v9.9.9" in ticket.subject

    def test_idempotent_per_release_tag(self, db_session, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: {
            "tag_name": "v9.9.9", "name": None, "body": None, "html_url": None, "published_at": None,
        })
        from vpnadmin.auth import hash_password
        from vpnadmin.models import Role, User
        admin = User(username="admin", password_hash=hash_password("adminpass123"), role=Role.admin)
        db_session.add(admin)
        db_session.commit()

        release_check.check_for_new_release(force=True)
        first = release_check.file_upgrade_ticket(db_session)
        second = release_check.file_upgrade_ticket(db_session)
        assert first is not None
        assert second is None
        assert db_session.query(SupportTicket).count() == 1

    def test_security_keyword_files_security_update_category(self, db_session, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: {
            "tag_name": "v9.9.9", "name": None, "body": "Fixes a SECURITY issue.", "html_url": None, "published_at": None,
        })
        from vpnadmin.auth import hash_password
        from vpnadmin.models import Role, User
        admin = User(username="admin", password_hash=hash_password("adminpass123"), role=Role.admin)
        db_session.add(admin)
        db_session.commit()

        release_check.check_for_new_release(force=True)
        ticket = release_check.file_upgrade_ticket(db_session)
        assert ticket.category == "sysmaint_security_update"
        assert ticket.priority == "high"


class TestReleaseStatusRoute:
    def test_admin_can_check_release_status(self, app_client, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: {
            "tag_name": "v9.9.9", "name": None, "body": None, "html_url": None, "published_at": None,
        })
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/release/status")
        assert r.status_code == 200
        body = r.json()
        assert body["latest_version"] == "v9.9.9"
        assert body["status"] in ("update_available", "critical_update")

    def test_status_check_auto_files_upgrade_ticket(self, app_client, monkeypatch):
        monkeypatch.setattr(release_check, "_fetch_latest_release", lambda *a, **k: {
            "tag_name": "v9.9.9", "name": None, "body": None, "html_url": None, "published_at": None,
        })
        login(app_client, "admin", "adminpass123")
        app_client.get("/api/release/status")
        r = app_client.get("/api/tickets")
        assert r.status_code == 200
        subjects = [t["subject"] for t in r.json()["tickets"]]
        assert any("v9.9.9" in s for s in subjects)

    def test_viewer_without_settings_view_cannot_check_status(self, app_client):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/release/status")
        assert r.status_code == 403
