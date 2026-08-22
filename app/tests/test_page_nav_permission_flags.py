"""Regression tests for a real RBAC coverage gap: routes/pages.py's _ctx()
used to expose Teams/Settings/Users-Activity nav visibility (and,
downstream, templates/teams.html's own write-control visibility) entirely
via "is_admin" (has_permission(db, user, "users", "manage")) -- even though
each of those pages/actions is actually gated on its OWN object
(teams:manage, settings:manage, audit_log:manage respectively; see
routes/pages.py's teams_page/settings_page/users_activity_page and
routes/teams.py's require_admin).

That meant a custom role granted exactly "Teams: Manage" (say) via Roles
Management -- without also granting "Users: Manage" -- could already reach
/teams and successfully call every /api/teams write endpoint directly, but
had no sidebar link to find the page, and once there, teams.html hid every
create/edit/delete/add-member control (all gated on the wrong flag). The
very permission an admin had just granted through the Roles & Permissions
page was effectively unreachable through the UI. Fixed by adding
can_manage_teams/can_manage_settings/can_view_users_activity to _ctx(),
each mirroring the real gate, and wiring base.html/teams.html to them
instead of is_admin.

These tests build a custom role with ONLY the object permission under
test (no "users" permission at all), confirming the page is both reachable
and its write UI renders -- the two symptoms of the bug -- without needing
full user-management access.
"""
from vpnadmin.auth import hash_password
from vpnadmin.models import ObjectPermission, RoleDef, RoleKind, User

from .conftest import login


def _make_role(db_session, slug: str, *, object_key: str, action: str = "manage") -> RoleDef:
    role = RoleDef(slug=slug, name=slug, kind=RoleKind.custom, is_system=False)
    db_session.add(role)
    db_session.flush()
    db_session.add(ObjectPermission(role_id=role.id, object_key=object_key, **{f"can_{action}": True}))
    db_session.commit()
    return role


def _make_user(db_session, username: str, role: RoleDef) -> None:
    db_session.add(User(username=username, password_hash=hash_password("testpass123"), role_id=role.id))
    db_session.commit()


class TestTeamsManageWithoutUsersManage:
    def test_teams_page_reachable_and_shows_write_controls(self, app_client, db_session):
        role = _make_role(db_session, "teams_only", object_key="teams")
        _make_user(db_session, "teamsonly", role)
        login(app_client, "teamsonly", "testpass123")

        r = app_client.get("/teams")
        assert r.status_code == 200
        # can_manage_teams (not is_admin) now drives these -- would be
        # absent before the fix, since this role has no "users" permission.
        assert 'id="create-team-form"' in r.text
        assert 'id="team-edit-toggle-btn"' in r.text

    def test_sidebar_shows_teams_link_without_users_manage(self, app_client, db_session):
        role = _make_role(db_session, "teams_only2", object_key="teams")
        _make_user(db_session, "teamsonly2", role)
        login(app_client, "teamsonly2", "testpass123")

        r = app_client.get("/teams")
        assert 'href="/teams"' in r.text

    def test_users_link_still_hidden_without_users_manage(self, app_client, db_session):
        """Confirms the fix is scoped correctly -- Users itself (genuinely
        gated on users:manage) must stay hidden for a teams-only role."""
        role = _make_role(db_session, "teams_only3", object_key="teams")
        _make_user(db_session, "teamsonly3", role)
        login(app_client, "teamsonly3", "testpass123")

        r = app_client.get("/teams")
        assert 'href="/users"' not in r.text


class TestSettingsManageWithoutUsersManage:
    def test_settings_page_reachable_and_nav_link_shown(self, app_client, db_session):
        role = _make_role(db_session, "settings_only", object_key="settings")
        _make_user(db_session, "settingsonly", role)
        login(app_client, "settingsonly", "testpass123")

        r = app_client.get("/settings")
        assert r.status_code == 200
        assert 'href="/settings"' in r.text


class TestAuditLogManageWithoutUsersManage:
    def test_users_activity_page_reachable_and_nav_link_shown(self, app_client, db_session):
        role = _make_role(db_session, "audit_only", object_key="audit_log")
        _make_user(db_session, "audityonly", role)
        login(app_client, "audityonly", "testpass123")

        r = app_client.get("/users/activity")
        assert r.status_code == 200
        assert 'href="/users/activity"' in r.text


class TestNoRegressionForPlainViewer:
    def test_viewer_sees_none_of_the_three_links(self, app_client):
        """Viewer has no teams/settings/audit_log permission at all (see
        permissions.py's _SYSTEM_ROLES) -- must still see none of these,
        confirming the fix didn't accidentally widen access."""
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/dashboard")
        assert r.status_code == 200
        assert 'href="/teams"' not in r.text
        assert 'href="/settings"' not in r.text
        assert 'href="/users/activity"' not in r.text

    def test_admin_still_sees_all_three(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.get("/dashboard")
        assert r.status_code == 200
        assert 'href="/teams"' in r.text
        assert 'href="/settings"' in r.text
        assert 'href="/users/activity"' in r.text
