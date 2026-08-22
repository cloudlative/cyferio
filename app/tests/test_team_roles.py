"""Team-Based Permissions, Roles & Policy Inheritance -- Phase 1: teams as
role containers. Covers permissions.py's effective_role_ids (the union of a
user's own direct role_id plus every role granted to a team they belong to
via team_role_defs) and routes/teams.py's role-assignment endpoints.

The core claim under test throughout this file is backward compatibility:
before this feature, a user's effective permissions were derived from
exactly one role (User.role_id). Every test in TestEffectiveRoleIds's first
two cases confirms that a user with no team-granted roles -- whether
because they're in no team at all, or because their team(s) have zero
roles assigned -- gets back EXACTLY that same single-role set, byte for
byte, with this feature installed. See models.py's team_role_defs and
permissions.py's effective_role_ids docstrings for the design."""
from vpnadmin.auth import hash_password
from vpnadmin.models import AuditLog, ObjectPermission, RoleDef, RoleKind, Team, User
from vpnadmin.permissions import effective_role_ids, has_permission

from .conftest import login


def _make_role(db_session, slug: str, *, object_key: str, action: str = "manage") -> RoleDef:
    role = RoleDef(slug=slug, name=slug, kind=RoleKind.custom, is_system=False)
    db_session.add(role)
    db_session.flush()
    db_session.add(ObjectPermission(role_id=role.id, object_key=object_key, **{f"can_{action}": True}))
    db_session.commit()
    return role


class TestEffectiveRoleIds:
    def test_user_with_no_team_memberships_gets_only_own_role_id(self, db_session):
        """Regression guard: a user in zero teams must resolve to exactly
        {user.role_id} -- identical to today's single-role behavior."""
        role = _make_role(db_session, "solo-role", object_key="vpn_profiles", action="view")
        user = User(username="solo", password_hash=hash_password("pw"), role_id=role.id)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {role.id}

    def test_user_with_no_role_id_and_no_teams_gets_empty_set(self, db_session):
        user = User(username="norole", password_hash=hash_password("pw"), role_id=None)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == set()

    def test_user_in_team_with_zero_assigned_roles_gets_identical_effective_permissions(self, db_session):
        """CORE BACKWARD-COMPATIBILITY GUARANTEE: a user who belongs to a
        team, but whose team has no roles assigned to it (today's reality
        for every existing team, since this feature didn't exist before),
        must get EXACTLY the same effective role set as if they belonged to
        no team at all -- i.e. just their own direct role_id."""
        role = _make_role(db_session, "own-role", object_key="vpn_profiles", action="view")
        team = Team(name="Empty-Role Team")
        db_session.add(team)
        db_session.flush()
        user = User(username="teamed", password_hash=hash_password("pw"), role_id=role.id)
        user.teams.append(team)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {role.id}

    def test_user_in_team_with_assigned_role_gains_it_with_no_direct_role_of_their_own(self, db_session):
        """The union actually works: a user with role_id=None, but who
        belongs to a team that has a role assigned, inherits that role's
        permissions purely through team membership."""
        team_role = _make_role(db_session, "team-role", object_key="vpn_profiles", action="view")
        team = Team(name="Granting Team")
        team.role_defs.append(team_role)
        db_session.add(team)
        db_session.flush()
        user = User(username="teamonly", password_hash=hash_password("pw"), role_id=None)
        user.teams.append(team)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {team_role.id}
        assert has_permission(db_session, user, "vpn_profiles", "view") is True

    def test_own_direct_role_combined_not_replaced_by_a_different_team_role(self, db_session):
        """A user's own direct role permissions are preserved AND combined
        (union, not replacement) when they're also in a team granting a
        different role with different permissions."""
        own_role = _make_role(db_session, "own-only", object_key="vpn_profiles", action="view")
        team_role = _make_role(db_session, "team-only", object_key="settings", action="manage")
        team = Team(name="Combining Team")
        team.role_defs.append(team_role)
        db_session.add(team)
        db_session.flush()
        user = User(username="combined", password_hash=hash_password("pw"), role_id=own_role.id)
        user.teams.append(team)
        db_session.add(user)
        db_session.commit()

        assert effective_role_ids(db_session, user) == {own_role.id, team_role.id}
        # Own role's grant still works...
        assert has_permission(db_session, user, "vpn_profiles", "view") is True
        # ...and the team-granted role's permission is ALSO available, not
        # replacing the direct one.
        assert has_permission(db_session, user, "settings", "manage") is True
        # Something neither role grants is still correctly denied.
        assert has_permission(db_session, user, "users", "manage") is False


class TestTeamRoleAssignmentApi:
    def test_denied_without_teams_manage(self, app_client, db_session):
        team = Team(name="API Team")
        db_session.add(team)
        db_session.commit()
        login(app_client, "viewer", "viewerpass123")
        r = app_client.post(f"/api/teams/{team.id}/roles", json={"role_id": 1})
        assert r.status_code == 403

    def test_assign_and_remove_round_trip(self, app_client, db_session):
        role = db_session.query(RoleDef).filter_by(slug="editor").first()
        team = Team(name="Assignable Team")
        db_session.add(team)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/teams/{team.id}/roles", json={"role_id": role.id})
        assert r.status_code == 201
        assert {rl["id"] for rl in r.json()["roles"]} == {role.id}

        # Reflected back on the list endpoint too.
        listed = app_client.get("/api/teams").json()
        api_team = next(t for t in listed if t["id"] == team.id)
        assert {rl["id"] for rl in api_team["roles"]} == {role.id}

        r2 = app_client.delete(f"/api/teams/{team.id}/roles/{role.id}")
        assert r2.status_code == 200
        listed2 = app_client.get("/api/teams").json()
        api_team2 = next(t for t in listed2 if t["id"] == team.id)
        assert api_team2["roles"] == []

    def test_assign_and_remove_are_audit_logged(self, app_client, db_session):
        role = db_session.query(RoleDef).filter_by(slug="viewer").first()
        team = Team(name="Audited Team")
        db_session.add(team)
        db_session.commit()

        login(app_client, "admin", "adminpass123")
        app_client.post(f"/api/teams/{team.id}/roles", json={"role_id": role.id})
        app_client.delete(f"/api/teams/{team.id}/roles/{role.id}")

        actions = [a.action for a in db_session.query(AuditLog).order_by(AuditLog.id).all()]
        assert "team_role_assigned" in actions
        assert "team_role_removed" in actions
        assigned = db_session.query(AuditLog).filter_by(action="team_role_assigned").one()
        assert assigned.target == "Audited Team"
        assert assigned.detail == "viewer"
        assert assigned.username == "admin"

    def test_available_roles_endpoint_gated_and_lists_roles(self, app_client, db_session):
        login(app_client, "viewer", "viewerpass123")
        r = app_client.get("/api/teams/available-roles")
        assert r.status_code == 403

        login(app_client, "admin", "adminpass123")
        r2 = app_client.get("/api/teams/available-roles")
        assert r2.status_code == 200
        slugs = {r["slug"] for r in r2.json()}
        assert "admin" in slugs and "viewer" in slugs
