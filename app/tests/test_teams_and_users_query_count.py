"""Regression tests for the N+1 query fix in routes/teams.py::list_teams()
and routes/users.py::list_users() (selectinload(User.teams)/(User.role_def)
-- see their own comments). Asserts the actual SQL query count doesn't grow
with the number of users, not just that the diff "looks" eager-loaded."""

from sqlalchemy import event

from vpnadmin.auth import hash_password
from vpnadmin.models import Role, Team, User

from .conftest import login


def _query_count_during(engine, fn):
    count = {"n": 0}

    def _cb(conn, cursor, statement, parameters, context, executemany):
        count["n"] += 1

    event.listen(engine, "before_cursor_execute", _cb)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", _cb)
    return count["n"]


def _add_users_across_teams(db_session, n_users, teams, prefix):
    for i in range(n_users):
        u = User(
            username=f"{prefix}{i}",
            password_hash=hash_password("memberpass123"),
            role=Role.viewer,
        )
        u.teams.append(teams[i % len(teams)])
        db_session.add(u)
    db_session.commit()


class TestTeamsQueryCountDoesNotScaleWithUsers:
    def test_list_teams_query_count_independent_of_user_count(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        engine = db_session.get_bind()
        teams = [Team(name=f"Team {i}") for i in range(3)]
        db_session.add_all(teams)
        db_session.commit()

        _add_users_across_teams(db_session, 5, teams, "membera")
        small_count = _query_count_during(engine, lambda: app_client.get("/api/teams"))

        _add_users_across_teams(db_session, 25, teams, "memberb")  # +25 more users
        large_count = _query_count_during(engine, lambda: app_client.get("/api/teams"))

        # Pre-fix (no selectinload), this scaled by roughly +1 query per
        # extra user (N+1) -- 25 more users would have meant ~25 more
        # queries. Fixed, it's the same handful of queries regardless of
        # row count (a small allowance for session/permission-check
        # overhead that isn't itself user-count-dependent).
        assert large_count - small_count <= 3, f"query count grew with user count ({small_count} -> {large_count}) -- N+1 regression"


class TestUsersQueryCountDoesNotScaleWithUsers:
    def test_list_users_query_count_independent_of_user_count(self, app_client, db_session):
        login(app_client, "admin", "adminpass123")
        engine = db_session.get_bind()
        teams = [Team(name=f"Team {i}") for i in range(3)]
        db_session.add_all(teams)
        db_session.commit()

        _add_users_across_teams(db_session, 5, teams, "membera")
        small_count = _query_count_during(engine, lambda: app_client.get("/api/users"))

        _add_users_across_teams(db_session, 25, teams, "memberb")
        large_count = _query_count_during(engine, lambda: app_client.get("/api/users"))

        assert large_count - small_count <= 3, f"query count grew with user count ({small_count} -> {large_count}) -- N+1 regression"
