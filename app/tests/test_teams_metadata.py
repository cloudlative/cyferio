"""Team metadata (slug/description/tags), added for future reporting by
team -- schema + basic CRUD only, see models.py's Team docstring."""

from vpnadmin.db import _backfill_team_slugs
from vpnadmin.models import Team

from .conftest import login


class TestCreateTeamWithMetadata:
    def test_explicit_slug_description_tags_round_trip(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            "/api/teams",
            json={
                "name": "DevOps Team",
                "slug": "devops-team",
                "description": "Infra and platform engineering.",
                "tags": ["infra", "on-call"],
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["slug"] == "devops-team"
        assert body["description"] == "Infra and platform engineering."
        assert body["tags"] == ["infra", "on-call"]

    def test_slug_auto_derived_when_omitted(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/teams", json={"name": "Finance Team"})
        assert r.status_code == 201
        assert r.json()["slug"] == "finance-team"

    def test_duplicate_slug_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r1 = app_client.post("/api/teams", json={"name": "Support A", "slug": "support"})
        assert r1.status_code == 201
        r2 = app_client.post("/api/teams", json={"name": "Support B", "slug": "support"})
        assert r2.status_code == 409

    def test_invalid_slug_shape_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/teams", json={"name": "Bad Slug Team", "slug": "Not A Slug!"})
        assert r.status_code == 422


class TestUpdateTeam:
    def test_patch_updates_fields(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/teams", json={"name": "Security Team"})
        team_id = r.json()["id"]
        r2 = app_client.patch(
            f"/api/teams/{team_id}",
            json={
                "description": "AppSec + infra security.",
                "tags": ["security"],
            },
        )
        assert r2.status_code == 200
        assert r2.json()["description"] == "AppSec + infra security."
        assert r2.json()["tags"] == ["security"]
        # Name/slug untouched by a partial update that doesn't mention them.
        assert r2.json()["team"] == "Security Team"

    def test_patch_rejects_duplicate_slug(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/teams", json={"name": "Team A", "slug": "team-a"})
        r2 = app_client.post("/api/teams", json={"name": "Team B", "slug": "team-b"})
        team_b_id = r2.json()["id"]
        r3 = app_client.patch(f"/api/teams/{team_b_id}", json={"slug": "team-a"})
        assert r3.status_code == 409

    def test_viewer_cannot_patch(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/teams", json={"name": "Viewer Blocked Team"})
        team_id = r.json()["id"]
        login(app_client, "viewer", "viewerpass123")
        r2 = app_client.patch(f"/api/teams/{team_id}", json={"description": "nope"})
        assert r2.status_code == 403


class TestSlugBackfill:
    def test_backfills_slug_for_pre_existing_rows(self, db_session):
        # Simulates a team row that predates the slug column (nullable at
        # the DB level for exactly this reason -- see models.py).
        team = Team(name="Legacy Ops Team")
        db_session.add(team)
        db_session.commit()
        assert team.slug is None

        # _backfill_team_slugs() opens its own SessionLocal() (and closes
        # it when done) -- point that factory at db_session's own engine
        # (the fixture's StaticPool-pinned in-memory connection) rather
        # than db_session itself, so the backfill's session.close() doesn't
        # tear down the fixture's still-in-use session.
        from sqlalchemy.orm import sessionmaker

        from vpnadmin import db as db_mod

        original_session_local = db_mod.SessionLocal
        db_mod.SessionLocal = sessionmaker(bind=db_session.get_bind())
        try:
            _backfill_team_slugs()
        finally:
            db_mod.SessionLocal = original_session_local

        db_session.refresh(team)
        assert team.slug == "legacy-ops-team"

    def test_backfill_dedupes_colliding_slugs(self, db_session):
        t1 = Team(name="Ops!")
        t2 = Team(name="Ops?")  # slugifies to the same base as t1
        db_session.add_all([t1, t2])
        db_session.commit()

        from sqlalchemy.orm import sessionmaker

        from vpnadmin import db as db_mod

        original_session_local = db_mod.SessionLocal
        db_mod.SessionLocal = sessionmaker(bind=db_session.get_bind())
        try:
            _backfill_team_slugs()
        finally:
            db_mod.SessionLocal = original_session_local

        db_session.refresh(t1)
        db_session.refresh(t2)
        slugs = {t1.slug, t2.slug}
        assert slugs == {"ops", "ops-2"}
