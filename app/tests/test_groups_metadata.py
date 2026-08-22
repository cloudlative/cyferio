"""Group metadata (slug/description/tags), added for future reporting by
group -- schema + basic CRUD only, see models.py's Group docstring."""
from vpnadmin.db import _backfill_group_slugs
from vpnadmin.models import Group

from .conftest import login


class TestCreateGroupWithMetadata:
    def test_explicit_slug_description_tags_round_trip(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/groups", json={
            "name": "DevOps Group", "slug": "devops-group",
            "description": "Infra and platform engineering.", "tags": ["infra", "on-call"],
        })
        assert r.status_code == 201
        body = r.json()
        assert body["slug"] == "devops-group"
        assert body["description"] == "Infra and platform engineering."
        assert body["tags"] == ["infra", "on-call"]

    def test_slug_auto_derived_when_omitted(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/groups", json={"name": "Finance Group"})
        assert r.status_code == 201
        assert r.json()["slug"] == "finance-group"

    def test_duplicate_slug_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r1 = app_client.post("/api/groups", json={"name": "Support A", "slug": "support"})
        assert r1.status_code == 201
        r2 = app_client.post("/api/groups", json={"name": "Support B", "slug": "support"})
        assert r2.status_code == 409

    def test_invalid_slug_shape_rejected(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/groups", json={"name": "Bad Slug Group", "slug": "Not A Slug!"})
        assert r.status_code == 422


class TestUpdateGroup:
    def test_patch_updates_fields(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/groups", json={"name": "Security Group"})
        group_id = r.json()["id"]
        r2 = app_client.patch(f"/api/groups/{group_id}", json={
            "description": "AppSec + infra security.", "tags": ["security"],
        })
        assert r2.status_code == 200
        assert r2.json()["description"] == "AppSec + infra security."
        assert r2.json()["tags"] == ["security"]
        # Name/slug untouched by a partial update that doesn't mention them.
        assert r2.json()["group"] == "Security Group"

    def test_patch_rejects_duplicate_slug(self, app_client):
        login(app_client, "admin", "adminpass123")
        app_client.post("/api/groups", json={"name": "Group A", "slug": "group-a"})
        r2 = app_client.post("/api/groups", json={"name": "Group B", "slug": "group-b"})
        group_b_id = r2.json()["id"]
        r3 = app_client.patch(f"/api/groups/{group_b_id}", json={"slug": "group-a"})
        assert r3.status_code == 409

    def test_viewer_cannot_patch(self, app_client):
        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/groups", json={"name": "Viewer Blocked Group"})
        group_id = r.json()["id"]
        login(app_client, "viewer", "viewerpass123")
        r2 = app_client.patch(f"/api/groups/{group_id}", json={"description": "nope"})
        assert r2.status_code == 403


class TestSlugBackfill:
    def test_backfills_slug_for_pre_existing_rows(self, db_session):
        # Simulates a group row that predates the slug column (nullable at
        # the DB level for exactly this reason -- see models.py).
        group = Group(name="Legacy Ops Group")
        db_session.add(group)
        db_session.commit()
        assert group.slug is None

        # _backfill_group_slugs() opens its own SessionLocal() (and closes
        # it when done) -- point that factory at db_session's own engine
        # (the fixture's StaticPool-pinned in-memory connection) rather
        # than db_session itself, so the backfill's session.close() doesn't
        # tear down the fixture's still-in-use session.
        from sqlalchemy.orm import sessionmaker

        from vpnadmin import db as db_mod
        original_session_local = db_mod.SessionLocal
        db_mod.SessionLocal = sessionmaker(bind=db_session.get_bind())
        try:
            _backfill_group_slugs()
        finally:
            db_mod.SessionLocal = original_session_local

        db_session.refresh(group)
        assert group.slug == "legacy-ops-group"

    def test_backfill_dedupes_colliding_slugs(self, db_session):
        t1 = Group(name="Ops!")
        t2 = Group(name="Ops?")  # slugifies to the same base as t1
        db_session.add_all([t1, t2])
        db_session.commit()

        from sqlalchemy.orm import sessionmaker

        from vpnadmin import db as db_mod
        original_session_local = db_mod.SessionLocal
        db_mod.SessionLocal = sessionmaker(bind=db_session.get_bind())
        try:
            _backfill_group_slugs()
        finally:
            db_mod.SessionLocal = original_session_local

        db_session.refresh(t1)
        db_session.refresh(t2)
        slugs = {t1.slug, t2.slug}
        assert slugs == {"ops", "ops-2"}
