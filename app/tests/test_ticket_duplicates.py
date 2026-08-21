"""Duplicate Ticket Management (spec sections 4/5) -- marking a ticket as a
duplicate, parent linkage, Option A enforcement (replies/status changes
blocked on a duplicate), and the duplicate-cluster detection heuristics."""
from vpnadmin.auth import hash_password
from vpnadmin.models import RoleDef, User

from .conftest import login


def _make_self_service_user(db_session, username, password="somepass123"):
    role = db_session.query(RoleDef).filter_by(slug="user").first()
    user = User(username=username, password_hash=hash_password(password), role_id=role.id)
    db_session.add(user)
    db_session.commit()
    return user


def _create_ticket(client, *, subject="Cannot connect", category="vpn_cannot_connect"):
    r = client.post("/api/me/tickets", data={
        "subject": subject, "category": category, "priority": "high",
        "description": "It just won't connect.", "attach_context": "false",
    })
    assert r.status_code == 201
    return r.json()["id"]


class TestMarkAsDuplicate:
    def test_mark_and_parent_linkage(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        parent_id = _create_ticket(app_client, subject="VPN broken")
        dup_id = _create_ticket(app_client, subject="VPN broken again")

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/tickets/{dup_id}/mark-duplicate", json={"parent_ticket_id": parent_id})
        assert r.status_code == 200
        body = r.json()
        assert body["duplicate_of_ticket_id"] == parent_id
        assert body["duplicate_of_subject"] == "VPN broken"

        r = app_client.get(f"/api/tickets/{parent_id}")
        parent = r.json()
        assert parent["duplicate_count"] == 1
        assert parent["duplicates"][0]["id"] == dup_id

    def test_cannot_mark_self_as_duplicate(self, app_client, db_session):
        _make_self_service_user(db_session, "bob")
        login(app_client, "bob", "somepass123")
        tid = _create_ticket(app_client)

        login(app_client, "admin", "adminpass123")
        r = app_client.post(f"/api/tickets/{tid}/mark-duplicate", json={"parent_ticket_id": tid})
        assert r.status_code == 400

    def test_cannot_chain_duplicates(self, app_client, db_session):
        _make_self_service_user(db_session, "carol")
        login(app_client, "carol", "somepass123")
        a = _create_ticket(app_client, subject="A")
        b = _create_ticket(app_client, subject="B")
        c = _create_ticket(app_client, subject="C")

        login(app_client, "admin", "adminpass123")
        assert app_client.post(f"/api/tickets/{b}/mark-duplicate", json={"parent_ticket_id": a}).status_code == 200
        r = app_client.post(f"/api/tickets/{c}/mark-duplicate", json={"parent_ticket_id": b})
        assert r.status_code == 400

    def test_option_a_blocks_self_service_reply_and_admin_reply(self, app_client, db_session):
        _make_self_service_user(db_session, "dana")
        login(app_client, "dana", "somepass123")
        parent_id = _create_ticket(app_client, subject="Parent issue")
        dup_id = _create_ticket(app_client, subject="Dup issue")

        login(app_client, "admin", "adminpass123")
        app_client.post(f"/api/tickets/{dup_id}/mark-duplicate", json={"parent_ticket_id": parent_id})

        # Admin reply blocked (non-internal).
        r = app_client.post(f"/api/tickets/{dup_id}/replies", data={"body": "hi", "is_internal_note": "false"})
        assert r.status_code == 409
        # Internal note still allowed.
        r = app_client.post(f"/api/tickets/{dup_id}/replies", data={"body": "internal fyi", "is_internal_note": "true"})
        assert r.status_code == 201
        # Status/priority change blocked.
        r = app_client.patch(f"/api/tickets/{dup_id}", json={"status": "resolved"})
        assert r.status_code == 409

        # Self-service reply blocked.
        login(app_client, "dana", "somepass123")
        r = app_client.post(f"/api/me/tickets/{dup_id}/replies", data={"body": "still broken"})
        assert r.status_code == 409

    def test_unmark_duplicate_restores_normal_processing(self, app_client, db_session):
        _make_self_service_user(db_session, "erin")
        login(app_client, "erin", "somepass123")
        parent_id = _create_ticket(app_client, subject="Parent")
        dup_id = _create_ticket(app_client, subject="Dup")

        login(app_client, "admin", "adminpass123")
        app_client.post(f"/api/tickets/{dup_id}/mark-duplicate", json={"parent_ticket_id": parent_id})
        r = app_client.post(f"/api/tickets/{dup_id}/unmark-duplicate")
        assert r.status_code == 200
        assert r.json()["duplicate_of_ticket_id"] is None
        r = app_client.patch(f"/api/tickets/{dup_id}", json={"status": "in_progress"})
        assert r.status_code == 200


class TestBulkMarkDuplicate:
    def test_bulk_mark_duplicate(self, app_client, db_session):
        _make_self_service_user(db_session, "frank")
        login(app_client, "frank", "somepass123")
        parent_id = _create_ticket(app_client, subject="Parent")
        dup1 = _create_ticket(app_client, subject="Dup1")
        dup2 = _create_ticket(app_client, subject="Dup2")

        login(app_client, "admin", "adminpass123")
        r = app_client.post("/api/tickets/bulk/mark-duplicate", json={
            "ticket_ids": [parent_id, dup1, dup2], "parent_ticket_id": parent_id,
        })
        assert r.status_code == 200
        assert set(r.json()["marked_duplicate"]) == {dup1, dup2}  # parent itself skipped

        r = app_client.get(f"/api/tickets/{parent_id}")
        assert r.json()["duplicate_count"] == 2


class TestDuplicateClusters:
    def test_same_subject_detected_as_cluster(self, app_client, db_session):
        _make_self_service_user(db_session, "gail")
        login(app_client, "gail", "somepass123")
        _create_ticket(app_client, subject="Cannot connect at all")
        _create_ticket(app_client, subject="Cannot connect at all")

        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/tickets/duplicate-clusters")
        assert r.status_code == 200
        data = r.json()
        assert data["clusters"], "expected at least one candidate cluster"
        cluster = data["clusters"][0]
        assert len(cluster["tickets"]) >= 2
        assert cluster["suggested_parent_id"] in [t["id"] for t in cluster["tickets"]]

    def test_same_user_and_category_detected(self, app_client, db_session):
        _make_self_service_user(db_session, "hank")
        login(app_client, "hank", "somepass123")
        _create_ticket(app_client, subject="Speed is slow", category="quota_speed_concern")
        _create_ticket(app_client, subject="Connection is slow today", category="quota_speed_concern")

        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/tickets/duplicate-clusters")
        data = r.json()
        assert any(len(c["tickets"]) >= 2 for c in data["clusters"])

    def test_different_subjects_and_categories_not_clustered(self, app_client, db_session):
        _make_self_service_user(db_session, "iris")
        login(app_client, "iris", "somepass123")
        id1 = _create_ticket(app_client, subject="Totally unique subject one", category="vpn_cannot_connect")

        _make_self_service_user(db_session, "jack")
        login(app_client, "jack", "somepass123")
        id2 = _create_ticket(app_client, subject="A different unrelated subject", category="account_profile_issue")

        login(app_client, "admin", "adminpass123")
        r = app_client.get("/api/tickets/duplicate-clusters")
        for cluster in r.json()["clusters"]:
            cluster_ids = {t["id"] for t in cluster["tickets"]}
            assert not ({id1, id2} <= cluster_ids), "unrelated tickets should not share a cluster"
