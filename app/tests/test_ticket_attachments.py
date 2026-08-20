"""Support Ticketing System, phase 2 -- attachment upload validation
(app/vpnadmin/ticket_attachments.py) and download access control."""
from vpnadmin.app_settings import runtime as runtime_settings

from .test_support_tickets import _make_self_service_user

from .conftest import login

_PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _create_ticket_with_files(client, files, *, subject="Attachment test"):
    return client.post("/api/me/tickets", data={
        "subject": subject, "category": "vpn_cannot_connect", "priority": "high",
        "description": "See attached.", "attach_context": "false",
    }, files=files)


class TestAttachmentValidation:
    def test_valid_attachment_accepted(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket_with_files(app_client, [("attachments", ("screenshot.png", _PNG_BYTES, "image/png"))])
        assert r.status_code == 201
        attachments = r.json()["messages"][0]["attachments"]
        assert len(attachments) == 1
        assert attachments[0]["filename"] == "screenshot.png"

    def test_disallowed_extension_rejected(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket_with_files(app_client, [("attachments", ("malware.exe", b"MZ\x90\x00", "application/octet-stream"))])
        assert r.status_code == 422
        assert "not allowed" in r.json()["detail"]

    def test_magic_bytes_mismatch_rejected(self, app_client, db_session):
        # A .png extension whose content is plainly NOT a PNG (no magic
        # bytes) -- the extension-only check would pass this, the magic-
        # byte check must not.
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket_with_files(app_client, [("attachments", ("fake.png", b"not really a png", "image/png"))])
        assert r.status_code == 422
        assert "doesn't look like" in r.json()["detail"]

    def test_oversized_attachment_rejected(self, app_client, db_session):
        runtime_settings.support_max_attachment_size_mb = 0  # 0 MB ceiling -- any non-empty file exceeds it
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket_with_files(app_client, [("attachments", ("screenshot.png", _PNG_BYTES, "image/png"))])
        assert r.status_code == 422
        assert "exceeds" in r.json()["detail"]

    def test_too_many_attachments_rejected(self, app_client, db_session):
        runtime_settings.support_max_attachments_per_message = 1
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket_with_files(app_client, [
            ("attachments", ("one.png", _PNG_BYTES, "image/png")),
            ("attachments", ("two.png", _PNG_BYTES, "image/png")),
        ])
        assert r.status_code == 422
        assert "No more than" in r.json()["detail"]

    def test_invalid_attachment_leaves_nothing_stored(self, app_client, db_session):
        """No partial-save: a request with one valid and one invalid file
        must store NEITHER, not just reject the bad one."""
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        r = _create_ticket_with_files(app_client, [
            ("attachments", ("good.png", _PNG_BYTES, "image/png")),
            ("attachments", ("bad.exe", b"MZ", "application/octet-stream")),
        ])
        assert r.status_code == 422
        r = app_client.get("/api/me/tickets")
        assert r.json()["tickets"] == []  # the ticket itself was never committed either


class TestAttachmentDownloadAccessControl:
    def _create_ticket_with_attachment(self, app_client):
        r = _create_ticket_with_files(app_client, [("attachments", ("screenshot.png", _PNG_BYTES, "image/png"))])
        ticket = r.json()
        return ticket["id"], ticket["messages"][0]["attachments"][0]["id"]

    def test_owner_can_download_their_own_attachment(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id, attachment_id = self._create_ticket_with_attachment(app_client)
        r = app_client.get(f"/api/me/tickets/{ticket_id}/attachments/{attachment_id}")
        assert r.status_code == 200
        assert r.content == _PNG_BYTES

    def test_another_user_cannot_download_it(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        _make_self_service_user(db_session, "bob")
        login(app_client, "alice", "somepass123")
        ticket_id, attachment_id = self._create_ticket_with_attachment(app_client)

        login(app_client, "bob", "somepass123")
        r = app_client.get(f"/api/me/tickets/{ticket_id}/attachments/{attachment_id}")
        assert r.status_code == 404

    def test_admin_can_download_any_attachment(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id, attachment_id = self._create_ticket_with_attachment(app_client)

        login(app_client, "admin", "adminpass123")
        r = app_client.get(f"/api/tickets/{ticket_id}/attachments/{attachment_id}")
        assert r.status_code == 200
        assert r.content == _PNG_BYTES

    def test_internal_note_attachment_hidden_from_self_service_download(self, app_client, db_session):
        _make_self_service_user(db_session, "alice")
        login(app_client, "alice", "somepass123")
        ticket_id = app_client.post("/api/me/tickets", data={
            "subject": "x", "category": "vpn_cannot_connect", "priority": "high",
            "description": "x", "attach_context": "false",
        }).json()["id"]

        login(app_client, "admin", "adminpass123")
        r = app_client.post(
            f"/api/tickets/{ticket_id}/replies",
            data={"body": "internal note", "is_internal_note": "true"},
            files=[("attachments", ("internal.png", _PNG_BYTES, "image/png"))],
        )
        assert r.status_code == 201
        attachment_id = r.json()["messages"][-1]["attachments"][0]["id"]

        # Admin can still fetch it.
        r = app_client.get(f"/api/tickets/{ticket_id}/attachments/{attachment_id}")
        assert r.status_code == 200

        login(app_client, "alice", "somepass123")
        r = app_client.get(f"/api/me/tickets/{ticket_id}/attachments/{attachment_id}")
        assert r.status_code == 404
