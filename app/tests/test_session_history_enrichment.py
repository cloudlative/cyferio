"""GET /api/status/session-history enriches each row with the linked portal
user's identity (portal_username/portal_display_name), so Connection
History's search box can match a portal user, not just the raw VPN profile
name -- see routes/status.py's get_session_history and models.py's
VpnProfileLink."""

from vpnadmin.models import Role, User, VpnProfileLink

from .conftest import login


def test_session_history_rows_carry_linked_portal_user(app_client, db_session, monkeypatch):
    from vpnadmin.routes import status as status_routes

    waleed = User(
        username="waleed",
        password_hash="x",
        role=Role.viewer,
        first_name="Waleed",
        last_name="Khan",
    )
    db_session.add(waleed)
    db_session.commit()
    db_session.add(VpnProfileLink(user_id=waleed.id, vpn_client_name="waleed-laptop", link_source="manual_admin_link"))
    db_session.commit()

    fake_rows = [
        {"client": "waleed-laptop", "connected_at": "2026-08-10T00:00:00Z"},
        {"client": "unlinked-client", "connected_at": "2026-08-10T00:00:00Z"},
    ]
    monkeypatch.setattr(status_routes.cli, "status_session_history", lambda limit, client=None: fake_rows)

    login(app_client, "admin", "adminpass123")
    r = app_client.get("/api/status/session-history")
    assert r.status_code == 200
    rows = {row["client"]: row for row in r.json()}

    assert rows["waleed-laptop"]["portal_username"] == "waleed"
    assert rows["waleed-laptop"]["portal_display_name"] == "Waleed Khan"
    assert rows["unlinked-client"]["portal_username"] is None
    assert rows["unlinked-client"]["portal_display_name"] is None
