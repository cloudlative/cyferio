import os

import pytest

from services.openvpn import client_manager
from services.openvpn.exceptions import (
    ClientAlreadyExistsError, ClientNotFoundError, ClientNotRevokedError,
    MacAlreadyRegisteredError, MacNotFoundError,
)


# --- add_client ---------------------------------------------------------

def test_add_client_success(paths):
    result = client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    assert result.client == "alice"
    assert result.mac == "aa:bb:cc:dd:ee:ff"
    assert os.path.exists(result.ovpn_path)
    assert os.path.exists(paths.issued_crt("alice"))

    lines = open(paths.db_file, encoding="utf-8").read().splitlines()
    assert lines == ["alice=aa:bb:cc:dd:ee:ff"]


def test_add_client_duplicate_name_rejected(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ClientAlreadyExistsError):
        client_manager.add_client(paths, "alice", "11:22:33:44:55:66")


def test_add_client_duplicate_mac_rejected_cross_client(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(MacAlreadyRegisteredError):
        client_manager.add_client(paths, "bob", "aa:bb:cc:dd:ee:ff")


def test_add_client_sanitizes_name(paths):
    result = client_manager.add_client(paths, "Bad Name!!", "aa:bb:cc:dd:ee:ff")
    assert result.client == "Bad_Name__"


def test_add_client_rollback_leaves_no_partial_state(paths, monkeypatch):
    """If the .ovpn write fails after the cert is issued, neither the cert
    files nor a DB_FILE entry should remain -- see client_manager.py's
    add_client() rollback contract."""
    import services.openvpn.config_manager as config_manager

    def _boom(*a, **kw):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(config_manager, "generate_ovpn", _boom)
    with pytest.raises(OSError):
        client_manager.add_client(paths, "carol", "aa:bb:cc:dd:ee:ff")

    assert not os.path.exists(paths.issued_crt("carol"))
    assert not os.path.exists(paths.private_key("carol"))
    assert not os.path.exists(paths.db_file) or "carol" not in open(paths.db_file).read()


# --- revoke_client / show_ovpn ------------------------------------------

def test_revoke_client_removes_db_entry_and_installs_crl(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.revoke_client(paths, "alice")

    assert open(paths.db_file, encoding="utf-8").read().strip() == ""
    revoked = client_manager.list_revoked(paths)
    assert any(r.name == "alice" for r in revoked)


def test_revoke_nonexistent_client_raises(paths):
    with pytest.raises(ClientNotFoundError):
        client_manager.revoke_client(paths, "ghost")


def test_show_ovpn_returns_delivered_content(paths):
    result = client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    content = client_manager.show_ovpn(paths, "alice")
    assert content == open(result.ovpn_path, encoding="utf-8").read()


# --- purge_revoked / clean_stale_db_entry / restore_client --------------

def test_purge_revoked_requires_revoked_first(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ClientNotRevokedError):
        client_manager.purge_revoked(paths, "alice")


def test_purge_revoked_removes_leftover_files_keeps_index_row(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.revoke_client(paths, "alice")
    client_manager.purge_revoked(paths, "alice")

    assert not os.path.exists(paths.issued_crt("alice"))
    assert not os.path.exists(paths.private_key("alice"))
    # index.txt row (audit trail) must survive a purge -- mirrors
    # do_purge_revoked's own docstring in the bash script.
    with open(paths.index_txt, encoding="utf-8") as f:
        assert "/CN=alice" in f.read()


def test_clean_stale_db_entry_refuses_if_client_still_valid(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ClientAlreadyExistsError):
        client_manager.clean_stale_db_entry(paths, "alice")


def test_clean_stale_db_entry_removes_orphan_line(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.revoke_client(paths, "alice")
    # Manually re-insert a stale line (simulating a DB entry that survived
    # a revoke some other way) to exercise the clean path.
    with open(paths.db_file, "a", encoding="utf-8") as f:
        f.write("alice=aa:bb:cc:dd:ee:ff\n")
    client_manager.clean_stale_db_entry(paths, "alice")
    assert "alice=" not in open(paths.db_file, encoding="utf-8").read()


def test_restore_client_issues_fresh_cert(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.revoke_client(paths, "alice")

    result = client_manager.restore_client(paths, "alice", "11:22:33:44:55:66")
    assert result.client == "alice"
    assert result.mac == "11:22:33:44:55:66"
    assert os.path.exists(paths.issued_crt("alice"))
    # New cert should now show as valid ("V"), not revoked -- restore issues
    # a brand-new index.txt row, it does not un-revoke the old one.
    valid_clients = [c.name for c in client_manager.list_clients(paths)]
    assert "alice" in valid_clients


def test_restore_client_requires_revoked_first(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ClientNotRevokedError):
        client_manager.restore_client(paths, "alice", "11:22:33:44:55:66")


# --- MAC management --------------------------------------------------------

def test_add_mac_and_list_macs(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.add_mac(paths, "alice", "11:22:33:44:55:66")

    result = client_manager.list_macs(paths, "alice")
    assert result.count == 2
    assert set(result.macs) == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}


def test_add_mac_rejects_exact_duplicate(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(MacAlreadyRegisteredError):
        client_manager.add_mac(paths, "alice", "aa:bb:cc:dd:ee:ff")


def test_add_mac_rejects_cross_client_conflict(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.add_client(paths, "bob", "11:22:33:44:55:66")
    with pytest.raises(MacAlreadyRegisteredError):
        client_manager.add_mac(paths, "alice", "11:22:33:44:55:66")


def test_add_mac_requires_existing_client(paths):
    with pytest.raises(ClientNotFoundError):
        client_manager.add_mac(paths, "ghost", "aa:bb:cc:dd:ee:ff")


def test_remove_mac_preserves_file_permissions(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.add_mac(paths, "alice", "11:22:33:44:55:66")

    os.chmod(paths.db_file, 0o664)
    before_mode = os.stat(paths.db_file).st_mode

    client_manager.remove_mac(paths, "alice", "11:22:33:44:55:66")

    after_mode = os.stat(paths.db_file).st_mode
    assert after_mode == before_mode
    remaining = client_manager.list_macs(paths, "alice")
    assert remaining.macs == ["aa:bb:cc:dd:ee:ff"]


def test_remove_mac_not_found_raises(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(MacNotFoundError):
        client_manager.remove_mac(paths, "alice", "ff:ff:ff:ff:ff:ff")


# --- list_clients / check_consistency / lint_db --------------------------

def test_list_clients_reports_mac_count_and_in_db(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.add_mac(paths, "alice", "11:22:33:44:55:66")

    clients = {c.name: c for c in client_manager.list_clients(paths)}
    assert clients["alice"].in_db is True
    assert clients["alice"].mac_count == 2


def test_check_consistency_detects_orphan_db_entry(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with open(paths.db_file, "a", encoding="utf-8") as f:
        f.write("ghost=ff:ff:ff:ff:ff:ff\n")

    report = client_manager.check_consistency(paths)
    assert report.clean is False
    assert "ghost" in report.orphan_db
    assert report.orphan_pki == []


def test_check_consistency_clean_when_matched(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    report = client_manager.check_consistency(paths)
    assert report.clean is True


def test_lint_db_flags_malformed_line_but_not_blank_line(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with open(paths.db_file, "a", encoding="utf-8") as f:
        f.write("\nnot-a-valid-line\n")

    report = client_manager.lint_db(paths)
    assert report.clean is False  # the malformed line trips this
    assert any("malformed" in issue for issue in report.issues)
    assert any("blank line" in issue for issue in report.issues)


def test_lint_db_clean_file_is_clean(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    report = client_manager.lint_db(paths)
    assert report.clean is True
    assert report.trailing_newline_ok is True


def test_lint_db_detects_duplicate_mac_across_clients(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.add_client(paths, "bob", "11:22:33:44:55:66")
    # Force a duplicate MAC assignment directly into the file (bypassing the
    # add_mac guard) to exercise lint_db's own detection of it.
    with open(paths.db_file, "a", encoding="utf-8") as f:
        f.write("bob=aa:bb:cc:dd:ee:ff\n")

    report = client_manager.lint_db(paths)
    assert report.clean is False
    assert any("assigned to multiple clients" in issue for issue in report.issues)


# --- idempotency: re-run twice ------------------------------------------

def test_add_client_twice_is_rejected_not_silently_duplicated(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ClientAlreadyExistsError):
        client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    # Still exactly one DB_FILE line, not two.
    assert len(open(paths.db_file, encoding="utf-8").read().splitlines()) == 1


def test_revoke_client_twice_second_call_raises(paths):
    client_manager.add_client(paths, "alice", "aa:bb:cc:dd:ee:ff")
    client_manager.revoke_client(paths, "alice")
    with pytest.raises(ClientNotFoundError):
        client_manager.revoke_client(paths, "alice")
