import os
import subprocess

from services.openvpn import certificate_manager


def test_base_pki_fixture_produces_valid_files(paths):
    """Sanity-checks the shared session fixture itself: CA/server cert/CRL/
    tc.key/DH all exist and the server cert verifies against the CA -- if
    this fails, every other test in this file is testing against a broken
    foundation."""
    assert os.path.exists(paths.installed_ca_crt)
    assert os.path.exists(paths.installed_server_crt)
    assert os.path.exists(paths.installed_server_key)
    assert os.path.exists(paths.installed_crl_pem)
    assert os.path.exists(paths.dh_pem)
    assert os.path.exists(paths.tc_key)

    result = subprocess.run(
        ["openssl", "verify", "-CAfile", paths.installed_ca_crt, paths.installed_server_crt],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_dh_params_are_the_pinned_ffdhe2048_blob(paths):
    """Mirrors openvpn-install.sh:1222-1229 -- DH params are a static
    pinned blob, not freshly generated per install."""
    with open(paths.dh_pem, encoding="utf-8") as f:
        content = f.read()
    assert content == certificate_manager.FFDHE2048_PEM


def test_build_client_cert_and_verify(paths):
    certificate_manager.build_client_cert(paths, "alice")
    assert os.path.exists(paths.issued_crt("alice"))
    assert os.path.exists(paths.private_key("alice"))

    result = subprocess.run(
        ["openssl", "verify", "-CAfile", paths.ca_crt, paths.issued_crt("alice")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    # CN in the issued cert should be exactly the client name (easyrsa's own
    # behavior, not something this module computes -- just confirming the
    # invocation was correct).
    cn = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-in", paths.issued_crt("alice")],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "CN = alice" in cn or "CN=alice" in cn


def test_revoke_client_cert_regenerates_crl(paths):
    certificate_manager.build_client_cert(paths, "bob")
    bob_serial = _cert_serial(paths.issued_crt("bob"))

    certificate_manager.revoke_client_cert(paths, "bob")

    # bob's actual serial number should now appear in the regenerated CRL's
    # revoked-certificate list -- a real content check, not just "a file got
    # touched" (CRL timestamps have only 1-second resolution, so a
    # before/after timestamp diff can spuriously pass/fail).
    crl_text = subprocess.run(
        ["openssl", "crl", "-noout", "-text", "-in", paths.pki_crl_pem],
        capture_output=True, text=True, check=True,
    ).stdout
    assert bob_serial.upper() in crl_text.upper()

    # Revoked cert should now show up as "R" in index.txt.
    with open(paths.index_txt, encoding="utf-8") as f:
        rows = [line.split("\t") for line in f.read().splitlines()[1:] if line.strip()]
    bob_rows = [r for r in rows if len(r) >= 6 and r[5] == "/CN=bob"]
    assert bob_rows and bob_rows[0][0] == "R"


def _cert_serial(cert_path: str) -> str:
    out = subprocess.run(
        ["openssl", "x509", "-noout", "-serial", "-in", cert_path],
        capture_output=True, text=True, check=True,
    ).stdout
    return out.strip().split("=", 1)[1]
