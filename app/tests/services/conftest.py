"""Fixtures for the Phase 1 Python OpenVPN service layer's tests -- see the
migration plan's §5/§9. Everything here operates against a scratch PKI
directory under pytest's tmp_path, never the real /etc/openvpn.

Building a CA + server cert from scratch (easyrsa init-pki/build-ca/
build-server-full, each its own subprocess) costs a couple of seconds --
too slow to redo per test function. So a session-scoped base PKI is built
once (`_session_base_pki`), and each test gets its own isolated copy of it
(`paths` fixture) via a plain directory copy, which is fast and keeps tests
independent (an add_client in one test can't collide with another's).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # .../app

from services.openvpn import certificate_manager, config_manager  # noqa: E402
from services.openvpn.config_manager import InstallOptions  # noqa: E402
from services.openvpn.paths import OpenVPNPaths  # noqa: E402


def _make_paths(base: Path) -> OpenVPNPaths:
    openvpn_dir = base / "openvpn"
    return OpenVPNPaths(
        openvpn_dir=str(openvpn_dir),
        easyrsa_dir=str(openvpn_dir / "easy-rsa"),
        db_file=str(openvpn_dir / "openvpn_db.txt"),
        client_common_file=str(openvpn_dir / "client-common.txt"),
        ovpn_output_dir=str(base / "output"),
        ovpn_output_owner="",  # skip chown -- tests run as an unprivileged dev user
    )


@pytest.fixture(scope="session")
def _session_base_pki(tmp_path_factory) -> Path:
    """Builds one CA + server cert + CRL + tc.key + client-common.txt, shared
    read-only as a template for every test in this session."""
    base = tmp_path_factory.mktemp("ovpn-base-pki")
    paths = _make_paths(base)
    certificate_manager.download_and_extract_easyrsa(paths.easyrsa_dir)
    certificate_manager.pki_init(paths)
    certificate_manager.build_ca(paths)
    certificate_manager.build_server_cert(paths)
    certificate_manager.gen_crl(paths)
    certificate_manager.install_pki_files(paths)
    certificate_manager.generate_tls_crypt_key(paths)
    certificate_manager.write_dh_params(paths)
    opts = InstallOptions(ip="203.0.113.10", port=1194, protocol="udp", dns=1, group_name="nogroup")
    with open(paths.client_common_file, "w", encoding="utf-8") as f:
        f.write(config_manager.render_client_common(opts))
    return base


@pytest.fixture
def paths(_session_base_pki: Path, tmp_path: Path) -> OpenVPNPaths:
    """A fresh, isolated copy of the shared base PKI for one test."""
    dest = tmp_path / "instance"
    shutil.copytree(_session_base_pki, dest)
    return _make_paths(dest)


@pytest.fixture
def empty_paths(tmp_path: Path) -> OpenVPNPaths:
    """No PKI at all -- for tests of "not installed yet" / validation-only
    behavior that shouldn't pay for a full CA build."""
    return _make_paths(tmp_path / "empty")
