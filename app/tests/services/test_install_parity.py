"""Real, live-host installer test -- see the Phase 1 plan's §5.

Deliberately SKIPPED by default (not part of the normal `pytest` run,
including CI): this test creates a real systemd unit, real firewall rules,
and a real running OpenVPN server. It's meant to be run explicitly against
the disposable test machine (34.182.51.24), as root, e.g.:

    RUN_LIVE_HOST_TESTS=1 sudo -E python3 -m pytest app/tests/services/test_install_parity.py -v

It always uses a throwaway, non-default port so it can't collide with a
real production install on the same box, and always uninstalls what it
created in a finally block.
"""

from __future__ import annotations

import os

import pytest

from services.openvpn import installer, service_manager
from services.openvpn.config_manager import InstallOptions
from services.openvpn.paths import OpenVPNPaths
from services.system import network_manager

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_HOST_TESTS") != "1",
    reason="Live-host install test -- run explicitly with RUN_LIVE_HOST_TESTS=1 as root on a disposable test machine, never in normal CI.",
)

TEST_PORT = 11941  # deliberately not 1194 or the bash-reference's 11940


def test_install_then_uninstall_real_host():
    if os.geteuid() != 0:
        pytest.skip("must run as root")

    paths = OpenVPNPaths()  # real /etc/openvpn/server -- intentional for this test
    if os.path.exists(paths.server_conf):
        pytest.skip(f"{paths.server_conf} already exists -- refusing to run against a live install")

    ip = network_manager.resolve_install_ip()
    opts = InstallOptions(ip=ip, port=TEST_PORT, protocol="udp", dns=1, group_name=paths.group_name)

    try:
        result = installer.install(paths, opts, first_client_name="paritytest")
        assert result.port == TEST_PORT

        active, raw = service_manager.status(paths.service_name)
        assert active, f"service not active after install: {raw}"
    finally:
        installer.uninstall(paths)
        assert not os.path.exists(paths.server_conf)
