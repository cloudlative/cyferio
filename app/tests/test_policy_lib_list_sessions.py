"""Regression test for the tab-vs-comma parsing bug fixed in
host-scripts/policy_lib.py's list_sessions() (the quota_enforcer.py hard-
enforcement poller's session-listing call). The management interface's
`status 3` response is TAB-separated -- confirmed live against this
deployment's actual OpenVPN 2.7.0 socket -- not comma-separated like the
`status` FILE vpn-status.py reads. The original implementation split on
"," and so silently returned an empty session list on every single call,
even with clients connected: hard quota enforcement never actually
detected an over-quota session since it shipped (v1.8.0).

Runs a tiny fake Unix-socket server that speaks just enough of the real
protocol (banner + a `status 3` response) for list_sessions() to exercise
its real socket-handling code end-to-end, rather than mocking it away.
"""
import importlib.util
import os
import socket
import threading

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_POLICY_LIB_PATH = os.path.join(_REPO_ROOT, "host-scripts", "policy_lib.py")


def _load_policy_lib():
    spec = importlib.util.spec_from_file_location("policy_lib_under_test", _POLICY_LIB_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Captured live via a raw socket query against this deployment's real
# OpenVPN 2.7.0 management interface -- see this fix's commit message.
_REAL_STATUS3_RESPONSE = (
    "TITLE\tOpenVPN 2.7.0 x86_64-pc-linux-gnu\n"
    "TIME\t2026-08-12 13:29:02\t1786541342\n"
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t"
    "Connected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n"
    "CLIENT_LIST\tclient\tudp4:182.185.203.112:38435\t10.8.0.2\t\t"
    "6946445\t38486863\t2026-08-12 13:26:07\t1786541167\tUNDEF\t3\t0\tAES-256-GCM\n"
    "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\n"
    "ROUTING_TABLE\t10.8.0.2\tclient\tudp4:182.185.203.112:38435\t2026-08-12 13:29:02\t1786541342\n"
    "GLOBAL_STATS\tMax bcast/mcast queue length\t1\n"
    "GLOBAL_STATS\tdco_enabled\t0\n"
    "END\n"
)


def _serve_once(srv, response_bytes):
    conn, _ = srv.accept()
    conn.sendall(b">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
    conn.recv(4096)  # the "status 3\n" command -- not inspected, one fixed response either way
    conn.sendall(response_bytes)
    conn.close()
    srv.close()


@pytest.fixture()
def fake_mgmt_socket(tmp_path):
    sock_path = str(tmp_path / "mgmt.sock")

    def _run(response_text):
        # Bind+listen synchronously, before list_sessions() ever tries to
        # connect -- avoids a connect-before-bind race from starting the
        # accept() loop in the background thread.
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        t = threading.Thread(target=_serve_once, args=(srv, response_text.encode("utf-8")), daemon=True)
        t.start()
        return sock_path, t

    return _run


class TestListSessions:
    def test_parses_real_tab_separated_response(self, fake_mgmt_socket):
        policy_lib = _load_policy_lib()
        sock_path, t = fake_mgmt_socket(_REAL_STATUS3_RESPONSE)
        sessions = policy_lib.list_sessions(sock_path)
        t.join(timeout=5)
        assert sessions == [{"common_name": "client", "bytes_received": 6946445, "bytes_sent": 38486863}]

    def test_comma_separated_response_yields_no_sessions(self, fake_mgmt_socket):
        # Regression guard for the actual bug: feeding the (wrong) comma-
        # separated shape must not silently look like "nobody connected"
        # without at least proving the parser genuinely requires tabs.
        policy_lib = _load_policy_lib()
        comma_response = (
            "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,"
            "Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,"
            "Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\n"
            "CLIENT_LIST,client,udp4:182.185.203.112:38435,10.8.0.2,,6946445,38486863,"
            "2026-08-12 13:26:07,1786541167,UNDEF,3,0,AES-256-GCM\n"
            "END\n"
        )
        sock_path, t = fake_mgmt_socket(comma_response)
        sessions = policy_lib.list_sessions(sock_path)
        t.join(timeout=5)
        assert sessions == []

    def test_no_clients_connected(self, fake_mgmt_socket):
        policy_lib = _load_policy_lib()
        response = (
            "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
            "Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t"
            "Connected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n"
            "END\n"
        )
        sock_path, t = fake_mgmt_socket(response)
        sessions = policy_lib.list_sessions(sock_path)
        t.join(timeout=5)
        assert sessions == []
