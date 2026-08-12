"""Minimal client for OpenVPN's management interface -- a local text
protocol OpenVPN exposes (when `management <socket> unix` is set in
server.conf, see host_scripts_manager.py) for exactly two things this app
needs: listing currently-connected clients with their live per-session
byte counts (`status 3`), and terminating a specific client's session
(`kill <common_name>`). This is the standard, OpenVPN-native mechanism for
both -- there is no other way to act on an in-progress session (a
client-connect/client-disconnect script only fires at the start/end of a
session, never during it).

Deliberately unauthenticated at the protocol level (no
`management-client-auth`/password file configured) -- the trust boundary
is the Unix socket's own filesystem permissions instead (created by
OpenVPN while still running as root, before it drops privileges to
`nobody`/`nogroup` for the tunnel itself, so the socket ends up root-only
by construction; see host_scripts_manager.py's render_server_conf_additions
docstring). Every caller of this module already runs as root (this app's
CLI actions, invoked via `sudo -n` over SSH by host_executor.py, exactly
like every other host-namespace action), so no additional auth layer adds
real security here, only complexity.

Protocol notes (OpenVPN 2.7, verified against this deployment's actual
`status` FILE output -- the management interface's `status 3` response
uses the same CSV-with-HEADER shape, generated from the same internal
data): each response is either one line (`kill`'s SUCCESS:/ERROR: line)
or a multi-line block terminated by a bare `END` line (`status 3`). This
client reads whichever shape a given command produces; if OpenVPN's exact
wire format for a command ever turns out to differ from what's assumed
here, MgmtProtocolError below is meant to surface that clearly rather than
silently misparsing.
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from .exceptions import OpenVPNError, ValidationError

# Real cert common names in this app are already restricted to
# [0-9a-zA-Z_-] (validator.py's sanitize_client_name) -- enforced again
# here, strictly (reject, don't mangle), as defense in depth against
# management-protocol injection: this is a line-based text protocol, so a
# common_name containing a newline could otherwise smuggle a second
# command into the same `kill <name>` line.
_SAFE_COMMON_NAME = re.compile(r"^[0-9a-zA-Z_-]+$")

_RECV_CHUNK = 4096
_SOCKET_TIMEOUT_SECONDS = 10


class MgmtConnectionError(OpenVPNError):
    """Couldn't connect to the management socket at all -- missing
    `management` directive in server.conf, OpenVPN not running, or a
    permissions problem reaching the socket."""


class MgmtProtocolError(OpenVPNError):
    """Connected fine, but the response didn't look like what this client
    expects -- surfaced distinctly from MgmtConnectionError so a caller
    (and an admin reading the error) can tell "OpenVPN isn't reachable"
    apart from "OpenVPN is reachable but said something this client
    doesn't understand" (e.g. a future OpenVPN version changing the
    `status` wire format)."""


@dataclass
class ClientSession:
    common_name: str
    real_address: str
    virtual_address: str
    bytes_received: int
    bytes_sent: int
    connected_since: str  # OpenVPN's own human-readable string, passed through as-is
    connected_since_epoch: int | None = None  # "Connected Since (time_t)" -- UTC, DST/timezone-proof
    source_ip: str = ""  # real_address with the leading "proto:" and trailing ":port" stripped


# Matches the "proto:" prefix OpenVPN puts on CLIENT_LIST's Real Address
# field, e.g. "udp4:182.185.203.112:53266" or "tcp6:[2001:db8::1]:1194" --
# udp4/udp6/tcp4/tcp6 are the only values OpenVPN emits here.
_REAL_ADDRESS_PROTO_RE = re.compile(r"^(?:udp|tcp)[46]:")


def parse_source_ip(real_address: str) -> str:
    """Extracts just the IP from CLIENT_LIST's "Real Address" field, e.g.
    "udp4:182.185.203.112:53266" -> "182.185.203.112", or
    "tcp6:[2001:db8::1]:1194" -> "2001:db8::1".

    This exists because vpn-status.py's own Source IP column has the
    equivalent bug uncaught until now: it does `real_addr.split(":")[0]`,
    which on this "proto:ip:port" shape returns the *protocol* ("udp4"),
    not the IP -- silently wrong for every session, always. vpn-status.py
    is off-limits to modify (see its own header comment), and its JSON
    output doesn't expose the raw Real Address for a caller to reprocess
    (only the already-mis-sliced result), so that bug can't be fixed
    downstream of it either. This client already gets the correct raw
    value from `status 3` for an unrelated reason (session listing/kill),
    so it's the one place in this app that can compute Source IP
    correctly -- callers needing an accurate Source IP should prefer this
    over vpn-status.py's connected/all-clients "source_ip" field."""
    addr = _REAL_ADDRESS_PROTO_RE.sub("", real_address, count=1)
    if addr.startswith("["):  # bracketed IPv6, e.g. "[2001:db8::1]:1194"
        end = addr.find("]")
        return addr[1:end] if end != -1 else addr
    return addr.rsplit(":", 1)[0] if ":" in addr else addr  # IPv4 "ip:port" -> "ip"


class ManagementClient:
    """One connection, used for exactly one request-response exchange (or a
    short handful, via the context manager) -- not a long-lived pooled
    client. The management interface accepts only one connection at a
    time in practice (a second connect attempt while one is open is
    refused by OpenVPN), so callers (the CLI actions, the quota-enforcer
    poller) are expected to connect, do their work, and disconnect
    promptly rather than holding the socket open."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._sock: socket.socket | None = None

    def __enter__(self) -> "ManagementClient":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def connect(self) -> None:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(_SOCKET_TIMEOUT_SECONDS)
            sock.connect(self.socket_path)
        except OSError as e:
            raise MgmtConnectionError(
                f"Couldn't connect to the OpenVPN management socket at {self.socket_path!r}: {e}. "
                "Is the `management` directive configured in server.conf, and is OpenVPN running?"
            ) from e
        self._sock = sock
        # OpenVPN sends a one-line banner ("...Management Interface Version
        # N -- type 'help' for more info") immediately on connect, before
        # any command is sent -- drain it so it doesn't get mistaken for
        # part of the first real command's response.
        self._read_line()

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _send(self, line: str) -> None:
        assert self._sock is not None, "connect() must be called first"
        try:
            self._sock.sendall((line + "\n").encode("utf-8"))
        except OSError as e:
            raise MgmtConnectionError(f"Failed writing to the management socket: {e}") from e

    def _read_line(self) -> str:
        """Reads a single newline-terminated line. Used only for the
        connect-time banner -- every real command's response is read via
        _read_until_end/_read_block below instead."""
        assert self._sock is not None
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                chunk = self._sock.recv(1)
                if not chunk:
                    break
                buf += chunk
        except OSError as e:
            raise MgmtConnectionError(f"Failed reading from the management socket: {e}") from e
        return buf.decode("utf-8", errors="replace").strip()

    def _read_until_end(self) -> list[str]:
        """Reads lines until a bare `END` line (status 3's terminator),
        returning every line before it."""
        assert self._sock is not None
        lines: list[str] = []
        buf = b""
        try:
            while True:
                chunk = self._sock.recv(_RECV_CHUNK)
                if not chunk:
                    raise MgmtConnectionError("Management socket closed before an END line was seen.")
                buf += chunk
                while b"\n" in buf:
                    raw_line, buf = buf.split(b"\n", 1)
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r")
                    if line == "END":
                        return lines
                    lines.append(line)
        except socket.timeout as e:
            raise MgmtConnectionError("Timed out waiting for the management socket to respond.") from e
        except OSError as e:
            raise MgmtConnectionError(f"Failed reading from the management socket: {e}") from e

    def _read_single_response(self) -> str:
        """Reads exactly one line -- used for commands (`kill`) whose
        response is a single SUCCESS:/ERROR: line with no END terminator."""
        return self._read_line()

    def list_sessions(self) -> list[ClientSession]:
        """Issues `status 3` and returns every currently-connected client's
        session info. Empty list if nobody's connected -- not an error."""
        self._send("status 3")
        lines = self._read_until_end()
        header: list[str] | None = None
        sessions: list[ClientSession] = []
        for line in lines:
            # The management interface's `status 3` response is TAB-
            # separated (confirmed against this deployment's real OpenVPN
            # 2.7.0 socket -- "HEADER\tCLIENT_LIST\tCommon Name\t...",
            # "CLIENT_LIST\tclient\tudp4:...\t..."). This is NOT the same
            # delimiter as the `status` FILE vpn-status.py reads (that one
            # is comma-separated, "HEADER,CLIENT_LIST,Common Name,..." --
            # see this deployment's actual openvpn-status.log). Splitting
            # on "," here (the original implementation) meant every line
            # matched neither the HEADER nor CLIENT_LIST check -- header
            # stayed None and list_sessions() silently returned an empty
            # list for every call, even with clients connected.
            parts = line.split("\t")
            if not parts:
                continue
            if parts[0] == "HEADER" and len(parts) > 1 and parts[1] == "CLIENT_LIST":
                header = parts[2:]  # field names, e.g. "Common Name","Real Address",...
                continue
            if parts[0] == "CLIENT_LIST":
                values = parts[1:]
                if header is None or len(values) < len(header):
                    # A CLIENT_LIST row before its own HEADER row (or a
                    # short row) means this OpenVPN version's `status 3`
                    # output doesn't match the shape this client expects --
                    # surface that clearly rather than silently returning
                    # wrong/empty data.
                    raise MgmtProtocolError(
                        f"Unexpected `status 3` CLIENT_LIST row (no matching HEADER seen yet): {line!r}"
                    )
                row = dict(zip(header, values))
                try:
                    real_address = row["Real Address"]
                    since_epoch_raw = row.get("Connected Since (time_t)")
                    sessions.append(ClientSession(
                        common_name=row["Common Name"],
                        real_address=real_address,
                        virtual_address=row.get("Virtual Address", ""),
                        bytes_received=int(row.get("Bytes Received") or 0),
                        bytes_sent=int(row.get("Bytes Sent") or 0),
                        connected_since=row.get("Connected Since", ""),
                        connected_since_epoch=int(since_epoch_raw) if since_epoch_raw else None,
                        source_ip=parse_source_ip(real_address),
                    ))
                except KeyError as e:
                    raise MgmtProtocolError(f"`status 3` CLIENT_LIST row missing expected field {e}: {line!r}") from e
        return sessions

    def kill(self, common_name: str) -> str:
        """Terminates every session (usually just one) matching
        `common_name`. Returns OpenVPN's own response line. Raises
        MgmtProtocolError if OpenVPN reports the common name wasn't found
        (i.e. that client isn't currently connected) -- callers decide
        whether that should be a hard error or a quiet no-op (e.g. the
        quota enforcer re-checking a client that already disconnected on
        its own between polls should treat this as fine, not a failure).

        Raises ValidationError (not sent to OpenVPN at all) if
        `common_name` contains anything outside this app's own client-name
        character set -- see _SAFE_COMMON_NAME above."""
        if not _SAFE_COMMON_NAME.match(common_name):
            raise ValidationError(f"Refusing to send an unsafe common name to the management interface: {common_name!r}")
        self._send(f"kill {common_name}")
        response = self._read_single_response()
        if response.startswith("SUCCESS"):
            return response
        raise MgmtProtocolError(f"OpenVPN refused to kill session {common_name!r}: {response}")
