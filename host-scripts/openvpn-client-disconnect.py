#!/usr/bin/python3
#
# openvpn-client-disconnect.py -- client-disconnect script: persists the
# just-ended session's bandwidth (bytes_received + bytes_sent) into
# client_usage.json, for the NEXT connect attempt's weekly-quota check
# (see openvpn-mac-addr-check.py stage 4, and policy_lib.add_usage's lazy
# weekly-rollover handling).
#
# This is deliberately the ONLY place usage is written -- soft cutoff by
# design: a session that goes over quota mid-connection is allowed to keep
# running uninterrupted until it naturally disconnects, not killed
# mid-session. There is no polling daemon and no OpenVPN management-
# interface integration; enforcement happens entirely at the next
# connection attempt.
#
# Install:
#   1) Deploy alongside openvpn-mac-addr-check.py and policy_lib.py in
#      /etc/openvpn/server/, owned nobody:nogroup, chmod +x.
#   2) Add to server.conf (script-security 2 is already required/present
#      for the client-connect script above):
#        client-disconnect /etc/openvpn/server/openvpn-client-disconnect.py
#   3) Restart the OpenVPN server service to pick up the new directive.
#
# Env vars used (provided by OpenVPN to every client-disconnect script):
#   common_name     -- the client's certificate CN (= their name)
#   bytes_received, bytes_sent -- byte counters for the session that just ended
#   time_duration   -- session length in seconds, computed by OpenVPN itself
#   time_unix       -- NOT the disconnect time. Empirically verified (2026-08-09,
#                      real connect/disconnect cycle against this exact
#                      OpenVPN 2.6.19 build) to be the SAME value the
#                      client-CONNECT script sees for the same session --
#                      i.e. this is the session's START time, fixed per
#                      client instance, not "now" at script-invocation
#                      time. Do NOT use it as the disconnect timestamp.
#                      This script instead uses its own wall-clock (now())
#                      as disconnected_at, and derives connected_at by
#                      subtracting time_duration from that -- see
#                      _session_history_record() below.
#   trusted_ip      -- session's source IP

import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy_lib  # noqa: E402

env_user = os.getenv('common_name')


def _int_env(name):
    try:
        return int(os.getenv(name, '0') or 0)
    except ValueError:
        return 0


def _session_history_record(user):
    """Builds one session_history.jsonl record for `user`'s just-ended
    session. disconnected_at is this script's own current time (the
    closest thing to a real "session ended" timestamp available -- see the
    time_unix note above for why that env var isn't usable for this).
    connected_at is derived by subtracting time_duration from
    disconnected_at, which keeps duration/connected_at/disconnected_at
    always mutually consistent even though it means connected_at is a
    computed approximation, not itself a raw OpenVPN timestamp."""
    duration = _int_env('time_duration')
    disconnected_at = datetime.now(timezone.utc)
    connected_at = disconnected_at - timedelta(seconds=duration)
    return {
        "client": user,
        "connected_at": connected_at.isoformat(),
        "disconnected_at": disconnected_at.isoformat(),
        "duration_seconds": duration,
        "source_ip": os.getenv('trusted_ip', ''),
        "bytes_received": _int_env('bytes_received'),
        "bytes_sent": _int_env('bytes_sent'),
    }


if env_user:
    session_bytes = _int_env('bytes_received') + _int_env('bytes_sent')
    if session_bytes > 0:
        try:
            policy_lib.add_usage(env_user, session_bytes)
        except Exception as e:
            # Never let a usage-write problem (e.g. permissions, disk full)
            # turn into a non-zero exit here -- OpenVPN doesn't gate
            # anything on client-disconnect's exit code the way it does
            # client-connect's, but there's no reason to risk it, and this
            # keeps the failure mode purely "usage tracking degraded",
            # never "disconnect processing broke".
            sys.stderr.write("usage write failed for {0}: {1}\n".format(env_user, e))

    # Session history -- independent of the usage write above (a failure
    # in one must never block the other): always recorded, even for a
    # zero-byte session, so a client that connected and immediately
    # disconnected still shows up with an accurate (possibly ~0s) duration
    # rather than silently vanishing from the history.
    try:
        policy_lib.append_session_history(_session_history_record(env_user))
    except Exception as e:
        sys.stderr.write("session history write failed for {0}: {1}\n".format(env_user, e))

sys.exit(0)
