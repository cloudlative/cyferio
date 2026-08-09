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

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy_lib  # noqa: E402

env_user = os.getenv('common_name')


def _int_env(name):
    try:
        return int(os.getenv(name, '0') or 0)
    except ValueError:
        return 0


if env_user:
    session_bytes = _int_env('bytes_received') + _int_env('bytes_sent')
    if session_bytes > 0:
        policy_lib.add_usage(env_user, session_bytes)

sys.exit(0)
