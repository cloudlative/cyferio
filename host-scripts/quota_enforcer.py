#!/usr/bin/python3
#
# quota_enforcer.py -- Hard Enforcement's poller: fired periodically (via
# the companion systemd timer, see systemd/openvpn-quota-enforcer.service/
# .timer in this repo, installed automatically by
# app/services/openvpn/host_scripts_manager.py's install_host_scripts()),
# checks every currently-connected client's live bandwidth usage against
# its monthly quota, and disconnects any that have crossed it AND are
# configured for "hard" enforcement (client_policy.json's
# quota_enforcement_policy, or the app-wide default when unset -- see
# policy_lib.get_global_defaults).
#
# Soft-enforced clients (the default, and this app's only-ever behavior
# before this script existed) are intentionally left alone here -- their
# enforcement already happens at the NEXT connection attempt, in
# openvpn-mac-addr-check.py's gate 7. This script's only job is the
# in-progress-session case soft enforcement can never cover: acting on a
# session that's already connected, which requires OpenVPN's management
# interface (see policy_lib.py's list_sessions/kill_session) -- no
# client-connect/disconnect script can do that, since those only fire at
# session start/end.
#
# Overshoot window: this only catches a hard-enforced client's quota
# breach on the NEXT time this script runs, not the instant it happens --
# see the systemd timer's interval for how large that window is. A
# shorter interval catches breaches sooner at the cost of more frequent
# management-socket round-trips; this is a deliberate, documented
# trade-off, not a bug (see the architecture review this feature shipped
# with for the full reasoning).
#
# Deploy: automatic, via install_host_scripts()/install-host-scripts --
# no manual step. Requires the `management` directive in server.conf
# (also automatic, same install step) and the OpenVPN service to have
# been (re)started at least once since that directive was added.

import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy_lib  # noqa: E402

LOG_FILE = policy_lib.CFG.get("QUOTA_ENFORCER_LOG", "/etc/openvpn/server/quota-enforcer.log")


def _log(message):
    line = f"{datetime.now(timezone.utc).isoformat()} {message}\n"
    sys.stdout.write(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        pass  # best-effort -- stdout (captured by the systemd unit's own logging) is the fallback


def main():
    try:
        sessions = policy_lib.list_sessions(policy_lib.MANAGEMENT_SOCKET)
    except (OSError, policy_lib.ManagementError) as e:
        # Fails open, loudly: if the management interface isn't reachable
        # (not configured yet, OpenVPN not running, a transient socket
        # problem), there is nothing to enforce this tick -- no
        # currently-connected session is disconnected in error, and the
        # NEXT tick tries again. Never crashes the systemd unit into a
        # failed state over a transient condition.
        _log(f"could not reach management interface at {policy_lib.MANAGEMENT_SOCKET}: {e} -- skipping this run")
        return 0

    if not sessions:
        return 0

    defaults = policy_lib.get_global_defaults()
    for session in sessions:
        name = session["common_name"]
        try:
            policy = policy_lib.get_policy(name)
        except Exception as e:
            _log(f"policy lookup failed for {name}: {e} -- skipping")
            continue

        quota_gb = policy.get("bandwidth_monthly_gb")
        if not quota_gb:
            continue  # no quota configured for this client -- nothing to enforce

        effective_policy = policy.get("quota_enforcement_policy") or defaults["quota_enforcement_policy"]
        if effective_policy != "hard":
            continue  # soft (the default) -- already enforced at the next connection attempt, not here

        try:
            already_used = policy_lib.get_usage(name)
        except Exception as e:
            _log(f"usage lookup failed for {name}: {e} -- treating prior usage as 0 for this check")
            already_used = 0
        live_session_bytes = session["bytes_received"] + session["bytes_sent"]
        total_used = already_used + live_session_bytes
        quota_bytes = float(quota_gb) * (1024 ** 3)

        if total_used < quota_bytes:
            continue

        try:
            killed = policy_lib.kill_session(policy_lib.MANAGEMENT_SOCKET, name)
        except (OSError, policy_lib.ManagementError) as e:
            _log(f"hard-enforcement kill FAILED for {name} "
                 f"({total_used / (1024 ** 3):.2f} / {quota_gb} GB used this month): {e}")
            continue
        if killed:
            _log(f"hard-enforcement kill for {name}: "
                 f"{total_used / (1024 ** 3):.2f} / {quota_gb} GB used this month "
                 f"(already_used={already_used}, live_session_bytes={live_session_bytes})")
        # killed == False means OpenVPN reported the client already
        # disconnected on its own between the status query and the kill
        # attempt (a normal race, not an error) -- nothing to log as an
        # action taken.
    return 0


if __name__ == "__main__":
    sys.exit(main())
