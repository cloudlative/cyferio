#!/usr/bin/env python3
"""
vpn-status.py -- inspect OpenVPN client connections on this server: who's
online right now, all known clients with last-seen, bandwidth usage, and
rejected (MAC-mismatch) connection attempts.

Usage:
  python3 vpn-status.py                               Currently-connected clients
  python3 vpn-status.py --all-clients                 All known clients (online + offline), with last-seen
  python3 vpn-status.py --rejected-connections [N]    Last N rejected connection attempts (default 20)
  python3 vpn-status.py --session-history [N]         Last N ended connection sessions (default 20)
  python3 vpn-status.py --json                        Any of the above, as JSON instead of a table

Config: reads /etc/openvpn/vpn-tools.conf if present (KEY=VALUE lines),
falls back to the defaults below otherwise -- see vpn-tools.conf.example.

Notes:
- OpenVPN's protocol does not expose the connecting machine's OS login
  username -- only device platform/MAC, and only when the client sends
  push-peer-info (baked into every .ovpn issued by openvpn-install.sh).
- "Rejected" here means the client-connect script (openvpn-mac-addr-check.py)
  refused the connection -- not a TLS/cert failure, which wouldn't reach
  that script at all. See each row's "reason": mac_mismatch (cert-CN +
  device-MAC pairing didn't match openvpn_db.txt), os_not_allowed,
  country_not_allowed, country_lookup_failed, or bandwidth_exceeded (the
  last four only apply to a client with a restriction configured in
  client_policy.json -- see the web app's "Manage Restrictions" dialog).
"""
import argparse
import glob
import gzip
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

CONFIG_FILE = "/etc/openvpn/vpn-tools.conf"

DEFAULTS = {
    "OPENVPN_DIR": "/etc/openvpn/server",
    "EASYRSA_DIR": "/etc/openvpn/server/easy-rsa",
    "DB_FILE": "/etc/openvpn/server/openvpn_db.txt",
    "STATUS_LOG": "/var/log/openvpn/openvpn-status.log",
    "CONN_LOG": "/etc/openvpn/server/openvpn.log",
    "SESSION_HISTORY_FILE": "/etc/openvpn/server/policy/session_history.jsonl",
}


def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


CFG = load_config()
STATUS_LOG = CFG["STATUS_LOG"]
CONN_LOG = CFG["CONN_LOG"]
DB_FILE = CFG["DB_FILE"]
SESSION_HISTORY_FILE = CFG["SESSION_HISTORY_FILE"]
PKI_INDEX = os.path.join(CFG["EASYRSA_DIR"], "pki", "index.txt")

NOTE_OS_MAC = (
    "Note: 'OS' = device platform reported by the client via push-peer-info, not an OS\n"
    "login username (OpenVPN doesn't expose that). 'n/a' means no matched connection\n"
    "with peer-info has been logged yet for this client."
)


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------

def read_privileged_file(path):
    """Read a file that may be root-only (status log, PKI index/private dir,
    session-history log), escalating via `sudo cat` if a direct read isn't
    permitted. Returns None if the file genuinely doesn't exist (vs. just
    being unreadable) -- e.g. session_history.jsonl before any client has
    ever connected/disconnected once, which is a normal, expected state on
    a fresh install, not an error.

    Checked before the os.access() readability check below, not folded into
    it: os.access() on a nonexistent path also just returns False (same as
    "exists but not readable"), so without this early return a missing file
    would fall through to attempting `sudo cat` on a path that will never
    succeed -- pure wasted work at best, and see the FileNotFoundError note
    below for what it does at worst in a container with no sudo binary."""
    if not os.path.exists(path):
        return None
    if os.access(path, os.R_OK):
        with open(path) as f:
            return f.read()
    try:
        out = subprocess.run(["sudo", "cat", path], capture_output=True, text=True, check=True)
        return out.stdout
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        # `sudo` itself isn't installed -- true in this project's own
        # Alpine-based app container (see app/Dockerfile), which always
        # already runs as root there anyway (see docker-compose.yml's own
        # comment on why USE_SUDO=false in that deployment), so escalation
        # was never actually reachable in practice for a root caller; only
        # a non-root caller on a sudo-less host hits this. Fail soft (None)
        # rather than crashing the whole script over a file that was
        # already known to need escalation to read.
        return None


def read_status():
    content = read_privileged_file(STATUS_LOG)
    return content or ""


def load_db():
    """name -> mac (last entry wins if a name has multiple device MACs)."""
    db = {}
    if os.path.exists(DB_FILE):
        with open(DB_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" not in line:
                    continue
                name, mac = line.split("=", 1)
                db[name] = mac
    return db


def load_pki_clients():
    """Set of client CNs with a currently-valid (non-revoked) cert, excluding the server cert.
    pki/ is root-only (700, holds private keys) -- escalates via sudo like the status log."""
    names = set()
    content = read_privileged_file(PKI_INDEX)
    if not content:
        return names
    for line in content.splitlines():
        if not line.startswith("V"):
            continue
        m = re.search(r"/CN=(.+?)\s*$", line)
        if m and m.group(1) != "server":
            names.add(m.group(1))
    return names


ENV_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*): (.*)$")


def connect_log_files():
    files = [CONN_LOG] + sorted(glob.glob(CONN_LOG + ".*"))
    return [f for f in files if os.path.exists(f)]


def block_timestamp(block):
    """Prefer OpenVPN's own time_unix/time_ascii env vars over anything else --
    reliable and always present, unlike the client-connect script's own
    separator/timestamp lines (observed not to reliably land in the log)."""
    if "time_unix" in block:
        try:
            return datetime.fromtimestamp(int(block["time_unix"]))
        except (ValueError, OSError):
            pass
    if "time_ascii" in block:
        try:
            return datetime.strptime(block["time_ascii"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def iter_env_blocks():
    """
    Parse the client-connect script's per-attempt env dumps ("KEY : VALUE"
    lines) across current + rotated connect logs (plain and .gz), delimited
    by the script's own "successfully matched" / "could not be found" lines
    -- these mark the end of one attempt's block reliably even though the
    script's separator/timestamp lines do not.
    Yields dicts with whatever KEY:VALUE pairs were dumped, plus 'matched'
    (bool) and 'timestamp' (datetime or None).
    """
    for path in connect_log_files():
        opener = gzip.open if path.endswith(".gz") else open
        try:
            fh = opener(path, "rt", errors="ignore")
        except (FileNotFoundError, PermissionError):
            continue
        with fh:
            block = {}
            for line in fh:
                stripped = line.rstrip("\n")
                if "successfully matched" in stripped:
                    block["matched"] = True
                    block["timestamp"] = block_timestamp(block)
                    yield block
                    block = {}
                    continue
                # "could not be found" is the original (MAC-mismatch-only)
                # rejection marker; "connection rejected" is the newer,
                # equally unambiguous marker added for the other rejection
                # reasons (os_not_allowed, country_not_allowed,
                # country_lookup_failed, bandwidth_exceeded) -- see
                # host-scripts/openvpn-mac-addr-check.py's reject(). Both
                # are recognized so log lines written before and after that
                # change parse the same way.
                if "could not be found" in stripped or "connection rejected" in stripped.lower():
                    block["matched"] = False
                    block["timestamp"] = block_timestamp(block)
                    yield block
                    block = {}
                    continue
                # Env-dump lines actually observed in practice are
                # "KEY: value" (from the client-connect script's print(),
                # captured via OpenVPN's stdout logging) -- NOT the
                # "KEY : value" the script's own LogFile.write() calls would
                # produce, which don't appear to reliably land in the log at
                # all. Match plain identifier-style keys to avoid false
                # positives from unrelated OpenVPN log prose that happens to
                # contain ": " (e.g. "Control Channel: TLSv1.3, ...").
                m = ENV_LINE_RE.match(stripped)
                if m:
                    block[m.group(1)] = m.group(2)
            # any dangling partial block at EOF (no match line seen) is dropped


def latest_matched_blocks():
    """name -> most recent matched block, across all connect logs."""
    latest = {}
    for block in iter_env_blocks():
        if not block.get("matched"):
            continue
        name = block.get("common_name")
        ts = block.get("timestamp")
        if not name or ts is None:
            continue
        if name not in latest or ts > latest[name]["timestamp"]:
            latest[name] = block
    return latest


# CLIENT_LIST's "Real Address" field is "proto:ip:port" (e.g.
# "udp4:182.185.203.112:53266", or "tcp6:[2001:db8::1]:1194" for IPv6) on
# this OpenVPN version -- NOT plain "ip:port". Found live 2026-08-20: the
# web app's "My VPN Profile" Current Session card was showing the literal
# string "udp4" as Source IP for every connected session, because this
# function used to do a naive `real_addr.split(":")[0]`, which returns
# the *protocol* on this shape, not the IP -- silently wrong for every
# session, always (not an edge case). Mirrors
# app/services/openvpn/management_client.py's parse_source_ip() exactly
# (that function already got this right, for an unrelated reason -- see
# its own docstring -- but couldn't be reused here: this script has to
# stay a standalone, dependency-free CLI usable outside the app).
_REAL_ADDRESS_PROTO_RE = re.compile(r"^(?:udp|tcp)[46]:")


def parse_real_address_ip(real_address):
    addr = _REAL_ADDRESS_PROTO_RE.sub("", real_address, count=1)
    if addr.startswith("["):  # bracketed IPv6, e.g. "[2001:db8::1]:1194"
        end = addr.find("]")
        return addr[1:end] if end != -1 else addr
    return addr.rsplit(":", 1)[0] if ":" in addr else addr  # IPv4 "ip:port" -> "ip"


def get_connected():
    status = read_status()
    now = time.time()
    rows = []
    for line in status.splitlines():
        if not line.startswith("CLIENT_LIST,"):
            continue
        parts = line.split(",")
        name = parts[1]
        real_addr = parts[2]
        bytes_recv = parts[5]
        bytes_sent = parts[6]
        since_str = parts[7]
        since_epoch = int(parts[8])
        ip = parse_real_address_ip(real_addr)
        rows.append({
            "name": name,
            "source_ip": ip,
            "bytes_received": int(bytes_recv),
            "bytes_sent": int(bytes_sent),
            "connected_since": since_str,
            "connected_since_epoch": since_epoch,
            "duration_seconds": int(now - since_epoch),
        })
    return rows


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------

MACOS_BUILD_RE = re.compile(r"^(\d+(?:\.\d+)*)\.([0-9A-Za-z]+)$")


def format_os(block):
    """Best-effort human-readable OS string from a matched env block.
    macOS clients report UV_PLAT_REL in Apple's raw `sw_vers`-style
    "<version>.<build>" form (e.g. "26.5.2.25F84"), which reads as noise
    next to Windows's "Microsoft_Windows_10_Pro_..." or plain "linux" --
    detect macOS (via IV_GUI_VER containing "macOS", or IV_PLAT == "mac")
    and reformat as "macOS <version> (<build>)" instead."""
    if not block:
        return "n/a"
    plat_rel = block.get("UV_PLAT_REL")
    gui_ver = block.get("IV_GUI_VER", "")
    iv_plat = block.get("IV_PLAT", "")
    is_mac = "macos" in gui_ver.lower() or iv_plat == "mac"
    if is_mac and plat_rel:
        m = MACOS_BUILD_RE.match(plat_rel)
        if m:
            return f"macOS {m.group(1)} ({m.group(2)})"
        return f"macOS {plat_rel}"
    return plat_rel or iv_plat or "n/a"


def human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "n/a"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{int(n)}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def fmt_duration(seconds):
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    return f"{d}d {h}h {m}m"


def print_table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
              for i, h in enumerate(headers)]
    fmt = "  ".join("{:<%d}" % w for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[str(c) for c in r]))


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_connected(as_json):
    rows = get_connected()
    db = load_db()
    latest = latest_matched_blocks()

    for r in rows:
        block = latest.get(r["name"])
        if block:
            r["mac"] = block.get("IV_HWADDR", "n/a")
            r["os"] = format_os(block)
        else:
            r["mac"] = db.get(r["name"], "n/a")
            r["os"] = "n/a"
        r["duration"] = fmt_duration(r["duration_seconds"])
        r["bytes_received_h"] = human_bytes(r["bytes_received"])
        r["bytes_sent_h"] = human_bytes(r["bytes_sent"])

    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return

    if not rows:
        print("No clients currently connected.")
        return

    headers = ("NAME", "SOURCE_IP", "MAC", "OS", "RX", "TX", "CONNECTED_SINCE", "DURATION")
    table = [[r["name"], r["source_ip"], r["mac"], r["os"], r["bytes_received_h"],
              r["bytes_sent_h"], r["connected_since"], r["duration"]] for r in rows]
    print_table(headers, table)
    print()
    print(NOTE_OS_MAC)


def cmd_all(as_json):
    pki_clients = load_pki_clients()
    db = load_db()
    connected = get_connected()
    connected_by_name = {r["name"]: r for r in connected}
    latest = latest_matched_blocks()

    all_names = sorted(pki_clients | set(connected_by_name) | set(latest))
    rows = []
    for name in all_names:
        online = name in connected_by_name
        in_pki = name in pki_clients
        block = latest.get(name)
        mac = (block.get("IV_HWADDR") if block else None) or db.get(name, "n/a")
        osname = format_os(block)

        # PKI is authoritative for validity: a name showing up here only via
        # connection history (not a currently-valid cert) has been revoked
        # -- distinct from "offline", which implies they could reconnect.
        if online:
            status = "online"
        elif in_pki:
            status = "offline"
        else:
            status = "revoked"

        row = {
            "name": name,
            "status": status,
            "mac": mac,
            "os": osname,
            "in_pki": in_pki,
            "in_db": name in db,
        }
        if online:
            c = connected_by_name[name]
            row["last_seen"] = "now (connected)"
            row["source_ip"] = c["source_ip"]
            row["duration"] = fmt_duration(c["duration_seconds"])
            row["bytes_received_h"] = human_bytes(c["bytes_received"])
            row["bytes_sent_h"] = human_bytes(c["bytes_sent"])
        else:
            row["last_seen"] = block["timestamp"].isoformat() if block and block.get("timestamp") else "never"
        rows.append(row)

    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return

    headers = ("NAME", "STATUS", "MAC", "OS", "LAST_SEEN")
    table = [[r["name"], r["status"], r["mac"], r["os"], r["last_seen"]] for r in rows]
    print_table(headers, table)
    print()
    print(NOTE_OS_MAC)

    orphans_pki = [r["name"] for r in rows if r["in_pki"] and not r["in_db"]]
    orphans_db = [r["name"] for r in rows if r["in_db"] and not r["in_pki"]]
    if orphans_pki:
        print(f"Note: valid cert but no openvpn_db.txt entry (can't connect until added): {', '.join(orphans_pki)}")
    if orphans_db:
        print(f"Note: openvpn_db.txt entry with no matching valid cert (stale, consider cleanup): {', '.join(orphans_db)}")


def cmd_rejected(limit, as_json):
    db = load_db()
    all_blocks = [b for b in iter_env_blocks() if b.get("matched") is False]

    # Repeat counts are computed across the *full* rejection history, not
    # just the limited/displayed window -- a name that's been rejected 40
    # times but only the latest 20 are shown should still read as "40", not
    # reset to whatever fits on screen.
    total_by_name = {}
    total_by_name_mac = {}
    for b in all_blocks:
        name = b.get("common_name", "n/a")
        mac = b.get("IV_HWADDR", "n/a")
        total_by_name[name] = total_by_name.get(name, 0) + 1
        total_by_name_mac[(name, mac)] = total_by_name_mac.get((name, mac), 0) + 1

    all_blocks.sort(key=lambda b: b["timestamp"] or datetime.min, reverse=True)
    blocks = all_blocks[:limit]

    def _mac_registered(b):
        # A row logged after this field shipped has a "registered_mac_at_time:"
        # line -- a FROZEN historical fact (what was actually on file at the
        # moment this specific attempt was rejected), never recomputed
        # later. "none" means the identity genuinely had no MAC on file
        # then, distinct from a row that simply predates this field (no
        # such key at all), which falls back to today's live lookup --
        # see host-scripts/openvpn-mac-addr-check.py's reject() docstring
        # and this function's own module-level note above on why a live
        # recompute against historical rows is misleading (an admin
        # registering the MAC later must never make an old rejection look
        # retroactively "resolved").
        frozen = b.get("registered_mac_at_time")
        if frozen is not None:
            return (frozen if frozen != "none" else "not registered"), False
        return db.get(b.get("common_name", ""), "not registered"), True

    rows = []
    for b in blocks:
        mac_registered, mac_registered_is_live = _mac_registered(b)
        rows.append({
            "timestamp": b["timestamp"].isoformat() if b.get("timestamp") else "unknown",
            "claimed_name": b.get("common_name", "n/a"),
            "mac_presented": b.get("IV_HWADDR", "n/a"),
            "mac_registered": mac_registered,
            # True only for rows that predate the registered_mac_at_time
            # field -- the frontend uses this to show an honest "this is a
            # live lookup, not historical record" caveat instead of the
            # old, misleading "now matches -- likely fixed" wording, which
            # implied a resolved historical fact this app never actually had.
            "mac_registered_is_live": mac_registered_is_live,
            "os": format_os(b),
            "platform": b.get("IV_PLAT", "n/a"),
            "source_ip": b.get("trusted_ip") or b.get("untrusted_ip", "n/a"),
            "source_port": b.get("trusted_port") or b.get("untrusted_port", "n/a"),
            # Defaults to "mac_mismatch" for log lines written before the
            # per-client restriction feature existed -- they never had a
            # "reason:" line at all, but every rejection logged back then WAS
            # a MAC mismatch (the only check that existed), so this default is
            # accurate, not just a placeholder.
            "reason": b.get("reason", "mac_mismatch"),
            "total_attempts_this_name": total_by_name.get(b.get("common_name", "n/a"), 1),
            "total_attempts_this_mac": total_by_name_mac.get((b.get("common_name", "n/a"), b.get("IV_HWADDR", "n/a")), 1),
        })

    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return

    if not rows:
        print("No rejected connection attempts found in available logs.")
        return

    headers = ("TIMESTAMP", "CLAIMED_NAME", "REASON", "MAC_PRESENTED", "MAC_REGISTERED", "OS", "SOURCE_IP:PORT", "TOTAL_ATTEMPTS")
    table = [[r["timestamp"], r["claimed_name"], r["reason"], r["mac_presented"], r["mac_registered"], r["os"],
              f"{r['source_ip']}:{r['source_port']}", r["total_attempts_this_name"]] for r in rows]
    print_table(headers, table)
    print()
    print("These are connections whose certificate CN + device MAC pair did not match")
    print("openvpn_db.txt -- rejected before reaching the VPN. Repeated entries for the")
    print("same name/IP are usually a client-side device/network issue (wrong adapter,")
    print("stale registration) rather than an attack, but worth a look if unexpected.")


def iter_session_history():
    """Yields one dict per line of SESSION_HISTORY_FILE (see host-scripts/
    policy_lib.py's append_session_history() for the writer and exact
    field set/semantics -- notably connected_at/disconnected_at are
    derived from duration_seconds + the disconnect script's own wall
    clock, NOT from OpenVPN's time_unix, which is empirically the
    session's START time, not "now" -- see that script's own comment).
    Malformed lines (partial write, corruption) are silently skipped
    rather than raising -- one bad line must never break the whole page.
    Uses read_privileged_file for the same reason STATUS_LOG does: this
    script may run unprivileged directly (e.g. from a terminal) even
    though the web app always invokes it via sudo."""
    content = read_privileged_file(SESSION_HISTORY_FILE)
    if not content:
        return
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def cmd_session_history(limit, as_json, client_filter=None):
    rows = list(iter_session_history())
    if client_filter:
        rows = [r for r in rows if r.get("client") == client_filter]
    # Newest-disconnected-first, same ordering convention as cmd_rejected.
    rows.sort(key=lambda r: r.get("disconnected_at") or "", reverse=True)
    rows = rows[:limit]
    for r in rows:
        r["duration_human"] = fmt_duration(r.get("duration_seconds", 0))

    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return

    if not rows:
        print("No session history found.")
        return

    headers = ("CLIENT", "CONNECTED_AT", "DISCONNECTED_AT", "DURATION", "SOURCE_IP", "BYTES_RX", "BYTES_TX")
    table = [[r.get("client", "n/a"), r.get("connected_at", "n/a"), r.get("disconnected_at", "n/a"),
              r["duration_human"], r.get("source_ip", "n/a"),
              human_bytes(r.get("bytes_received", 0)), human_bytes(r.get("bytes_sent", 0))] for r in rows]
    print_table(headers, table)


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Inspect OpenVPN client connections.")
    ap.add_argument("--all-clients", action="store_true", help="Show all known clients (online + offline) with last-seen")
    ap.add_argument("--rejected-connections", nargs="?", const=20, type=int, metavar="N",
                     help="Show the last N rejected (MAC-mismatch) connection attempts (default 20)")
    ap.add_argument("--session-history", nargs="?", const=20, type=int, metavar="N",
                     help="Show the last N ended connection sessions (default 20)")
    ap.add_argument("--client", type=str, default=None, metavar="NAME",
                     help="With --session-history, only show sessions for this client name")
    ap.add_argument("--json", action="store_true", help="Output as JSON instead of a table")
    args = ap.parse_args()

    if args.session_history is not None:
        cmd_session_history(args.session_history, args.json, args.client)
    elif args.rejected_connections is not None:
        cmd_rejected(args.rejected_connections, args.json)
    elif args.all_clients:
        cmd_all(args.json)
    else:
        cmd_connected(args.json)


if __name__ == "__main__":
    main()
