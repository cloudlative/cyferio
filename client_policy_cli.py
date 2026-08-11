#!/usr/bin/env python3
"""
client_policy_cli.py -- companion helper for openvpn-install.sh's
--set-country/--set-os/--set-bandwidth/--get-policy subcommands. Bash has
no good native JSON support, so those subcommands delegate the actual
read-modify-write of client_policy.json to this small standalone script.

This is intentionally a SEPARATE file from host-scripts/policy_lib.py
(imported by the client-connect/disconnect scripts) -- this one ships in
the git repo / wherever openvpn-install.sh lives (e.g. /opt/openvpn-toolkit),
while policy_lib.py is deployed only alongside the connect/disconnect
scripts under /etc/openvpn/server/. The two locations are not guaranteed
to be the same machine layout across every self-hosted install, so this
duplicates the same small atomic-write pattern independently rather than
depending on an import path across those two different install locations.

Usage:
  client_policy_cli.py get NAME                  Print NAME's policy as JSON ({} if unrestricted)
  client_policy_cli.py get-all                    Print every client's policy as JSON
  client_policy_cli.py usage NAME                 Print NAME's current-month usage as JSON
  client_policy_cli.py set-country NAME CODE|-    Set (or "-" to clear) the country restriction
                                                   (CODE is an ISO 3166-1 alpha-2 code, e.g. PK)
  client_policy_cli.py set-os NAME LIST|-         Set (comma list from windows,linux,mac; "-" clears)
  client_policy_cli.py set-bandwidth NAME GB|-    Set (or "-" to clear) the monthly GB quota

Exit 0 on success (prints the affected client's resulting policy/usage
entry as JSON on stdout), 1 on error (message on stderr).

Reads/writes CLIENT_POLICY_FILE / CLIENT_USAGE_FILE as configured in
/etc/openvpn/vpn-tools.conf (same KEY=VALUE convention as
openvpn-install.sh / vpn-status.py), defaulting to
/etc/openvpn/server/client_policy.json and client_usage.json.
"""
import fcntl
import json
import os
import sys
import tempfile
from datetime import date

CONFIG_FILE = "/etc/openvpn/vpn-tools.conf"
DEFAULTS = {
    "CLIENT_POLICY_FILE": "/etc/openvpn/server/policy/client_policy.json",
    "CLIENT_USAGE_FILE": "/etc/openvpn/server/policy/client_usage.json",
}
VALID_OS = {"windows", "linux", "mac"}


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
POLICY_FILE = CFG["CLIENT_POLICY_FILE"]
USAGE_FILE = CFG["CLIENT_USAGE_FILE"]


def _read_only(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            content = f.read().strip()
            return json.loads(content) if content else {}
    except json.JSONDecodeError:
        return {}


def _ensure_dir_writable_by_nobody(d):
    """Same helper as host-scripts/policy_lib.py's own copy -- see that
    module's docstring for the full rationale. This script normally runs
    as root (via openvpn-install.sh/sudo), so this reliably succeeds here,
    unlike the connect/disconnect scripts' own copy (which runs as
    `nobody` and can only rely on this directory already existing)."""
    if os.path.isdir(d):
        return
    try:
        os.makedirs(d, exist_ok=True)
        import grp
        import pwd
        os.chown(d, pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nogroup").gr_gid)
        os.chmod(d, 0o770)
    except (OSError, KeyError):
        pass


def _locked_read_modify_write(path, mutate_fn):
    """Same atomic write-to-tmp-then-os.rename + owner/mode preservation
    pattern as policy_lib.py -- see that module's atomic_write_json()
    docstring for the full rationale (kept in sync manually, not shared
    code, per this file's own module docstring)."""
    lock_path = path + ".lock"
    _ensure_dir_writable_by_nobody(os.path.dirname(lock_path) or ".")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o666)
    # Force 0666 + nobody:nogroup, ignoring umask -- this script normally
    # runs as root (via openvpn-install.sh/sudo), so a lock file it
    # creates/re-opens must not end up unwritable by the OpenVPN host's
    # nobody-run connect/disconnect scripts. See policy_lib.py's identical
    # comment on its own copy of this pattern.
    try:
        os.fchmod(fd, 0o666)
        import grp
        import pwd
        os.fchown(fd, pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nogroup").gr_gid)
    except (OSError, KeyError):
        pass
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        data = _read_only(path)
        result = mutate_fn(data)

        orig_mode = 0o664
        orig_uid = orig_gid = None
        if os.path.exists(path):
            st = os.stat(path)
            orig_mode = st.st_mode & 0o777
            orig_uid, orig_gid = st.st_uid, st.st_gid
        else:
            try:
                import grp
                import pwd
                orig_uid = pwd.getpwnam("nobody").pw_uid
                orig_gid = grp.getgrnam("nogroup").gr_gid
            except (KeyError, ImportError):
                pass

        d = os.path.dirname(path) or "."
        _ensure_dir_writable_by_nobody(d)
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=d)
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.write("\n")
            os.chmod(tmp_path, orig_mode)
            if orig_uid is not None:
                try:
                    os.chown(tmp_path, orig_uid, orig_gid)
                except PermissionError:
                    pass
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return result
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def cmd_get(name):
    data = _read_only(POLICY_FILE)
    print(json.dumps(data.get(name, {}) or {}))


def cmd_get_all():
    print(json.dumps(_read_only(POLICY_FILE)))


def cmd_usage(name):
    data = _read_only(USAGE_FILE)
    entry = data.get(name) or {"period_start": None, "bytes_used": 0}
    period_start = date.today().replace(day=1).isoformat()
    if entry.get("period_start") != period_start:
        entry = {"period_start": period_start, "bytes_used": 0}
    print(json.dumps(entry))


def _set_field(name, field, value):
    def mutate(data):
        entry = dict(data.get(name) or {})
        if value is None:
            entry.pop(field, None)
        else:
            entry[field] = value
        if entry:
            data[name] = entry
        else:
            data.pop(name, None)
        return entry
    return _locked_read_modify_write(POLICY_FILE, mutate)


def cmd_set_country(name, code):
    value = None if code == "-" else code.strip().upper()
    if value is not None and (len(value) != 2 or not value.isalpha()):
        print("Invalid country code: '{0}' -- expected an ISO 3166-1 alpha-2 code (e.g. PK) or '-' to clear.".format(code), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(_set_field(name, "country", value)))


def cmd_set_os(name, os_list):
    if os_list == "-":
        value = None
    else:
        items = [x.strip().lower() for x in os_list.split(",") if x.strip()]
        bad = [x for x in items if x not in VALID_OS]
        if bad:
            print("Invalid OS name(s): {0} -- expected a comma list from: {1}, or '-' to clear.".format(
                ", ".join(bad), ", ".join(sorted(VALID_OS))), file=sys.stderr)
            sys.exit(1)
        value = sorted(set(items)) or None
    print(json.dumps(_set_field(name, "allowed_os", value)))


def cmd_set_bandwidth(name, gb):
    if gb == "-":
        value = None
    else:
        try:
            value = float(gb)
            if value <= 0:
                raise ValueError
        except ValueError:
            print("Invalid bandwidth quota: '{0}' -- expected a positive number of GB, or '-' to clear.".format(gb), file=sys.stderr)
            sys.exit(1)
    print(json.dumps(_set_field(name, "bandwidth_monthly_gb", value)))


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    cmd, rest = args[0], args[1:]
    try:
        if cmd == "get" and len(rest) == 1:
            cmd_get(rest[0])
        elif cmd == "get-all" and len(rest) == 0:
            cmd_get_all()
        elif cmd == "usage" and len(rest) == 1:
            cmd_usage(rest[0])
        elif cmd == "set-country" and len(rest) == 2:
            cmd_set_country(rest[0], rest[1])
        elif cmd == "set-os" and len(rest) == 2:
            cmd_set_os(rest[0], rest[1])
        elif cmd == "set-bandwidth" and len(rest) == 2:
            cmd_set_bandwidth(rest[0], rest[1])
        else:
            print(__doc__, file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print("Error: {0}".format(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
