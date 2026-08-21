#!/usr/bin/env python3
"""CLI entrypoint for the Python OpenVPN service layer (app/services/openvpn/).

Two roles:
  1. The one command host_executor.py is allowed to run remotely over SSH
     for host-namespace operations (install/uninstall) -- see the Phase 1
     plan's §2a. The restricted sudoers/authorized_keys entry on the host
     should scope to exactly this script.
  2. A directly-runnable tool for local dev/debugging of any action,
     without going through the web app or SSH at all.

Always prints a single JSON object to stdout: {"ok": true, "data": ...} on
success, {"ok": false, "error": {"type": ..., "detail": ..., "context": ...}}
on failure -- structured so host_executor.py never has to scrape stderr
text. Exit code is 0 on success, 1 on a handled OpenVPNError, 2 on anything
else unexpected.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))  # parent of app/
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from app.services.openvpn import client_manager, host_scripts_manager, installer  # noqa: E402
from app.services.openvpn.config_manager import InstallOptions  # noqa: E402
from app.services.openvpn.exceptions import OpenVPNError, ValidationError  # noqa: E402
from app.services.openvpn.management_client import ManagementClient  # noqa: E402
from app.services.openvpn.paths import OpenVPNPaths  # noqa: E402
from app.services.openvpn import service_manager  # noqa: E402
from app.services.openvpn.validator import sanitize_client_name  # noqa: E402
from app.services.system import audit_probe, network_manager  # noqa: E402


def _to_jsonable(value):
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, list):
        return [_to_jsonable(v) for v in value]
    if hasattr(value, "__dict__") and not isinstance(value, (str, int, float, bool, type(None))):
        return {k: _to_jsonable(v) for k, v in vars(value).items()}
    return value


def _ok(data=None) -> int:
    print(json.dumps({"ok": True, "data": _to_jsonable(data)}))
    return 0


def _err(e: OpenVPNError) -> int:
    print(json.dumps({
        "ok": False,
        "error": {"type": type(e).__name__, "detail": e.detail, "context": e.context},
    }))
    return 1


_VPN_TOOLS_CONF = "/etc/openvpn/vpn-tools.conf"
_MAXMIND_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{10,}$")


def _upsert_maxmind_key(license_key: str) -> str:
    """Idempotently sets MAXMIND_LICENSE_KEY in vpn-tools.conf -- the exact
    same read/compare/sed-or-append logic setup.sh's own MaxMind Phase 3
    already implements in bash, ported here so the Settings page's
    "geoip-update" host action can do the identical thing without shelling
    out to setup.sh itself (which does a lot more than this one step).
    Returns a short human-readable status string for the caller's `data`.
    Format-validated the same way setup.sh's own --maxmind-key check is --
    a sanity check against an obvious paste error, not a full MaxMind-side
    validation (that already happens client-side, see routes/settings.py's
    /api/settings/geoip/validate, before this action is ever invoked)."""
    if not _MAXMIND_KEY_RE.match(license_key):
        raise ValidationError(
            "License key doesn't look like a valid MaxMind license key "
            "(expected 10+ alphanumeric/_/- characters).", value=license_key,
        )

    os.makedirs(os.path.dirname(_VPN_TOOLS_CONF), exist_ok=True)
    if not os.path.exists(_VPN_TOOLS_CONF):
        open(_VPN_TOOLS_CONF, "a").close()

    with open(_VPN_TOOLS_CONF, encoding="utf-8") as f:
        lines = f.read().splitlines()

    key_line = f"MAXMIND_LICENSE_KEY={license_key}"
    found = False
    changed = False
    for i, line in enumerate(lines):
        if line.startswith("MAXMIND_LICENSE_KEY="):
            found = True
            if line != key_line:
                lines[i] = key_line
                changed = True
            break

    if found:
        status = "updated" if changed else "unchanged"
    else:
        lines += ["", "# MaxMind GeoLite2 license key -- set by the Settings page.", key_line]
        status = "set"

    if status != "unchanged":
        with open(_VPN_TOOLS_CONF, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    os.chmod(_VPN_TOOLS_CONF, 0o640)
    return status


def _geoip_update(license_key: str | None) -> dict:
    """Handles the Settings page's "Save & Refresh Databases" action --
    optionally upserts the license key (see _upsert_maxmind_key above),
    then runs the existing geoip-update.sh unchanged (see that script's own
    header for what it does: geoipupdate if available, else a direct
    per-edition HTTPS download; Country must succeed for overall success,
    City/ASN failures are logged but don't fail this call, same as the
    weekly systemd-timer-triggered run). geoip-update.sh lives at the repo
    root -- _REPO_ROOT (module-level, see this file's own path-bootstrap
    at the top) is exactly that directory, since this script's own known
    location is app/cli/openvpn_admin.py."""
    key_status = None
    if license_key:
        key_status = _upsert_maxmind_key(license_key)

    script_path = os.path.join(_REPO_ROOT, "geoip-update.sh")
    if not os.path.isfile(script_path):
        raise OpenVPNError(f"geoip-update.sh not found at {script_path}.", path=script_path)

    result = subprocess.run(
        ["/bin/bash", script_path],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise OpenVPNError(
            "geoip-update.sh failed -- see output for which edition(s) and why.",
            exit_code=result.returncode, output=(result.stdout + result.stderr).strip()[-4000:],
        )
    return {"key_status": key_status, "output": result.stdout.strip()[-4000:]}


def _paths_from_args(args: argparse.Namespace) -> OpenVPNPaths:
    if not (args.easyrsa_dir or args.openvpn_dir):
        return OpenVPNPaths.from_conf()
    # When --openvpn-dir is overridden (test/dev against a scratch dir),
    # derive db_file/client_common_file from it too rather than leaving them
    # at the real-system defaults -- those two are conceptually "under
    # OPENVPN_DIR" even though OpenVPNPaths keeps them as independent fields
    # (matching vpn-tools.conf's ability to override each one separately).
    openvpn_dir = args.openvpn_dir or OpenVPNPaths.openvpn_dir
    easyrsa_dir = args.easyrsa_dir or (
        f"{openvpn_dir}/easy-rsa" if args.openvpn_dir else OpenVPNPaths.easyrsa_dir
    )
    return OpenVPNPaths(
        openvpn_dir=openvpn_dir,
        easyrsa_dir=easyrsa_dir,
        db_file=f"{openvpn_dir}/openvpn_db.txt",
        client_common_file=f"{openvpn_dir}/client-common.txt",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openvpn_admin", description=__doc__)
    parser.add_argument("--openvpn-dir", dest="openvpn_dir", default=None)
    parser.add_argument("--easyrsa-dir", dest="easyrsa_dir", default=None)
    sub = parser.add_subparsers(dest="action", required=True)

    p = sub.add_parser("install", help="Fresh install (mirrors openvpn-install.sh's interactive install)")
    p.add_argument("--ip", default=None, help="Local IPv4 (auto-detected if there's exactly one)")
    p.add_argument(
        "--public-ip", default=None,
        help="Public IP/hostname if behind NAT. Auto-detected when omitted and the "
        "resolved local IP is itself private (see network_manager.detect_public_ip).",
    )
    p.add_argument("--port", type=int, default=1194)
    p.add_argument("--protocol", default="udp", choices=["udp", "tcp"])
    p.add_argument("--dns", type=int, default=1, choices=[1, 2, 3, 4, 5, 6])
    p.add_argument(
        "--client-name", default=None,
        help="Name for an optional first client. Omit (or pass an empty string) to "
        "install OpenVPN with no first client at all -- installer.install() then "
        "skips client-cert/.ovpn generation entirely, and this command never calls "
        "add_mac(). A client can always be added afterward via the ordinary "
        "add-client action, exactly like every other client.",
    )
    p.add_argument(
        "--client-mac", default=None,
        help="MAC address to register the first client's cert under -- required only "
        "when --client-name is given (validated in main() below, not here, so the "
        "'X requires Y' relationship stays in one place rather than split across "
        "argparse's own required= mechanics). installer.install() deliberately "
        "mirrors the bash script's own gap of generating the first client's cert "
        "without registering it in DB_FILE (see installer.py); this CLI layer "
        "closes that gap immediately after install by calling the same add_mac() "
        "do_add_client/do_add_mac use, so the first client can actually pass the "
        "MAC check like every other one.",
    )
    p.add_argument("--no-packages", action="store_true", help="Skip OS package install (test/dev only)")

    sub.add_parser("uninstall", help="Remove OpenVPN and all its config")

    p = sub.add_parser("add-client")
    p.add_argument("name")
    p.add_argument("mac")

    p = sub.add_parser("revoke-client")
    p.add_argument("name")

    p = sub.add_parser("restore-client")
    p.add_argument("name")
    p.add_argument("mac")

    p = sub.add_parser("purge-revoked")
    p.add_argument("name")

    p = sub.add_parser("clean-stale-db")
    p.add_argument("name")

    p = sub.add_parser("show-ovpn")
    p.add_argument("name")

    sub.add_parser("list-clients")
    sub.add_parser("list-revoked")

    p = sub.add_parser("list-macs")
    p.add_argument("name")

    p = sub.add_parser("add-mac")
    p.add_argument("name")
    p.add_argument("mac")

    p = sub.add_parser("remove-mac")
    p.add_argument("name")
    p.add_argument("mac")

    sub.add_parser("check-consistency")
    sub.add_parser("lint-db")
    sub.add_parser("status")

    sub.add_parser("list-sessions", help="List currently-connected clients with live session byte counts")

    p = sub.add_parser("kill-session", help="Immediately terminate a client's active VPN session")
    p.add_argument("name")

    p = sub.add_parser(
        "geoip-update",
        help="Write MAXMIND_LICENSE_KEY into vpn-tools.conf (if given) and run geoip-update.sh -- "
        "the host action Settings -> Geo/IP (MaxMind) triggers after a key is saved/changed.",
    )
    p.add_argument(
        "--license-key", default=None,
        help="MaxMind GeoLite2 license key to write into vpn-tools.conf before refreshing. "
        "Omit to just re-run geoip-update.sh against whatever key is already there.",
    )

    p = sub.add_parser(
        "install-host-scripts",
        help="Deploy/repair the MAC-binding + per-client-restriction enforcement scripts "
        "(host-scripts/) on an ALREADY-installed server -- a fresh `install` already does "
        "this automatically. Idempotent, safe to re-run.",
    )
    p.add_argument(
        "--restart", action="store_true",
        help="Also restart the OpenVPN service so a newly-appended server.conf hook block "
        "takes effect immediately. DISRUPTIVE -- drops every currently-connected client. "
        "Omit to only stage the files/server.conf change for a restart at a chosen "
        "maintenance window.",
    )

    sub.add_parser(
        "audit-firewall",
        help="Read-only live firewall/service state (ufw, iptables, nftables, firewalld, "
        "systemd unit enabled/active) for the System Audit module's Phase 2 firewall "
        "checks -- see services/system/audit_probe.py. Never modifies anything.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = _paths_from_args(args)

    try:
        if args.action == "install":
            ip = network_manager.resolve_install_ip(args.ip)
            public_ip = args.public_ip
            # Auto-detect the real public IP when the caller didn't supply
            # one and the resolved local address is itself private (NAT'd
            # cloud VM -- GCP/AWS/etc. never expose the public IP on the
            # NIC itself). Mirrors openvpn-install.sh:1090-1103's own
            # detection, but applied automatically rather than just shown
            # as an interactive-prompt suggestion, since this entrypoint is
            # non-interactive (run over SSH by host_executor.py). Without
            # this, client-common.txt's `remote` line silently gets the
            # private IP, producing an .ovpn no client outside the VM's own
            # network can ever connect with -- reproduced and root-caused
            # on the 34.182.51.24 test box on 2026-08-11 (a public_ip
            # left blank on install resulted in `remote 10.138.0.2 1194`).
            if not public_ip and network_manager.is_private_ipv4(ip):
                public_ip = network_manager.detect_public_ip()
            client_name = (args.client_name or "").strip() or None
            if client_name and not args.client_mac:
                raise ValidationError("--client-mac is required when --client-name is given.")
            opts = InstallOptions(
                ip=ip, port=args.port, protocol=args.protocol, dns=args.dns,
                public_ip=public_ip, group_name=paths.group_name,
            )
            result = installer.install(paths, opts, client_name, install_packages=not args.no_packages)
            mac = client_manager.add_mac(paths, result.client_name, args.client_mac) if client_name else None
            return _ok({**_to_jsonable(result), "mac": mac, "public_ip": public_ip})
        elif args.action == "uninstall":
            installer.uninstall(paths)
            return _ok({"uninstalled": True})
        elif args.action == "add-client":
            return _ok(client_manager.add_client(paths, args.name, args.mac))
        elif args.action == "revoke-client":
            client_manager.revoke_client(paths, args.name)
            return _ok({"revoked": args.name})
        elif args.action == "restore-client":
            return _ok(client_manager.restore_client(paths, args.name, args.mac))
        elif args.action == "purge-revoked":
            client_manager.purge_revoked(paths, args.name)
            return _ok({"purged": args.name})
        elif args.action == "clean-stale-db":
            client_manager.clean_stale_db_entry(paths, args.name)
            return _ok({"cleaned": args.name})
        elif args.action == "show-ovpn":
            return _ok({"name": args.name, "ovpn": client_manager.show_ovpn(paths, args.name)})
        elif args.action == "list-clients":
            return _ok(client_manager.list_clients(paths))
        elif args.action == "list-revoked":
            return _ok(client_manager.list_revoked(paths))
        elif args.action == "list-macs":
            return _ok(client_manager.list_macs(paths, args.name))
        elif args.action == "add-mac":
            mac = client_manager.add_mac(paths, args.name, args.mac)
            return _ok({"name": args.name, "mac": mac})
        elif args.action == "remove-mac":
            mac = client_manager.remove_mac(paths, args.name, args.mac)
            return _ok({"name": args.name, "mac": mac})
        elif args.action == "check-consistency":
            return _ok(client_manager.check_consistency(paths))
        elif args.action == "lint-db":
            return _ok(client_manager.lint_db(paths))
        elif args.action == "status":
            active, raw = service_manager.status(paths.service_name)
            return _ok({"service": paths.service_name, "active": active, "raw": raw})
        elif args.action == "list-sessions":
            with ManagementClient(paths.management_socket) as mc:
                sessions = mc.list_sessions()
            return _ok([vars(s) for s in sessions])
        elif args.action == "kill-session":
            name = sanitize_client_name(args.name)
            with ManagementClient(paths.management_socket) as mc:
                result = mc.kill(name)
            return _ok({"name": name, "result": result})
        elif args.action == "geoip-update":
            return _ok(_geoip_update(args.license_key))
        elif args.action == "install-host-scripts":
            changes = host_scripts_manager.install_host_scripts(paths)
            restarted = False
            if args.restart:
                service_manager.restart(paths.service_name)
                restarted = True
            return _ok({"changes": changes, "restarted": restarted})
        elif args.action == "audit-firewall":
            return _ok(audit_probe.probe_firewall())
        else:  # pragma: no cover - argparse `required=True` already prevents this
            parser.error(f"Unknown action: {args.action}")
            return 2
    except OpenVPNError as e:
        return _err(e)
    except Exception as e:  # unexpected -- still emit structured JSON, exit 2
        print(json.dumps({"ok": False, "error": {"type": type(e).__name__, "detail": str(e), "context": {}}}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
