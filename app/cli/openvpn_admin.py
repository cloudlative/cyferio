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
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_THIS_DIR))  # parent of app/
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from app.services.openvpn import client_manager, installer  # noqa: E402
from app.services.openvpn.config_manager import InstallOptions  # noqa: E402
from app.services.openvpn.exceptions import OpenVPNError, ValidationError  # noqa: E402
from app.services.openvpn.paths import OpenVPNPaths  # noqa: E402
from app.services.openvpn import service_manager  # noqa: E402
from app.services.system import network_manager  # noqa: E402


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
