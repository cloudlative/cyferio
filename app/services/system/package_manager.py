"""OS detection + package install dispatch -- Python port of
openvpn-install.sh:21-77 (OS/version detection) and :1187-1196
(apt-get/yum/dnf package install).

Only the "ubuntu" branch is exercised against a real target as of Phase 1
(the test machine at 34.182.51.24 is Ubuntu 26.04) -- the debian/centos/
fedora branches are ported directly from the bash script's own logic as the
spec, per the Phase 1 plan's risk note, but are untested against a real host
of those distros.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ..openvpn.exceptions import UnsupportedOSError
from .process_manager import run_checked

# alpine is deliberately excluded here (bash's os="alpine" branch, :39-54):
# that branch exists only so the containerized web app's Alpine image can
# invoke client/MAC subcommands against an already-installed *host*. It's
# never a real install target, so package_manager.py -- which only backs
# installer.py's actual install step -- doesn't need to represent it.
SUPPORTED_OS = ("ubuntu", "debian", "centos", "fedora")

_MIN_VERSION = {
    "ubuntu": 1804,  # VERSION_ID digits with '.' stripped, e.g. "24.04" -> 2404
    "debian": 9,
    "centos": 7,
}


@dataclass(frozen=True)
class OSInfo:
    os: str  # one of SUPPORTED_OS
    os_version: str
    group_name: str  # "nogroup" (Debian/Ubuntu) or "nobody" (CentOS/Fedora)


def detect_os() -> OSInfo:
    """Mirrors openvpn-install.sh:21-77 exactly, including the per-OS
    minimum-version checks. Raises UnsupportedOSError instead of the bash
    script's `echo ...; exit`."""
    if _read_file_contains("/etc/os-release", "ubuntu"):
        version_id = _grep_field("/etc/os-release", "VERSION_ID").replace(".", "")
        info = OSInfo("ubuntu", version_id, "nogroup")
    elif os.path.exists("/etc/debian_version"):
        version = _first_int(_read_text("/etc/debian_version"))
        info = OSInfo("debian", version, "nogroup")
    elif any(os.path.exists(p) for p in ("/etc/almalinux-release", "/etc/rocky-release", "/etc/centos-release")):
        version = ""
        for p in ("/etc/almalinux-release", "/etc/rocky-release", "/etc/centos-release"):
            if os.path.exists(p):
                version = _first_int(_read_text(p))
                if version:
                    break
        info = OSInfo("centos", version, "nobody")
    elif os.path.exists("/etc/fedora-release"):
        info = OSInfo("fedora", _first_int(_read_text("/etc/fedora-release")), "nobody")
    else:
        raise UnsupportedOSError(
            "This installer seems to be running on an unsupported distribution. "
            "Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, and Fedora."
        )

    _check_min_version(info)
    return info


def _check_min_version(info: OSInfo) -> None:
    minimum = _MIN_VERSION.get(info.os)
    if minimum is None or not info.os_version:
        return
    try:
        version_num = int(info.os_version)
    except ValueError:
        return
    if version_num < minimum:
        raise UnsupportedOSError(
            f"{info.os.capitalize()} {minimum} or higher is required to use this installer. This version ({info.os_version}) is too old and unsupported.",
            os=info.os,
            os_version=info.os_version,
        )


def install_packages(info: OSInfo, packages: list[str]) -> None:
    """Installs `packages` via the OS's native package manager -- ports the
    apt-get/yum/dnf dispatch at openvpn-install.sh:1187-1196. `packages`
    should already exclude anything conditionally empty (bash's `$firewall`
    var, which can be "" for a plain iptables install with no firewalld) --
    callers filter that before calling, this function has no OS-specific
    special-casing."""
    packages = [p for p in packages if p]
    if not packages:
        return
    if info.os in ("debian", "ubuntu"):
        run_checked(["apt-get", "update"], timeout=120, error_prefix="apt-get update failed")
        run_checked(
            ["apt-get", "install", "-y", "--no-install-recommends", *packages],
            timeout=300,
            error_prefix="apt-get install failed",
        )
    elif info.os == "centos":
        run_checked(["yum", "install", "-y", "epel-release"], timeout=120, error_prefix="yum epel-release failed")
        run_checked(["yum", "install", "-y", *packages], timeout=300, error_prefix="yum install failed")
    elif info.os == "fedora":
        run_checked(["dnf", "install", "-y", *packages], timeout=300, error_prefix="dnf install failed")
    else:  # pragma: no cover - detect_os() already rejects anything else
        raise UnsupportedOSError(f"No package manager mapping for OS {info.os!r}", os=info.os)


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _read_file_contains(path: str, needle: str) -> bool:
    if not os.path.exists(path):
        return False
    return needle in _read_text(path).lower()


def _grep_field(path: str, key: str) -> str:
    """Mirrors `grep 'KEY' file | cut -d '"' -f 2` -- os-release's
    KEY="value" format."""
    for line in _read_text(path).splitlines():
        if line.startswith(f"{key}="):
            value = line.split("=", 1)[1].strip()
            return value.strip('"')
    return ""


def _first_int(text: str) -> str:
    match = re.search(r"\d+", text)
    return match.group(0) if match else ""
