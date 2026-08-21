"""System Configuration checks -- OS/kernel/architecture, installed
packages, filesystem permissions, world-writable scan, and time/timezone.
Every check here reads through the host_root bind mount (see this
package's __init__.py module docstring for why file reads, not
subprocess) -- nothing here shells out.

Host machine resource state (CPU/memory/disk/uptime, already covered by
health.py's get_host_health()) is deliberately NOT duplicated as findings
here -- that's live status, not a configuration posture question. This
module only reports on things that are WRONG or risky about how the
system is configured, reusing health.py's own /proc-reading helpers where
it's the same underlying data (see _os_release below)."""
import os
import re
import stat

from . import Finding

# World-writable scan is intentionally bounded to a short list of
# security-sensitive locations, not a full filesystem crawl -- walking an
# entire host root through a bind mount from inside a container is slow,
# and the vast majority of a real "find / -perm -0002" result on any
# Linux system is noise (deliberately world-writable files under /tmp,
# /var/tmp, browser caches, etc.) that would bury the handful of findings
# that actually matter. These are the locations where a world-writable
# entry is a genuine red flag.
_WORLD_WRITABLE_SCAN_PATHS = ("/etc", "/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system", "/root")
_WORLD_WRITABLE_MAX_DEPTH = 2


def _p(host_root: str, *parts: str) -> str:
    return os.path.join(host_root, *(p.lstrip("/") for p in parts))


def _read(path: str) -> str | None:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _os_release(host_root: str) -> dict[str, str]:
    text = _read(_p(host_root, "/etc/os-release")) or ""
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def _check_os_and_kernel(host_root: str) -> list[Finding]:
    findings = []
    osr = _os_release(host_root)
    kernel = _read(_p(host_root, "/proc/sys/kernel/osrelease"))
    kernel = kernel.strip() if kernel else "unknown"
    pretty = osr.get("PRETTY_NAME", "unknown")
    findings.append(Finding(
        check_id="system.os_kernel_info",
        category="system", severity="info",
        title="Operating system and kernel",
        description=f"Running {pretty}, kernel {kernel}.",
        current_state=f"OS: {pretty}\nKernel: {kernel}",
        evidence="/etc/os-release, /proc/sys/kernel/osrelease",
    ))
    # A handful of long-EOL distro/version markers this project's own
    # installer explicitly rejects (openvpn-install.sh's minimum-version
    # gate) -- flagged again here since a system that WAS supported at
    # install time can silently age past support without anyone noticing.
    eol_id_likes = {"centos": ("7", "8"), "ubuntu": ("14.04", "16.04"), "debian": ("8", "7")}
    dist_id = osr.get("ID", "").lower()
    version_id = osr.get("VERSION_ID", "")
    if dist_id in eol_id_likes and version_id in eol_id_likes[dist_id]:
        findings.append(Finding(
            check_id="system.os_end_of_life",
            category="system", severity="high",
            title="Operating system version is end-of-life",
            description=f"{pretty} no longer receives security updates from its distributor.",
            why_it_matters="An unpatched OS accumulates known, publicly-documented vulnerabilities over time "
                            "with no vendor fix available.",
            current_state=pretty, expected_state="A currently-supported OS release",
            remediation="Plan an OS upgrade or migration to a supported release.",
        ))
    return findings


def _check_reboot_required(host_root: str) -> list[Finding]:
    # Debian/Ubuntu's own marker file, written by unattended-upgrades/apt
    # when a just-installed package (commonly a kernel update) needs a
    # reboot to take effect -- reading this file is the standard way to
    # check this without invoking apt/dpkg.
    marker = _p(host_root, "/var/run/reboot-required")
    if os.path.exists(marker):
        pkgs = _read(_p(host_root, "/var/run/reboot-required.pkgs")) or ""
        return [Finding(
            check_id="system.reboot_required",
            category="system", severity="medium",
            title="System reboot required",
            description="A recently-installed update (commonly a kernel or core library update) requires a "
                         "reboot to take effect. Until then, the running system is not actually using the "
                         "patched code.",
            current_state="Reboot pending" + (f"\nPackages: {pkgs.strip()}" if pkgs.strip() else ""),
            expected_state="No reboot pending",
            remediation="Reboot the server at a planned maintenance window. VPN service will be briefly "
                         "interrupted during the reboot.",
        )]
    return [Finding(
        check_id="system.reboot_required", category="system", severity="passed",
        title="No reboot required", description="No pending-reboot marker was found.",
    )]


def _check_installed_packages(host_root: str) -> list[Finding]:
    # Debian/Ubuntu's dpkg status database -- a plain text file, no dpkg
    # invocation needed. Not portable to RPM-based distros (openvpn-
    # install.sh also supports CentOS/Rocky/AlmaLinux/Fedora, which use
    # /var/lib/rpm instead) -- reported as Informational "could not
    # determine" rather than silently skipped, so an RPM-based install
    # doesn't just show a gap with no explanation.
    dpkg_status = _p(host_root, "/var/lib/dpkg/status")
    text = _read(dpkg_status)
    if text is None:
        return [Finding(
            check_id="system.package_inventory", category="system", severity="info",
            title="Package inventory could not be read",
            description="This check currently only supports Debian/Ubuntu's dpkg package database "
                         "(/var/lib/dpkg/status), which was not found or not readable on this host -- likely an "
                         "RPM-based distribution. Package auditing for RPM-based systems is not implemented yet.",
        )]
    count = len(re.findall(r"^Package: ", text, re.MULTILINE))
    return [Finding(
        check_id="system.package_inventory", category="system", severity="info",
        title="Installed package count",
        description=f"{count} packages installed (dpkg).",
        current_state=str(count),
        evidence="/var/lib/dpkg/status",
    )]


def _check_permissions(host_root: str) -> list[Finding]:
    """Spot-checks a short, security-meaningful list of files/directories
    rather than a general filesystem crawl -- the same "bounded, not
    exhaustive" reasoning as the world-writable scan below."""
    findings = []
    checks = [
        ("/etc/shadow", 0o640, "should not be group/world-readable beyond the shadow group"),
        ("/etc/passwd", 0o644, "should be world-readable but not world-writable"),
        ("/etc/ssh/sshd_config", 0o644, "should not be world-writable"),
        ("/etc/sudoers", 0o440, "should not be group/world-writable"),
    ]
    for rel_path, max_mode, note in checks:
        full = _p(host_root, rel_path)
        try:
            st = os.stat(full)
        except OSError:
            continue  # file doesn't exist on this system -- not itself a finding
        mode = stat.S_IMODE(st.st_mode)
        world_writable = bool(mode & 0o002)
        too_permissive = (mode & ~max_mode) & 0o077  # bits set beyond the max allowed, in group/other
        if world_writable or too_permissive:
            findings.append(Finding(
                check_id=f"system.permissions.{rel_path.strip('/').replace('/', '_')}",
                category="system", severity="high" if world_writable else "medium",
                title=f"{rel_path} has overly permissive file permissions",
                description=f"{note}.",
                current_state=f"{oct(mode)}", expected_state=f"{oct(max_mode)} or stricter",
                evidence=f"stat {rel_path} (via host mount)",
                remediation=f"chmod {oct(max_mode)[2:]} {rel_path}",
            ))
        else:
            findings.append(Finding(
                check_id=f"system.permissions.{rel_path.strip('/').replace('/', '_')}",
                category="system", severity="passed",
                title=f"{rel_path} permissions OK", description=f"Current mode {oct(mode)}.",
            ))
    return findings


def _check_world_writable(host_root: str) -> list[Finding]:
    hits = []
    for rel_dir in _WORLD_WRITABLE_SCAN_PATHS:
        base = _p(host_root, rel_dir)
        if not os.path.isdir(base):
            continue
        base_depth = base.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(base):
            depth = dirpath.rstrip("/").count("/") - base_depth
            if depth >= _WORLD_WRITABLE_MAX_DEPTH:
                dirnames[:] = []  # don't descend further
            for name in list(dirnames) + filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue  # a symlink's own mode is meaningless; its target may be outside the scan anyway
                if stat.S_IMODE(st.st_mode) & 0o002:
                    # Report the path relative to host_root (never expose
                    # the container-side /hostfs prefix to the admin --
                    # it's an internal mount detail, not the real host
                    # path they'd use to fix it).
                    hits.append(os.path.relpath(full, host_root))
        if len(hits) > 50:
            break  # bounded -- this is a red-flag sampler, not an exhaustive report
    if hits:
        return [Finding(
            check_id="system.world_writable_files",
            category="system", severity="high",
            title="World-writable files found in sensitive locations",
            description=f"{len(hits)} world-writable file(s)/director(y/ies) found under "
                         f"{', '.join(_WORLD_WRITABLE_SCAN_PATHS)} (scanned {_WORLD_WRITABLE_MAX_DEPTH} levels deep).",
            why_it_matters="A world-writable file in a system location can be modified by any local user or "
                            "process, potentially escalating privileges or persisting malicious changes.",
            current_state="\n".join(f"/{h}" for h in hits[:20]) + (f"\n... and {len(hits) - 20} more" if len(hits) > 20 else ""),
            expected_state="No world-writable entries in these locations",
            evidence=f"Scanned: {', '.join(_WORLD_WRITABLE_SCAN_PATHS)}",
            remediation="Review each listed path and remove world-write permission (chmod o-w) unless there is "
                         "a specific, understood reason it's needed.",
        )]
    return [Finding(
        check_id="system.world_writable_files", category="system", severity="passed",
        title="No world-writable files found",
        description=f"Scanned {', '.join(_WORLD_WRITABLE_SCAN_PATHS)} ({_WORLD_WRITABLE_MAX_DEPTH} levels deep).",
    )]


def _check_timezone(host_root: str) -> list[Finding]:
    tz = _read(_p(host_root, "/etc/timezone"))
    if tz:
        tz = tz.strip()
    else:
        # Fallback for distros that only symlink /etc/localtime (no
        # /etc/timezone file, e.g. some RPM-based systems).
        try:
            link = os.readlink(_p(host_root, "/etc/localtime"))
            tz = link.rsplit("zoneinfo/", 1)[-1] if "zoneinfo/" in link else None
        except OSError:
            tz = None
    return [Finding(
        check_id="system.timezone", category="system", severity="info",
        title="System timezone",
        description=f"Timezone is set to {tz or 'unknown'}.",
        current_state=tz or "unknown",
    )]


def run(host_root: str) -> list[Finding]:
    findings: list[Finding] = []
    findings += _check_os_and_kernel(host_root)
    findings += _check_reboot_required(host_root)
    findings += _check_installed_packages(host_root)
    findings += _check_permissions(host_root)
    findings += _check_world_writable(host_root)
    findings += _check_timezone(host_root)
    return findings
