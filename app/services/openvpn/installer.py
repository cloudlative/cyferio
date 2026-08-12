"""Orchestrates a fresh install / uninstall -- Python port of
openvpn-install.sh's interactive install sequence (:1064-1411) and the
uninstall branch (menu option 8, :1542-1592).

Unlike the bash script, install() tracks which steps actually completed and
unwinds them in reverse on any failure (see _rollback below) -- a failed
install here should never leave a half-configured host, which the bash
script has no protection against at all. This is the "genuine improvement"
called out in the Phase 1 plan's §4.
"""
from __future__ import annotations

import logging
import os
import shutil

from ..system import package_manager
from . import certificate_manager, config_manager, firewall_manager, host_scripts_manager, service_manager
from .config_manager import InstallOptions
from .exceptions import AlreadyInstalledError, InstallError, OpenVPNError
from .paths import OpenVPNPaths
from .validator import sanitize_client_name

logger = logging.getLogger(__name__)

DEFAULT_PACKAGES = ["openvpn", "openssl", "ca-certificates"]

# Ordered so _rollback() can unwind in reverse; see install()'s try block for
# where each is appended once its step actually completes.
_STEP_LIMITNPROC = "limitnproc_dropin"
_STEP_PKI = "pki"  # covers init-pki through gen-crl + install_pki_files -- all live
# under EASYRSA_DIR/OPENVPN_DIR's PKI-derived files, unwound together (see _rollback)
_STEP_TC_KEY = "tc_key"
_STEP_DH = "dh"
_STEP_SERVER_CONF = "server_conf"
_STEP_HOST_SCRIPTS = "host_scripts"
_STEP_IP_FORWARD = "ip_forward"
_STEP_FIREWALL = "firewall"
_STEP_CLIENT_COMMON = "client_common"
_STEP_SERVICE = "service"


class InstallResult:
    def __init__(self, client_name: str | None, ovpn_path: str | None, port: int, protocol: str) -> None:
        self.client_name = client_name
        self.ovpn_path = ovpn_path
        self.port = port
        self.protocol = protocol

    def __repr__(self) -> str:
        return f"InstallResult(client_name={self.client_name!r}, port={self.port}, protocol={self.protocol!r})"


def install(
    paths: OpenVPNPaths,
    opts: InstallOptions,
    first_client_name: str | None = "client",
    *,
    install_packages: bool = True,
) -> InstallResult:
    """Mirrors :1064-1411. Raises AlreadyInstalledError (a no-op signal, not
    a failure) if paths.server_conf already exists -- this is the sole
    install-marker check the bash script itself uses (:1064, :1412).

    `first_client_name=None` (or an empty string) skips creating a first
    client entirely -- unlike the bash script (which always prompts for and
    creates one, defaulting to "client" on a blank answer), a first client
    is optional here: the server/firewall/systemd steps below never read or
    depend on `client`/`InstallResult.client_name`/`.ovpn_path` being set,
    so skipping it just means InstallResult.client_name/ovpn_path come back
    None and no cert/.ovpn is generated. A client can always be added
    afterward through the ordinary add-client path, identical to any other
    client -- there is nothing structurally special about "the first one"
    once install() returns.

    `install_packages=False` skips the OS package-manager step (used by the
    parity test harness, which runs against a scratch PKI dir without
    wanting to apt-get install a second OpenVPN system package)."""
    if os.path.exists(paths.server_conf):
        raise AlreadyInstalledError(
            f"{paths.server_conf} already exists -- OpenVPN is already installed.",
        )

    completed: list[str] = []
    client = sanitize_client_name(first_client_name) if first_client_name else None
    try:
        if install_packages:
            os_info = package_manager.detect_os()
            if service_manager.is_container():
                service_manager.write_limitnproc_dropin()
                completed.append(_STEP_LIMITNPROC)
            package_manager.install_packages(os_info, DEFAULT_PACKAGES)

        certificate_manager.download_and_extract_easyrsa(paths.easyrsa_dir)
        certificate_manager.pki_init(paths)
        certificate_manager.build_ca(paths)
        certificate_manager.build_server_cert(paths)
        if client:
            certificate_manager.build_client_cert(paths, client)
        certificate_manager.gen_crl(paths)
        certificate_manager.install_pki_files(paths)
        completed.append(_STEP_PKI)

        certificate_manager.generate_tls_crypt_key(paths)
        completed.append(_STEP_TC_KEY)
        certificate_manager.write_dh_params(paths)
        completed.append(_STEP_DH)

        with open(paths.server_conf, "w", encoding="utf-8") as f:
            f.write(config_manager.render_server_conf(paths, opts))
        completed.append(_STEP_SERVER_CONF)

        # Installs the MAC-binding/per-client-restriction enforcement layer
        # (host-scripts/) and appends its server.conf hook block -- BEFORE
        # the service's first start below, so a fresh install is
        # fully-enforcing from boot with no separate restart/maintenance
        # window needed (unlike wiring this onto an ALREADY-running server,
        # see host_scripts_manager's own docstring and the
        # `install-host-scripts` CLI action for that case). Previously this
        # entire step was a manual, README-documented process, entirely
        # outside this installer.
        host_scripts_manager.install_host_scripts(paths)
        completed.append(_STEP_HOST_SCRIPTS)

        firewall_manager.enable_ip_forward(ipv6=bool(opts.ip6))
        completed.append(_STEP_IP_FORWARD)
        firewall_manager.install_iptables_firewall(
            ip=opts.ip, port=opts.port, protocol=opts.protocol, ip6=opts.ip6,
        )
        completed.append(_STEP_FIREWALL)

        with open(paths.client_common_file, "w", encoding="utf-8") as f:
            f.write(config_manager.render_client_common(opts))
        completed.append(_STEP_CLIENT_COMMON)

        service_manager.daemon_reload()
        service_manager.enable_and_start(paths.service_name)
        completed.append(_STEP_SERVICE)

        # Mirrors :1406 -- the first client's .ovpn is (re)generated after
        # the service starts. Note the bash script does NOT register this
        # first client in DB_FILE here (unlike do_add_client) -- ported
        # faithfully: the first client needs a separate add_mac/restore
        # call before it can actually connect through the MAC check, same
        # gap that exists in the bash original. Skipped entirely when no
        # first client was requested (client is None) -- see this
        # function's docstring.
        ovpn_path = None
        if client:
            ovpn_content = config_manager.generate_ovpn(paths, client)
            os.makedirs(paths.ovpn_output_dir, exist_ok=True)
            ovpn_path = paths.ovpn_output(client)
            with open(ovpn_path, "w", encoding="utf-8") as f:
                f.write(ovpn_content)
            os.chmod(ovpn_path, int(paths.ovpn_output_mode, 8))

        return InstallResult(client_name=client, ovpn_path=ovpn_path, port=opts.port, protocol=opts.protocol)
    except Exception as e:
        _rollback(paths, completed)
        if isinstance(e, OpenVPNError):
            raise
        raise InstallError(f"Install failed: {e}") from e


def _rollback(paths: OpenVPNPaths, completed: list[str]) -> None:
    """Unwinds `completed` steps in reverse. Best-effort: a rollback failure
    is logged, not raised (the original exception is what the caller should
    see), but every step is still attempted so a partial rollback doesn't
    stop the rest."""
    for step in reversed(completed):
        try:
            if step == _STEP_SERVICE:
                service_manager.disable_and_stop(paths.service_name)
            elif step == _STEP_CLIENT_COMMON:
                _rm(paths.client_common_file)
            elif step == _STEP_FIREWALL:
                firewall_manager.remove_iptables_firewall()
            elif step == _STEP_IP_FORWARD:
                firewall_manager.disable_ip_forward()
            elif step == _STEP_HOST_SCRIPTS:
                # Best-effort teardown of what install_host_scripts() added
                # -- server.conf itself is removed wholesale by the
                # _STEP_SERVER_CONF branch below (which runs AFTER this one
                # in reverse order, i.e. next), so there's nothing to undo
                # there; just the extra files this step created.
                for p in (paths.mac_check_script, paths.disconnect_script, paths.policy_lib_script):
                    _rm(p)
                for p in (paths.client_policy_file, paths.client_usage_file,
                          f"{paths.client_policy_file}.lock", f"{paths.client_usage_file}.lock"):
                    _rm(p)
            elif step == _STEP_SERVER_CONF:
                _rm(paths.server_conf)
            elif step == _STEP_DH:
                _rm(paths.dh_pem)
            elif step == _STEP_TC_KEY:
                _rm(paths.tc_key)
            elif step == _STEP_PKI:
                shutil.rmtree(paths.easyrsa_dir, ignore_errors=True)
                for p in (paths.installed_ca_crt, paths.installed_ca_key,
                          paths.installed_server_crt, paths.installed_server_key,
                          paths.installed_crl_pem):
                    _rm(p)
            elif step == _STEP_LIMITNPROC:
                service_manager.remove_limitnproc_dropin()
        except Exception:
            logger.exception("rollback step %r failed -- continuing with remaining steps", step)


def _rm(path: str) -> None:
    if os.path.exists(path):
        os.remove(path)


def uninstall(paths: OpenVPNPaths, *, purge_packages: bool = True) -> None:
    """Mirrors the uninstall branch (menu option 8, :1542-1592). Unlike
    install(), this has no rollback -- it's meant to be a clean teardown,
    and re-running it is already idempotent (every step no-ops if its
    target doesn't exist)."""
    if service_manager.is_active(paths.service_name):
        service_manager.disable_and_stop(paths.service_name)
    else:
        # Still attempt disable in case the unit exists but isn't active
        # (e.g. a previous partial uninstall) -- matches bash's
        # unconditional `systemctl disable --now` at :1575.
        try:
            service_manager.disable_and_stop(paths.service_name)
        except OpenVPNError:
            pass

    firewall_manager.remove_iptables_firewall()
    firewall_manager.disable_ip_forward()
    service_manager.remove_limitnproc_dropin()

    if os.path.exists(paths.openvpn_dir):
        shutil.rmtree(paths.openvpn_dir, ignore_errors=True)

    if purge_packages:
        try:
            os_info = package_manager.detect_os()
            _purge_packages(os_info)
        except Exception:
            logger.exception("package purge failed during uninstall -- continuing")


def _purge_packages(os_info: package_manager.OSInfo) -> None:
    from ..system.process_manager import run

    if os_info.os in ("debian", "ubuntu"):
        run(["apt-get", "remove", "--purge", "-y", "openvpn"], timeout=120)
    elif os_info.os == "centos":
        run(["yum", "remove", "-y", "openvpn"], timeout=120)
    elif os_info.os == "fedora":
        run(["dnf", "remove", "-y", "openvpn"], timeout=120)
