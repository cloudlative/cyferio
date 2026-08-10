"""Structured exception hierarchy for the Python OpenVPN service layer --
the successor to app/vpnadmin/cli_wrapper.py's single ScriptError, now that
callers need to distinguish *why* an operation failed (already exists vs.
not found vs. a firewall/systemd problem) instead of pattern-matching a
stderr string.

Every exception carries:
  - `.detail`: a human-readable message, safe to surface directly in an API
    response (mirrors the bash script's own stderr messages where one
    exists -- see each module for the specific line being ported).
  - `.context`: a dict of structured fields (e.g. {"client": "alice"}) for
    logging/audit, not meant to be user-facing on its own.
"""
from __future__ import annotations


class OpenVPNError(Exception):
    """Base for every error this service layer raises."""

    def __init__(self, detail: str, **context: object) -> None:
        super().__init__(detail)
        self.detail = detail
        self.context = context

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"{type(self).__name__}({self.detail!r}, context={self.context!r})"


class ValidationError(OpenVPNError):
    """A caller-supplied value (client name, MAC, port, protocol, DNS
    choice, ...) failed the same whitelist validation openvpn-install.sh
    performs -- see validator.py."""


class InstallError(OpenVPNError):
    """Something went wrong during installer.install()/uninstall(). Raised
    after any partially-completed steps have already been rolled back (see
    installer.py's docstring) -- callers never need to clean up themselves."""


class AlreadyInstalledError(InstallError):
    """installer.install() was called but $OPENVPN_DIR/server.conf already
    exists. Treated as an idempotent no-op by callers, not a failure --
    mirrors the bash script's own install-vs-menu gate (server.conf's
    existence is the sole install marker there too)."""


class NotInstalledError(OpenVPNError):
    """An operation that requires an existing install (client add/revoke/
    etc.) was attempted before one exists -- mirrors the CLI dispatch guard
    at openvpn-install.sh:961-967."""


class CertificateError(OpenVPNError):
    """An easyrsa/openssl operation failed (PKI init, CA/server/client cert
    issuance, CRL generation)."""


class ClientAlreadyExistsError(OpenVPNError):
    """add_client() called for a name that already has an issued cert --
    mirrors openvpn-install.sh:263-266."""


class ClientNotFoundError(OpenVPNError):
    """An operation targeted a client name with no issued cert (or, for
    purge/restore, no *revoked* cert) -- mirrors the various "no such
    client" checks throughout openvpn-install.sh's do_* functions."""


class ClientNotRevokedError(OpenVPNError):
    """purge_revoked()/restore_client() called for a name that isn't
    actually on the CRL -- mirrors openvpn-install.sh:373-375, :434-436."""


class MacAlreadyRegisteredError(OpenVPNError):
    """add_mac() called with a MAC that's already registered -- either to
    this same client (exact-match case, :536-538) or to a different one
    (cross-client conflict, :540-544)."""


class MacNotFoundError(OpenVPNError):
    """remove_mac() called for a name=mac pair that has no matching entry
    in DB_FILE -- mirrors openvpn-install.sh:570-572."""


class FirewallConfigError(OpenVPNError):
    """sysctl/iptables configuration failed."""


class ServiceManagementError(OpenVPNError):
    """A systemctl operation (enable/disable/start/stop) failed."""


class UnsupportedOSError(OpenVPNError):
    """The host OS/version isn't one openvpn-install.sh supports -- mirrors
    the checks at openvpn-install.sh:21-77."""


class HostExecutorError(OpenVPNError):
    """Raised by services/system/host_executor.py for transport-level
    failures (SSH connection refused/timed out, malformed/missing JSON
    output) -- distinct from an OpenVPNError the remote openvpn_admin.py
    invocation itself raised and reported structurally (see
    host_executor.run_host_command, which re-raises those as their original
    exception type via _EXCEPTION_REGISTRY below)."""


# name -> class, used by host_executor.run_host_command to reconstruct the
# same exception type the remote `openvpn_admin.py` process raised (it
# reports {"error": {"type": "ClientAlreadyExistsError", ...}} as JSON --
# see app/cli/openvpn_admin.py's _err()) rather than flattening every
# failure into a generic HostExecutorError.
_EXCEPTION_REGISTRY: dict[str, type[OpenVPNError]] = {
    cls.__name__: cls
    for cls in (
        ValidationError, InstallError, AlreadyInstalledError, NotInstalledError,
        CertificateError, ClientAlreadyExistsError, ClientNotFoundError,
        ClientNotRevokedError, MacAlreadyRegisteredError, MacNotFoundError,
        FirewallConfigError, ServiceManagementError, UnsupportedOSError,
    )
}


def from_remote_error(error_type: str, detail: str, context: dict) -> OpenVPNError:
    """Reconstructs the appropriate OpenVPNError subclass from a remote
    openvpn_admin.py JSON error payload; falls back to the generic
    OpenVPNError for an unrecognized type (e.g. a Python built-in exception
    the CLI's catch-all handler reported, see openvpn_admin.py's main())."""
    cls = _EXCEPTION_REGISTRY.get(error_type, OpenVPNError)
    return cls(detail, **context)
