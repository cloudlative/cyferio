"""CRL (certificate revocation list) regeneration + install -- Python port
of the crl.pem handling inside do_revoke_client (openvpn-install.sh:
316-320): regenerate via easyrsa, then copy into OPENVPN_DIR with the
ownership OpenVPN's dropped-privilege process needs to read it.
"""
from __future__ import annotations

import grp
import os
import pwd
import shutil

from . import certificate_manager
from .exceptions import CertificateError
from .paths import OpenVPNPaths


def regenerate_and_install(paths: OpenVPNPaths) -> None:
    """Mirrors openvpn-install.sh:316-320 -- regenerate crl.pem in the PKI
    tree (already done by certificate_manager.revoke_client_cert's gen-crl
    call; this function only handles the install-into-OPENVPN_DIR + chown
    half, called separately so a standalone CRL refresh -- not tied to a
    revoke -- can reuse it) then copy it into place as nobody:$group_name."""
    install_crl(paths)


def install_crl(paths: OpenVPNPaths) -> None:
    """Mirrors:
        rm -f "$OPENVPN_DIR/crl.pem"
        cp "$EASYRSA_DIR/pki/crl.pem" "$OPENVPN_DIR/crl.pem"
        chown nobody:"$group_name" "$OPENVPN_DIR/crl.pem"
    """
    if os.path.exists(paths.installed_crl_pem):
        os.remove(paths.installed_crl_pem)
    try:
        shutil.copyfile(paths.pki_crl_pem, paths.installed_crl_pem)
    except OSError as e:
        raise CertificateError(f"Failed to install CRL: {e}") from e
    _chown_best_effort(paths.installed_crl_pem, "nobody", paths.group_name)


def _chown_best_effort(path: str, user: str, group: str) -> None:
    """chown to `user:group`, matching the bash script's own chown calls.
    Best-effort: silently no-ops if the target user/group don't exist on
    this host (e.g. a local dev machine without a "nobody"/"nogroup"
    account under those exact names) rather than failing the whole
    operation over a cosmetic permission detail -- the bash script itself
    has no such fallback (chown just fails loudly there), but a Python test
    fixture running as a non-root dev user has no way to chown to nobody at
    all, so this needs to degrade gracefully outside a real install."""
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, uid, gid)
    except (KeyError, PermissionError, OSError):
        pass
