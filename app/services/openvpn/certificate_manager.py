"""easyrsa-backed PKI/certificate lifecycle -- Python port of the easyrsa
invocations scattered throughout openvpn-install.sh (PKI download/init at
:1201-1212, per-client build-client-full at :282, revoke+gen-crl at :316).

Every function here shells out to the real `easyrsa`/`openssl` binaries via
process_manager -- this module does not reimplement any cryptography, only
orchestrates the same commands the bash script runs, which is also why the
Phase 1 parity tests validate "did Python invoke easyrsa correctly" rather
than diffing byte-for-byte cert output (see the plan's §5b).
"""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass

from ..system.process_manager import CommandError, run_checked
from .exceptions import CertificateError
from .paths import OpenVPNPaths

EASYRSA_VERSION = "3.1.7"
EASYRSA_URL = f"https://github.com/OpenVPN/easy-rsa/releases/download/v{EASYRSA_VERSION}/EasyRSA-{EASYRSA_VERSION}.tgz"
CERT_DAYS = "3650"  # matches every --days=3650 in the bash script

# Static ffdhe2048 DH params, byte-identical to openvpn-install.sh:1222-1229
# -- the bash script never regenerates these per install, so neither do we.
FFDHE2048_PEM = """-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
"""


@dataclass(frozen=True)
class EasyRSA:
    """Handle to an installed easyrsa binary within a given EASYRSA_DIR."""

    easyrsa_dir: str

    @property
    def binary(self) -> str:
        return os.path.join(self.easyrsa_dir, "easyrsa")

    def _run(self, *args: str, timeout: int = 60) -> None:
        try:
            run_checked(
                [self.binary, "--batch", *args],
                cwd=self.easyrsa_dir,
                timeout=timeout,
                error_prefix=f"easyrsa {' '.join(args)} failed",
            )
        except CommandError as e:
            raise CertificateError(e.message, easyrsa_args=args) from e


def download_and_extract_easyrsa(easyrsa_dir: str) -> None:
    """Mirrors openvpn-install.sh:1201-1205 -- downloads the pinned EasyRSA
    release tarball and extracts it into easyrsa_dir with the top-level
    directory stripped (tar's --strip-components 1)."""
    os.makedirs(easyrsa_dir, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as tmp:
            tmp_path = tmp.name
            with urllib.request.urlopen(EASYRSA_URL, timeout=30) as resp:
                shutil.copyfileobj(resp, tmp)
        with tarfile.open(tmp_path, "r:gz") as tar:
            _extract_strip_components(tar, easyrsa_dir, strip=1)
    except Exception as e:
        raise CertificateError(f"Failed to download/extract EasyRSA {EASYRSA_VERSION}: {e}") from e
    finally:
        if "tmp_path" in locals() and os.path.exists(tmp_path):
            os.remove(tmp_path)


def _extract_strip_components(tar: tarfile.TarFile, dest: str, *, strip: int) -> None:
    for member in tar.getmembers():
        parts = member.name.split("/")[strip:]
        if not parts:
            continue
        member.name = "/".join(parts)
        tar.extract(member, dest, filter="data")


def pki_init(paths: OpenVPNPaths) -> None:
    """Mirrors `./easyrsa --batch init-pki` (openvpn-install.sh:1208)."""
    EasyRSA(paths.easyrsa_dir)._run("init-pki")


def build_ca(paths: OpenVPNPaths) -> None:
    """Mirrors `./easyrsa --batch build-ca nopass` (:1209)."""
    EasyRSA(paths.easyrsa_dir)._run("build-ca", "nopass")


def build_server_cert(paths: OpenVPNPaths, common_name: str = "server") -> None:
    """Mirrors `./easyrsa --batch --days=3650 build-server-full server nopass` (:1210)."""
    EasyRSA(paths.easyrsa_dir)._run(f"--days={CERT_DAYS}", "build-server-full", common_name, "nopass")


def build_client_cert(paths: OpenVPNPaths, name: str) -> None:
    """Mirrors `./easyrsa --batch --days=3650 build-client-full "$client" nopass`
    (:1211, and do_add_client's :282). Caller (client_manager.add_client) is
    responsible for the ClientAlreadyExistsError pre-check -- this function
    just issues the cert."""
    EasyRSA(paths.easyrsa_dir)._run(f"--days={CERT_DAYS}", "build-client-full", name, "nopass")


def revoke_client_cert(paths: OpenVPNPaths, name: str) -> None:
    """Mirrors `./easyrsa --batch revoke "$client" && ./easyrsa --batch
    --days=3650 gen-crl` (do_revoke_client, :316). Caller (client_manager.
    revoke_client) handles the "no such client" pre-check and the
    crl.pem install-into-OPENVPN_DIR step (crl_manager.install_crl)."""
    rsa = EasyRSA(paths.easyrsa_dir)
    rsa._run("revoke", name)
    rsa._run(f"--days={CERT_DAYS}", "gen-crl")


def gen_crl(paths: OpenVPNPaths) -> None:
    """Standalone CRL (re)generation, used by installer.py's initial install
    (:1212) and available for crl_manager to call directly without a
    preceding revoke."""
    EasyRSA(paths.easyrsa_dir)._run(f"--days={CERT_DAYS}", "gen-crl")


def install_pki_files(paths: OpenVPNPaths) -> None:
    """Mirrors `cp pki/ca.crt pki/private/ca.key pki/issued/server.crt
    pki/private/server.key pki/crl.pem "$OPENVPN_DIR"` (:1214) -- copies the
    freshly-built CA/server/CRL material from the PKI tree into the runtime
    OPENVPN_DIR the server.conf template (config_manager.py) references by
    relative filename."""
    os.makedirs(paths.openvpn_dir, exist_ok=True)
    for src, dst in (
        (paths.ca_crt, paths.installed_ca_crt),
        (paths.ca_key, paths.installed_ca_key),
        (paths.server_crt, paths.installed_server_crt),
        (paths.server_key, paths.installed_server_key),
        (paths.pki_crl_pem, paths.installed_crl_pem),
    ):
        try:
            shutil.copyfile(src, dst)
        except OSError as e:
            raise CertificateError(f"Failed to install PKI file {src} -> {dst}: {e}") from e


def write_dh_params(paths: OpenVPNPaths) -> None:
    """Mirrors :1222-1229 -- writes the static ffdhe2048 PEM, not a freshly
    generated one."""
    with open(paths.dh_pem, "w", encoding="utf-8") as f:
        f.write(FFDHE2048_PEM)


def generate_tls_crypt_key(paths: OpenVPNPaths) -> None:
    """Mirrors `openvpn --genkey --secret "$OPENVPN_DIR/tc.key"` (:1220)."""
    os.makedirs(paths.openvpn_dir, exist_ok=True)
    try:
        # Matches the bash script's exact invocation (:1220) -- deliberately
        # the pre-2.5 `--genkey --secret FILE` form, not the newer
        # `--genkey secret FILE`, since parity with what openvpn-install.sh
        # actually runs is the point, not "most modern" syntax.
        run_checked(
            ["openvpn", "--genkey", "--secret", paths.tc_key],
            timeout=15,
            error_prefix="Failed to generate tls-crypt key",
        )
    except CommandError as e:
        raise CertificateError(e.message) from e
