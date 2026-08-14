"""Path/config layout shared by every module in this package -- Python
equivalent of the config variables at openvpn-install.sh:101-145 (and their
/etc/openvpn/vpn-tools.conf override mechanism at :147-151). One
OpenVPNPaths instance is threaded through certificate_manager/config_manager/
client_manager/installer rather than each hardcoding these strings, so a
test fixture can point the whole stack at a scratch directory (see
app/tests/services/conftest.py) without touching the real /etc/openvpn.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class OpenVPNPaths:
    openvpn_dir: str = "/etc/openvpn/server"
    easyrsa_dir: str = "/etc/openvpn/server/easy-rsa"
    db_file: str = "/etc/openvpn/server/openvpn_db.txt"
    client_common_file: str = "/etc/openvpn/server/client-common.txt"
    status_log: str = "/var/log/openvpn/openvpn-status.log"
    service_name: str = "openvpn-server@server.service"
    ovpn_output_mode: str = "600"
    ovpn_output_dir: str = "/root"
    ovpn_output_owner: str = "root:root"
    group_name: str = "nogroup"  # "nogroup" (Debian/Ubuntu) or "nobody" (CentOS/Fedora)

    @classmethod
    def from_conf(cls, conf_path: str = "/etc/openvpn/vpn-tools.conf", **overrides: str) -> OpenVPNPaths:
        """Mirrors openvpn-install.sh:147-151 -- optionally overridden by a
        plain KEY=VALUE file, no quoting, one assignment per line. Keys
        match this dataclass's field names uppercased (OPENVPN_DIR,
        EASYRSA_DIR, DB_FILE, CLIENT_COMMON_FILE, STATUS_LOG, SERVICE_NAME,
        OVPN_OUTPUT_MODE, OVPN_OUTPUT_DIR, OVPN_OUTPUT_OWNER)."""
        values: dict[str, str] = {}
        if os.path.isfile(conf_path):
            key_by_field = {f.upper(): f for f in cls.__dataclass_fields__}
            with open(conf_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    field = key_by_field.get(key.strip())
                    if field:
                        values[field] = value.strip()
        values.update(overrides)
        return cls(**values)

    # --- PKI tree (under EASYRSA_DIR) -----------------------------------
    @property
    def pki_dir(self) -> str:
        return f"{self.easyrsa_dir}/pki"

    @property
    def index_txt(self) -> str:
        return f"{self.pki_dir}/index.txt"

    @property
    def ca_crt(self) -> str:
        return f"{self.pki_dir}/ca.crt"

    @property
    def ca_key(self) -> str:
        return f"{self.pki_dir}/private/ca.key"

    @property
    def server_crt(self) -> str:
        return f"{self.pki_dir}/issued/server.crt"

    @property
    def server_key(self) -> str:
        return f"{self.pki_dir}/private/server.key"

    @property
    def pki_crl_pem(self) -> str:
        return f"{self.pki_dir}/crl.pem"

    def issued_crt(self, name: str) -> str:
        return f"{self.pki_dir}/issued/{name}.crt"

    def private_key(self, name: str) -> str:
        return f"{self.pki_dir}/private/{name}.key"

    def req_file(self, name: str) -> str:
        return f"{self.pki_dir}/reqs/{name}.req"

    # --- OPENVPN_DIR (installed/runtime copies + generated config) ------
    @property
    def server_conf(self) -> str:
        return f"{self.openvpn_dir}/server.conf"

    @property
    def installed_ca_crt(self) -> str:
        return f"{self.openvpn_dir}/ca.crt"

    @property
    def installed_ca_key(self) -> str:
        return f"{self.openvpn_dir}/ca.key"

    @property
    def installed_server_crt(self) -> str:
        return f"{self.openvpn_dir}/server.crt"

    @property
    def installed_server_key(self) -> str:
        return f"{self.openvpn_dir}/server.key"

    @property
    def installed_crl_pem(self) -> str:
        return f"{self.openvpn_dir}/crl.pem"

    @property
    def dh_pem(self) -> str:
        return f"{self.openvpn_dir}/dh.pem"

    @property
    def tc_key(self) -> str:
        return f"{self.openvpn_dir}/tc.key"

    def ovpn_output(self, name: str) -> str:
        return f"{self.ovpn_output_dir}/{name}.ovpn"

    # --- host-scripts/ (client-connect/disconnect + per-client policy
    # enforcement -- see host_scripts_manager.py) -------------------------
    # Deployed as siblings of server.conf under OPENVPN_DIR, same directory
    # every other "installed" file above (ca.crt, dh.pem, ...) lives in.
    @property
    def mac_check_script(self) -> str:
        return f"{self.openvpn_dir}/openvpn-mac-addr-check.py"

    @property
    def disconnect_script(self) -> str:
        return f"{self.openvpn_dir}/openvpn-client-disconnect.py"

    @property
    def policy_lib_script(self) -> str:
        return f"{self.openvpn_dir}/policy_lib.py"

    @property
    def conn_log(self) -> str:
        return f"{self.openvpn_dir}/openvpn.log"

    # Matches policy_lib.py's own DEFAULTS -- a "policy/" subdirectory
    # rather than directly in OPENVPN_DIR (root-owned) so the nobody-run
    # connect/disconnect scripts can atomically write-then-rename inside it
    # (needs write permission on the directory itself, not just the file).
    @property
    def policy_dir(self) -> str:
        return f"{self.openvpn_dir}/policy"

    @property
    def client_policy_file(self) -> str:
        return f"{self.policy_dir}/client_policy.json"

    @property
    def client_usage_file(self) -> str:
        return f"{self.policy_dir}/client_usage.json"

    @property
    def quota_enforcer_script(self) -> str:
        """Hard Enforcement's poller (host-scripts/quota_enforcer.py, see
        host_scripts_manager.py) -- deployed as a sibling of the other
        host-scripts/ files, but run as root by its own systemd timer
        (systemd/openvpn-quota-enforcer.{service,timer}), not invoked
        per-connection like mac_check_script/disconnect_script."""
        return f"{self.openvpn_dir}/quota_enforcer.py"

    @property
    def management_socket(self) -> str:
        """OpenVPN's management-interface Unix socket (see
        management_client.py, host_scripts_manager.py's
        render_server_conf_additions) -- created by OpenVPN itself at
        startup while still running as root (before it drops to
        `user nobody`/`group nogroup` for the tunnel), so it ends up
        root-owned by construction, not something this app chmods
        after the fact."""
        return f"{self.openvpn_dir}/mgmt.sock"
