# OpenVPN Toolkit

A small, self-contained OpenVPN road-warrior installer and management toolkit for Ubuntu/Debian/CentOS/Fedora, extending the well-known [Nyr/Angristan-style installer](https://github.com/shahzadmasud/openvpn.git) lineage with:

- **Device MAC-address binding** — every client connection is checked against a registered `name=mac` allowlist (`openvpn_db.txt`) in addition to normal certificate auth, via a `client-connect` script.
- **A non-interactive CLI** alongside the original interactive menu, so clients can be added/revoked/listed from automation, not just a terminal prompt.
- **A live status tool** (`vpn-status.py`) — who's connected right now, all known clients with last-seen, bandwidth, and rejected (MAC-mismatch) connection attempts.
- **A shared config file** (`vpn-tools.conf`) so paths/settings aren't hardcoded per install.

## Contents

| File | Purpose |
|---|---|
| `openvpn-install.sh` | Installer + client management (add/revoke/list/check/lint), interactive menu or CLI flags |
| `vpn-status.py` | Live connection status, all-clients view, bandwidth, rejected-attempt auditing |
| `vpn-tools.conf.example` | Copy to `/etc/openvpn/vpn-tools.conf` to override any default path/setting |

## Quick start

```bash
git clone https://github.com/asifrafiq/openvpn-toolkit.git
cd openvpn-toolkit
sudo bash openvpn-install.sh
```

First run walks you through a normal OpenVPN server install (IP, protocol, port, DNS). Every run after that (once `/etc/openvpn/server/server.conf` exists) drops into a management menu:

```
1) Add a new client
2) List existing clients
3) List revoked clients
4) Revoke an existing client
5) Remove OpenVPN
6) Exit
```

Adding a client prompts for a name and the device's MAC address (any common format — `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`, `aabbccddeeff`, mixed case — all normalized automatically). The client only needs push-peer-info in their `.ovpn` (already baked in by this installer) for the MAC check to work.

## Non-interactive CLI

Every menu action is also available as a flag, for scripting/automation:

```bash
sudo bash openvpn-install.sh --add NAME MAC     # e.g. --add alice aa:bb:cc:dd:ee:ff
sudo bash openvpn-install.sh --revoke NAME
sudo bash openvpn-install.sh --list             # valid clients + db registration status
sudo bash openvpn-install.sh --list-revoked     # revoked clients, when, stale db entries
sudo bash openvpn-install.sh --check            # cross-check PKI certs vs openvpn_db.txt
sudo bash openvpn-install.sh --lint-db          # validate openvpn_db.txt formatting/health
sudo bash openvpn-install.sh --help
```

`--check` and `--lint-db` exit `0` when clean and `1` when they find a problem, so they're monitoring/CI-friendly.

## Live status

```bash
python3 vpn-status.py               # who's connected right now
python3 vpn-status.py --all         # every known client: online / offline / revoked, last-seen
python3 vpn-status.py --rejected    # last 20 MAC-mismatch rejections (--rejected N for a different count)
python3 vpn-status.py --json        # any of the above as JSON
```

Neither command needs to be run as root — both escalate internally via `sudo` for the handful of files that require it (the live status log, the PKI index), so a regular sudo-capable user account is enough.

## Configuration

Copy `vpn-tools.conf.example` to `/etc/openvpn/vpn-tools.conf` and uncomment only what you want to change. Both tools fall back to sensible defaults if the file doesn't exist at all, so a fresh clone works out of the box.

Notably, **where generated `.ovpn` files get delivered is auto-detected**, not hardcoded to any particular distro's default account name: `openvpn-install.sh` uses whoever actually ran `sudo` to invoke it (`$SUDO_USER`), falling back to the first regular human account on the box, then `root`. Set `OVPN_OUTPUT_DIR`/`OVPN_OUTPUT_OWNER` explicitly in the config only if you want delivery to go somewhere else.

## How the MAC-binding check works

`openvpn-install.sh --add` registers each client as a `name=mac` line in `openvpn_db.txt`. A `client-connect` script (`openvpn-mac-addr-check.py`, already wired into `server.conf`) checks the connecting certificate's CN against the device's MAC address (via `IV_HWADDR`, which requires `push-peer-info` — already set in every generated `.ovpn`) on every connection attempt, and rejects anything that doesn't match. This adds a device-binding layer on top of normal certificate authentication: a stolen/copied `.ovpn` file alone isn't enough to connect from an unregistered device.

## Requirements

- Ubuntu 18.04+, Debian 9+, AlmaLinux/Rocky/CentOS 7+, or Fedora
- Root (or passwordless sudo) to run `openvpn-install.sh`
- Python 3 for `vpn-status.py`

## License

MIT — see [LICENSE](LICENSE).
