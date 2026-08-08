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
| `completions/*.bash` | Optional bash tab-completion for both tools' CLI flags |
| `app/` | Optional web admin UI (FastAPI) for non-technical users — see [app/README.md](app/README.md) |

## Quick start

```bash
git clone https://github.com/cloudlative/openvpn-toolkit.git
cd openvpn-toolkit
sudo bash openvpn-install.sh
```

First run walks you through a normal OpenVPN server install (IP, protocol, port, DNS). Every run after that (once `/etc/openvpn/server/server.conf` exists) drops into a management menu:

```
1) Add a new client
2) List existing clients
3) List revoked clients
4) List MAC addresses for a client
5) Add a MAC address for an existing client
6) Remove a MAC address from an existing client
7) Revoke an existing client
8) Remove OpenVPN
9) Show/print a client's .ovpn config
10) Permanently delete a revoked client's leftover files
11) Restore (reissue a new cert for) a revoked client
12) Exit
```

Adding a client prompts for a name and the device's MAC address (any common format — `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`, `aabbccddeeff`, mixed case — all normalized automatically). The client only needs push-peer-info in their `.ovpn` (already baked in by this installer) for the MAC check to work.

## Non-interactive CLI

Every menu action is also available as a flag, for scripting/automation:

```bash
sudo bash openvpn-install.sh --add NAME MAC     # e.g. --add alice aa:bb:cc:dd:ee:ff
sudo bash openvpn-install.sh --revoke NAME
sudo bash openvpn-install.sh --list             # valid clients + db registration status
sudo bash openvpn-install.sh --list-revoked     # revoked clients, when, stale db entries
sudo bash openvpn-install.sh --macs NAME        # every MAC address registered for one client
sudo bash openvpn-install.sh --add-mac NAME MAC     # register an extra device MAC for an existing client
sudo bash openvpn-install.sh --remove-mac NAME MAC  # remove one MAC registration (client keeps its cert)
sudo bash openvpn-install.sh --show-ovpn NAME       # print an existing client's .ovpn config to stdout
sudo bash openvpn-install.sh --purge-revoked NAME   # permanently delete a revoked client's leftover PKI/.ovpn files
sudo bash openvpn-install.sh --restore NAME MAC     # reissue a brand-new cert under a revoked client's name
sudo bash openvpn-install.sh --check            # cross-check PKI certs vs openvpn_db.txt
sudo bash openvpn-install.sh --lint-db          # validate openvpn_db.txt formatting/health
sudo bash openvpn-install.sh --help
```

`--check` and `--lint-db` exit `0` when clean and `1` when they find a problem, so they're monitoring/CI-friendly.

`--restore` is **not** un-revoking the old certificate — once a cert is on the CRL it stays revoked forever, by design. `--restore` purges the old revoked client's leftover files and issues a brand-new certificate under the same name instead, so the person can connect again, but it's a fresh cryptographic identity, not the old one reactivated.

Add `--json` to `--list`, `--list-revoked`, `--macs`, `--check`, or `--lint-db` to get structured JSON instead of a table — handy for building a frontend/dashboard on top of this toolkit. Argument order doesn't matter (`--list --json` and `--json --list` are equivalent). It's rejected with a clear error on every other command:

```bash
$ sudo bash openvpn-install.sh --list --json
[{"name":"alice","in_db":true}, ...]

$ sudo bash openvpn-install.sh --list-revoked --json
[{"name":"bob","revoked_at":"2026-03-26 19:46:27 UTC","stale_db_entry":false}, ...]

$ sudo bash openvpn-install.sh --macs alice --json
{"name":"alice","count":2,"macs":["aa:bb:cc:dd:ee:ff","11:22:33:44:55:66"]}

$ sudo bash openvpn-install.sh --check --json
{"clean":true,"orphan_pki":[],"orphan_db":[]}

$ sudo bash openvpn-install.sh --lint-db --json
{"clean":true,"entries":18,"trailing_newline_ok":true,"issues":[]}

$ sudo bash openvpn-install.sh --add alice aa:bb:cc:dd:ee:ff --json
--json option is not allowed with this command.
```

## Live status

```bash
python3 vpn-status.py               # who's connected right now
python3 vpn-status.py --all         # every known client: online / offline / revoked, last-seen
python3 vpn-status.py --rejected    # last 20 MAC-mismatch rejections (--rejected N for a different count)
python3 vpn-status.py --json        # any of the above as JSON
```

Neither command needs to be run as root — both escalate internally via `sudo` for the handful of files that require it (the live status log, the PKI index), so a regular sudo-capable user account is enough.

## Shell completion

Bash tab-completion for both tools' flags (and, for `--revoke`, live client names when the PKI index happens to be readable by the completing user):

```bash
source completions/openvpn-install-completion.bash
source completions/vpn-status-completion.bash
```

Add those two lines to `~/.bashrc` to make it permanent, or copy the files into `/etc/bash_completion.d/` for a system-wide install. Only the scripts' own names (`openvpn-install.sh`, `vpn-status.py`) are bound — not bare `sudo`/`bash`/`python3`, which would break tab-completion for every *other* command invoked that way. `sudo openvpn-install.sh <TAB>` still completes correctly on any system with the standard `bash-completion` package installed, since its own `sudo` handling looks up whatever completion is already registered for the command that follows. If you run `vpn-status.py` as `python3 vpn-status.py ...` and want completion for that exact invocation, add a matching shell function/alias named `vpn-status.py` (see the comment in that completion file for the one-liner) — or just invoke it directly as `./vpn-status.py`, which already works since it's executable with a `python3` shebang.

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
