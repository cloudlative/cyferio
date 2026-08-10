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
sudo bash openvpn-install.sh --add-user NAME MAC     # e.g. --add-user alice aa:bb:cc:dd:ee:ff
sudo bash openvpn-install.sh --revoke-user NAME
sudo bash openvpn-install.sh --list-users             # valid clients + db registration status
sudo bash openvpn-install.sh --list-revoked-users     # revoked clients, when, stale db entries
sudo bash openvpn-install.sh --macs NAME             # every MAC address registered for one client
sudo bash openvpn-install.sh --add-mac NAME MAC      # register an extra device MAC for an existing client
sudo bash openvpn-install.sh --remove-mac NAME MAC   # remove one MAC registration (client keeps its cert)
sudo bash openvpn-install.sh --show-ovpn NAME        # print an existing client's .ovpn config to stdout
sudo bash openvpn-install.sh --purge-revoked NAME    # permanently delete a revoked client's leftover PKI/.ovpn files
sudo bash openvpn-install.sh --restore NAME MAC      # reissue a brand-new cert under a revoked client's name
sudo bash openvpn-install.sh --check-certs           # cross-check PKI certs vs openvpn_db.txt
sudo bash openvpn-install.sh --lint-mac-db           # validate openvpn_db.txt formatting/health
sudo bash openvpn-install.sh --help
```

`--check-certs` and `--lint-mac-db` exit `0` when clean and `1` when they find a problem, so they're monitoring/CI-friendly.

`--restore` is **not** un-revoking the old certificate — once a cert is on the CRL it stays revoked forever, by design. `--restore` purges the old revoked client's leftover files and issues a brand-new certificate under the same name instead, so the person can connect again, but it's a fresh cryptographic identity, not the old one reactivated.

Add `--json` to `--list-users`, `--list-revoked-users`, `--macs`, `--check-certs`, or `--lint-mac-db` to get structured JSON instead of a table — handy for building a frontend/dashboard on top of this toolkit. Argument order doesn't matter (`--list-users --json` and `--json --list-users` are equivalent). It's rejected with a clear error on every other command:

```bash
$ sudo bash openvpn-install.sh --list-users --json
[{"name":"alice","in_db":true}, ...]

$ sudo bash openvpn-install.sh --list-revoked-users --json
[{"name":"bob","revoked_at":"2026-03-26 19:46:27 UTC","stale_db_entry":false}, ...]

$ sudo bash openvpn-install.sh --macs alice --json
{"name":"alice","count":2,"macs":["aa:bb:cc:dd:ee:ff","11:22:33:44:55:66"]}

$ sudo bash openvpn-install.sh --check-certs --json
{"clean":true,"orphan_pki":[],"orphan_db":[]}

$ sudo bash openvpn-install.sh --lint-mac-db --json
{"clean":true,"entries":18,"trailing_newline_ok":true,"issues":[]}

$ sudo bash openvpn-install.sh --add-user alice aa:bb:cc:dd:ee:ff --json
--json option is not allowed with this command.
```

## Live status

```bash
python3 vpn-status.py                        # who's connected right now
python3 vpn-status.py --all-clients          # every known client: online / offline / revoked, last-seen
python3 vpn-status.py --rejected-connections # last 20 MAC-mismatch rejections (--rejected-connections N for a different count)
python3 vpn-status.py --json                 # any of the above as JSON
```

Neither command needs to be run as root — both escalate internally via `sudo` for the handful of files that require it (the live status log, the PKI index), so a regular sudo-capable user account is enough.

## Shell completion

Bash tab-completion for both tools' flags (and, for `--revoke-user`, live client names when the PKI index happens to be readable by the completing user):

```bash
source completions/openvpn-install-completion.bash
source completions/vpn-status-completion.bash
```

Add those two lines to `~/.bashrc` to make it permanent, or copy the files into `/etc/bash_completion.d/` for a system-wide install. Only the scripts' own names (`openvpn-install.sh`, `vpn-status.py`) are bound — not bare `sudo`/`bash`/`python3`, which would break tab-completion for every *other* command invoked that way. `sudo openvpn-install.sh <TAB>` still completes correctly on any system with the standard `bash-completion` package installed, since its own `sudo` handling looks up whatever completion is already registered for the command that follows. If you run `vpn-status.py` as `python3 vpn-status.py ...` and want completion for that exact invocation, add a matching shell function/alias named `vpn-status.py` (see the comment in that completion file for the one-liner) — or just invoke it directly as `./vpn-status.py`, which already works since it's executable with a `python3` shebang.

## Configuration

Copy `vpn-tools.conf.example` to `/etc/openvpn/vpn-tools.conf` and uncomment only what you want to change. Both tools fall back to sensible defaults if the file doesn't exist at all, so a fresh clone works out of the box.

Notably, **where generated `.ovpn` files get delivered is auto-detected**, not hardcoded to any particular distro's default account name: `openvpn-install.sh` uses whoever actually ran `sudo` to invoke it (`$SUDO_USER`), falling back to the first regular human account on the box, then `root`. Set `OVPN_OUTPUT_DIR`/`OVPN_OUTPUT_OWNER` explicitly in the config only if you want delivery to go somewhere else.

## How the MAC-binding check works

`openvpn-install.sh --add-user` registers each client as a `name=mac` line in `openvpn_db.txt`. A `client-connect` script (`openvpn-mac-addr-check.py`, already wired into `server.conf`) checks the connecting certificate's CN against the device's MAC address (via `IV_HWADDR`, which requires `push-peer-info` — already set in every generated `.ovpn`) on every connection attempt, and rejects anything that doesn't match. This adds a device-binding layer on top of normal certificate authentication: a stolen/copied `.ovpn` file alone isn't enough to connect from an unregistered device.

## Per-client restrictions (country / OS / bandwidth quota)

On top of the MAC-binding check above, each client can optionally be restricted by:

- **Country** — a per-client dropdown of ISO 3166-1 countries (or "Unrestricted"); each client can be restricted to a *different* country independently, verified via GeoIP against the connecting IP.
- **Allowed device OS** — a subset of `windows` / `linux` / `mac` (matched against OpenVPN's own `IV_PLAT`). **Leaving this empty means unrestricted (any OS allowed) — it does NOT mean "block everything."**
- **Weekly bandwidth quota** — a soft cutoff in GB, checked only at connection time. A session that goes over quota mid-connection is **not** killed; it's simply not allowed to *reconnect* once the week's quota is used up. Resets every Monday 00:00 server-local time.

All three are entirely optional per client, and orthogonal to the MAC-binding check (which always applies).

### How it's enforced

Enforcement happens **on the OpenVPN host itself**, in two scripts under `host-scripts/` in this repo (installed to `/etc/openvpn/server/`, alongside — not replacing the concept of — `openvpn-mac-addr-check.py`, which this repo's copy *is* that script, now extended):

| File (deploy to `/etc/openvpn/server/`) | server.conf directive |
|---|---|
| `host-scripts/openvpn-mac-addr-check.py` | `client-connect /etc/openvpn/server/openvpn-mac-addr-check.py` (already required) |
| `host-scripts/openvpn-client-disconnect.py` | `client-disconnect /etc/openvpn/server/openvpn-client-disconnect.py` (new) |
| `host-scripts/policy_lib.py` | (imported by both of the above — deploy as a sibling file, no server.conf entry needed) |

Both scripts need `chown nobody:nogroup` + `chmod +x`, same as the original `openvpn-mac-addr-check.py`. After adding the `client-disconnect` line to `server.conf`, restart the OpenVPN server service (**this drops all currently-connected clients** — pick a maintenance window).

**Before that restart**, create the `policy/` subdirectory the two JSON files below live in, owned by `nobody`:

```bash
mkdir -p /etc/openvpn/server/policy
chown nobody:nogroup /etc/openvpn/server/policy
chmod 0770 /etc/openvpn/server/policy
echo '{}' > /etc/openvpn/server/policy/client_policy.json
echo '{}' > /etc/openvpn/server/policy/client_usage.json
chown nobody:nogroup /etc/openvpn/server/policy/client_policy.json /etc/openvpn/server/policy/client_usage.json
chmod 664 /etc/openvpn/server/policy/client_policy.json /etc/openvpn/server/policy/client_usage.json
```

This lives in its own subdirectory rather than directly in `/etc/openvpn/server/` (which is root-owned) because the connect/disconnect scripts run as `nobody` and need to atomically write-then-rename `client_usage.json` — which requires *write permission on the containing directory itself*, not just the file; owning the file alone isn't enough. `policy_lib.py` also makes a best-effort attempt to create/chown this directory itself if it's missing and the caller happens to be running as root (the app, or `openvpn-install.sh`/`client_policy_cli.py` via sudo) — but do the above explicitly rather than relying on that fallback, same reasoning as the original installer's own setup steps `touch`-ing + `chown`-ing `openvpn_db.txt`/`openvpn.log` up front. Skipping this doesn't break the MAC-binding check or take down the VPN — a policy-file read failure fails *open* (treated as unrestricted, loudly logged) rather than rejecting connections — but restrictions and usage tracking silently won't work until it's done.

The connect script checks, in order, once identity is established by the MAC check: OS → country → bandwidth quota. Each rejection is logged to `openvpn.log` with a machine-readable `reason` (`mac_mismatch`, `os_not_allowed`, `country_not_allowed`, `country_lookup_failed`, `bandwidth_exceeded`), visible via `vpn-status.py --rejected-connections` and the web app's Diagnostics page.

### Storage

Two new JSON files under `/etc/openvpn/server/policy/` (paths configurable via `vpn-tools.conf`'s `CLIENT_POLICY_FILE`/`CLIENT_USAGE_FILE`):

- **`client_policy.json`** — admin-configured restrictions, keyed by client name:
  ```json
  {
    "alice": {"country": "PK", "allowed_os": ["windows", "linux"], "bandwidth_weekly_gb": 5},
    "bob": {"bandwidth_weekly_gb": 10}
  }
  ```
  A client absent from this file, or present with an empty object, is fully unrestricted (only the MAC check applies). Written by the web app (`app/vpnadmin/policy_store.py`, direct filesystem access via the bind-mounted `/etc/openvpn`) or the CLI (`openvpn-install.sh --set-country`/`--set-os`/`--set-bandwidth`, which delegate to `client_policy_cli.py`).

- **`client_usage.json`** — weekly bandwidth usage, keyed by client name, written only by `openvpn-client-disconnect.py`:
  ```json
  {"alice": {"week_start": "2026-08-03", "bytes_used": 1073741824}}
  ```

Both files use an atomic write-to-tmp-then-`rename` pattern with `flock`-based locking (see `host-scripts/policy_lib.py`), so the app, the CLI, and the connect/disconnect scripts can all touch them concurrently without corruption.

### CLI

```bash
sudo bash openvpn-install.sh --set-country alice PK      # restrict alice to country code PK, or ANY to clear
sudo bash openvpn-install.sh --set-os alice windows,linux # restrict alice's allowed OS, or ANY to clear
sudo bash openvpn-install.sh --set-bandwidth alice 5      # 5 GB/week quota for alice, or ANY to clear
sudo bash openvpn-install.sh --get-policy alice           # show alice's current policy
sudo bash openvpn-install.sh --get-policy                 # show every client's policy
```

### Web UI

The VPN Clients page's "Manage Restrictions" dialog exposes all three settings per client — a full ISO 3166-1 country dropdown, the OS checkboxes, and the bandwidth quota field — plus a best-effort (updated-on-disconnect, not live) "used this week" indicator when a quota is set. The country list is a static, self-contained dataset embedded in `app.js` (no external API call at runtime).

### Setting up country restriction (GeoIP)

Country restriction needs a MaxMind GeoLite2-Country database on the OpenVPN host, which requires a **free** MaxMind account:

1. Sign up at <https://www.maxmind.com/en/geolite2/signup> and generate a license key.
2. Add it to `/etc/openvpn/vpn-tools.conf`:
   ```
   MAXMIND_LICENSE_KEY=your_key_here
   ```
3. Run `sudo bash geoip-update.sh` once to fetch the database (defaults to `/etc/openvpn/server/GeoLite2-Country.mmdb`; override with `MAXMIND_DB_PATH`).
4. Install the weekly refresh timer: copy `systemd/openvpn-geoip-update.{service,timer}` to `/etc/systemd/system/`, then `systemctl enable --now openvpn-geoip-update.timer`. Safe to install *before* step 1/2 — the update script detects a missing license key and exits cleanly (logging why) instead of erroring.
5. `python3 -m pip install geoip2` on the OpenVPN host (the connect script's GeoIP lookup uses this pure-Python MaxMind db reader — needed only on the host, not inside the app's Docker image).
6. Pick a country per client from the "Manage Restrictions" dialog's dropdown on the VPN Clients page (or `openvpn-install.sh --set-country NAME CODE` from the CLI) — no deployment-wide setting to configure; every client is independent.

**Fail-safe behavior:** a client with *no* country restriction configured never triggers a GeoIP lookup at all (zero dependency on the mmdb/geoip2 being present). A client *with* a country restriction configured, where the lookup can't be completed (missing db, missing package, any other error), is **rejected** (fail closed) rather than silently let through — logged as `country_lookup_failed`, distinct from an actual `country_not_allowed` mismatch.

### Design notes

- **Why bandwidth is a soft cutoff:** no OpenVPN management-interface integration, no polling daemon — the simplest form that's still genuinely useful. An in-progress session is never killed; only the *next* connection attempt is gated.
- **This is a self-hosted, open-source project** — nothing above hardcodes any specific country, deployment, or organization; every client independently picks its own restriction (or none) from the full ISO 3166-1 list.

## Login restrictions (country / IP allowlisting)

Separate from VPN client restrictions above, an **admin login** to this web app itself can also be restricted per user — to a set of countries, a set of IPs/CIDR ranges, both, or (the default) neither.

- **Where:** Users page → Add User's "Login restrictions" section, or an existing user's Edit dialog → "Login Restrictions". Two independent toggles: "Restrict login by country" and "Restrict login by IP address"; each has its own list, editable regardless of whether the other is on.
- **Countries:** picked from the same full ISO 3166-1 country list used elsewhere in the app (no API call at runtime). Detected via GeoIP on the sign-in request's IP — see below for the database this needs.
- **IPs:** one per line, each either a single address (`203.0.113.5`) or a CIDR range (`10.0.0.0/24`), IPv4 or IPv6.
- **Blank = unrestricted.** Leaving a toggle off, or its list empty, means that dimension is never checked for that user — a fresh account has no login restriction at all by default.
- **Order of checks:** country, then IP, both *before* the password is ever verified — a request from a blocked country/IP is rejected without touching password-hashing, and without revealing whether the username/password would otherwise have been correct. A blocked attempt gets a specific message ("Login is not permitted from your current country/IP address"); a genuinely wrong username or password still gets the same generic "Invalid username or password" as before, so a blocked-vs-wrong-credentials response never leaks which case it was.
- **Audit trail:** every blocked attempt is logged (Users Activity page → Recent User Activity, action `login_blocked_country` or `login_blocked_ip`) with the attempted username, source IP, detected country, and which restriction blocked it.

**GeoIP setup:** the country check reuses the *same* GeoLite2-Country database as VPN client country restriction (see the setup steps above) — no separate MaxMind account needed. The one difference: this lookup happens **inside the app's own Docker container**, not on the bare host, so it needs the `geoip2` Python package (already in `app/requirements.txt`, nothing to install manually) and `GEOIP_DB_PATH` pointed at the mmdb file (defaults to the same path the host-side setup already produces, `/etc/openvpn/server/GeoLite2-Country.mmdb`, which the app already bind-mounts rw — see `.env.example`).

**Fail-safe behavior:** identical stance to VPN client country restriction — a user with country restriction enabled whose country can't be determined (missing db, lookup error) is rejected (fail closed), not silently let through.

## Requirements

- Ubuntu 18.04+, Debian 9+, AlmaLinux/Rocky/CentOS 7+, or Fedora
- Root (or passwordless sudo) to run `openvpn-install.sh`
- Python 3 for `vpn-status.py`

## License

MIT — see [LICENSE](LICENSE).
