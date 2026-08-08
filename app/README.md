# OpenVPN Toolkit — Web App

A web admin UI for the [OpenVPN Toolkit](../README.md) CLI scripts, aimed at
non-technical users who need to add/revoke clients and check VPN status
without touching a terminal. It's a thin FastAPI frontend over
`openvpn-install.sh` and `vpn-status.py` — those two scripts remain the
single source of truth for all VPN logic; this app doesn't reimplement any
of it, only calls it and renders the result.

> **Status**: not yet deployed to any production server. Built and tested
> locally (including inside a real Docker container against fake stand-in
> scripts) — review before deploying against a real OpenVPN install.

## Features

Everything the CLI can do, plus more:
- Add / revoke clients, with MAC-address input in any common format
- List all clients (online/offline/revoked status, last-seen, MAC count), sorted online-first, with a live total count
- Add, remove, or bulk-remove individual MAC addresses for an existing client (multi-device users) without re-issuing a cert
- Consistency check (`--check`) and MAC-db formatting health (`--lint-db`)
- Live connection status: who's online now, bandwidth, rejected (MAC-mismatch) connection attempts with expected-vs-presented MAC and repeat-attempt counts
- Clickable dashboard stat cards (plus a second row of MAC/rejection stats) linking straight to the filtered table behind each number
- Multi-user accounts with two roles: **admin** (full control) and **viewer** (read-only)
- Self-service profile page (click your username in the sidebar): any user can set their own name/gender/team and change their own password
- Team view: portal users grouped by team, click a team to see its members
- Admin user management: edit any user's role, profile fields, and reset their password (account creation date is immutable); soft-delete/restore accounts (deleted users are recoverable, never silently gone)
- Every add/revoke/user-management action is written to an audit log (who, when, what, success/failure)

## Architecture

- **Backend**: FastAPI, server-rendered HTML (Jinja2) + a bit of vanilla JS calling a JSON API — no separate frontend build step.
- **Database**: SQLAlchemy, works with either SQLite (default, zero setup) or PostgreSQL — set via `DATABASE_URL`. Only stores this app's own accounts and audit log, never VPN client data (that always comes live from the scripts).
- **Runs co-located** with the OpenVPN server: calls `openvpn-install.sh`/`vpn-status.py` via `subprocess` on the same box, not over SSH.
- **No shell injection surface**: every subprocess call uses an explicit argument list (never `shell=True` or string-built commands) — see `vpnadmin/cli_wrapper.py` and `tests/test_cli_wrapper.py`, which specifically asserts a malicious-looking client name arrives as one inert argument, not something a shell could interpret.

## Quick start (local, no Docker)

```bash
cd app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env: set SECRET_KEY, OPENVPN_INSTALL_SCRIPT/VPN_STATUS_SCRIPT paths,
# BOOTSTRAP_ADMIN_USERNAME/PASSWORD
uvicorn main:app --host 0.0.0.0 --port 8000
```

Requires root (or passwordless `sudo`) to actually run the underlying
scripts — set `USE_SUDO=true` in `.env` if this process isn't already root.

## Quick start (Docker)

```bash
cd app
cp .env.example .env   # fill in SECRET_KEY, BOOTSTRAP_ADMIN_USERNAME/PASSWORD
docker compose up -d --build
```

`docker-compose.yml` bind-mounts what the container needs from the host:

| Mount | Why |
|---|---|
| `/etc/openvpn:/etc/openvpn` (rw) | `--add`/`--revoke` write new certs and update `openvpn_db.txt` here |
| `/var/log/openvpn:/var/log/openvpn` (ro) | `vpn-status.py` reads connection/rejection history from here |
| `../openvpn-install.sh`, `../vpn-status.py` (ro) | the actual scripts this app wraps — bind-mounted, not baked into the image, so a `git pull` on the host takes effect without rebuilding |
| `./data` | SQLite file persistence (skip if using Postgres instead) |

The container runs as root (needed to touch root-owned `/etc/openvpn` and
run `easyrsa`) with `USE_SUDO=false` — no `sudo` binary needed since the
process already has the privilege it would otherwise escalate to.

To use PostgreSQL instead of SQLite: set `DATABASE_URL=postgresql://...` in
`.env` and uncomment the `postgres` service in `docker-compose.yml`.

## Configuration

See `.env.example` for the full list with explanations. Nothing is
hardcoded to any specific server — every path/setting is env-driven.

## Roles

- **admin**: everything, including adding/revoking clients and managing app user accounts.
- **viewer**: read-only — can see status/clients/diagnostics, cannot mutate anything.

Guardrails prevent an admin from locking everyone out: you can't demote,
deactivate, or delete your own account, and you can't remove the last
active admin.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

62 tests, none of which require a real OpenVPN install or root — the CLI
wrapper tests monkeypatch `subprocess.run` and assert on the exact argument
lists constructed (including an explicit injection-safety test); the auth/
role/DB tests run against an in-memory SQLite database.

## What this app deliberately does NOT expose

Installing or fully uninstalling the OpenVPN server itself (`--remove` in
the CLI) is not in the UI — that's a destructive, whole-server action best
left to a human running the script directly, not a web button. This app
manages **clients**, not the VPN server's own install state.

## Planned (phase 2)

A Traefik reverse proxy in front of this app for TLS termination and
domain routing — not yet implemented. For now, run it behind whatever
TLS/proxy setup you already have, or access it directly over HTTP on your
internal network.
