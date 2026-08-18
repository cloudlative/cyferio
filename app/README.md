# Cyferio Admin

The web admin UI for the [Cyferio](../README.md) CLI scripts, aimed at
non-technical users who need to add/revoke clients and check VPN status
without touching a terminal. It's a thin FastAPI frontend over
`openvpn-install.sh` and `vpn-status.py` — those two scripts remain the
single source of truth for all VPN logic; this app doesn't reimplement any
of it, only calls it and renders the result.

> **Status**: production-ready — deploys behind Traefik (automatic Let's
> Encrypt TLS) with a PostgreSQL backend; see `docker-compose.yml` and the
> repo root's `setup.sh` for a full self-hosted install.

## Features

Everything the CLI can do, plus more:
- Add / revoke clients, with MAC-address input in any common format
- List all clients (online/offline/revoked status, last-seen, MAC count), sorted online-first, with a live total count and a "missing a MAC" filter
- Add, remove, or bulk-remove individual MAC addresses for an existing client (multi-device users) without re-issuing a cert
- View or copy a client's .ovpn profile on demand (admin-only), including right after adding a new client
- Email a client's .ovpn profile directly to a recipient's inbox, with a branded HTML template (requires SMTP config -- see `.env.example`; the UI stays present either way, and the action fails cleanly with a clear message if SMTP isn't set up)
- Selective, permanent cleanup of a revoked client's leftover certificate/key files (checkboxes + bulk delete, admin-only) -- the revocation record itself always stays, for CRL correctness and audit history
- Restore a revoked client: since a revoked certificate can never be un-revoked (that's how PKI revocation is supposed to work), this issues a brand-new certificate under the same name instead -- documented plainly in the UI, not oversold as reactivating the old cert
- Consistency check (`--check-certs`) and MAC-db formatting health (`--lint-mac-db`)
- Live connection status: who's online now, bandwidth, rejected (MAC-mismatch) connection attempts with expected-vs-presented MAC and repeat-attempt counts
- A donut chart of rejected-connection attempts broken down by claimed client name, on the Diagnostics page
- Clickable dashboard stat cards (plus a second row of MAC/rejection stats) linking straight to the filtered table behind each number
- **Dynamic role-based access control**: 4 built-in roles (Admin, Editor, Viewer, User), plus admin-creatable custom roles with a per-module permission matrix (View/Create/Update/Delete/Execute/Manage, each with an Any-record/Own-record-only scope) editable from the Roles page (`/roles`) -- see [Roles & Permissions](#roles--permissions). The bootstrap admin (the very first admin account a deployment ever creates) can never be demoted, deactivated, or deleted by anyone -- every other admin account remains fully manageable by another admin
- **VPN profile ↔ portal account identity linking**: every VPN client gets a linked portal account (auto-created if none matches), and a **My VPN Profile** self-service page (`/my-vpn-profile`) lets a "User" (self-service role) account view their own profile, manage their own MAC addresses, and download their own `.ovpn` -- with no visibility into any other user's clients, users, teams, audit logs, or settings. See [Roles & Permissions](#roles--permissions)
- First Name is required for every account (add-user and edit-user, both client- and server-side validated) -- it's also now the primary displayed identity (profile page heading), not the raw login username
- Search box on the Users page filters the list by name, username, or team as you type
- Soft-deleted accounts can be restored, or permanently (irreversibly) deleted as a distinct, separately-confirmed admin action -- audit history survives a permanent delete since it stores a username snapshot, not a foreign key
- Self-service profile page (click your username in the sidebar): any user can set their own name/gender/teams and change their own password
- Teams are a real, many-to-many resource: a user can belong to several teams at once, assignable from the Users page, the Teams page's per-team add/remove-member controls, or the profile page; a team can only be deleted once it has no members; the Teams page shows a summary (team/assigned/unassigned counts) plus per-team member management
- Admin user management: edit any user's role, profile fields, and reset their password (account creation date is immutable); soft-delete/restore accounts (deleted users are recoverable, never silently gone, unless permanently deleted)
- Team pickers everywhere (add-user, edit-user, profile) are a closed-by-default dropdown multiselect, not a giant always-open checkbox list
- **Settings page** (admin-only, `/settings`): branding, SMTP, security (minimum password length, session timeout), and audit-log-retention are all editable at runtime from the UI, stored in the database, and take effect immediately app-wide -- no `.env` edit or restart needed. Environment variables (see `.env.example`) remain the seed/fallback default for anything never touched on this page. Includes a "Send Test Email" action that dry-runs whatever SMTP values are currently in the form (not necessarily saved yet) against a destination address, without persisting anything
- Every add/revoke/user-management/team/email/settings action is written to an audit log (who, when, what, success/failure)

## Architecture

- **Backend**: FastAPI, server-rendered HTML (Jinja2) + a bit of vanilla JS calling a JSON API — no separate frontend build step.
- **Database**: SQLAlchemy, works with either SQLite (zero-setup default, still the right choice for local/dev) or PostgreSQL (production, via the `postgres` compose service) — set via `DATABASE_URL`. Only stores this app's own accounts and audit log, never VPN client data (that always comes live from the scripts).
- **Runs co-located** with the OpenVPN server: calls `openvpn-install.sh`/`vpn-status.py` via `subprocess` on the same box, not over SSH.
- **No shell injection surface**: every subprocess call uses an explicit argument list (never `shell=True` or string-built commands) — see `vpnadmin/cli_wrapper.py` and `tests/test_cli_wrapper.py`, which specifically asserts a malicious-looking client name arrives as one inert argument, not something a shell could interpret.

Measured footprint of the `app` container itself: 120-150 MB RAM steady
state, negligible CPU except a one-time ~90-115s single-core spike at
startup (and after any GeoIP database refresh) while building the
city/ASN restriction pick-lists. Runs a single `uvicorn` worker by default
(see `Dockerfile`'s `CMD`) — fine for typical admin/portal concurrency,
but `--workers N` is the knob if a large self-service portal user base
grows past that. Full CPU/RAM/storage/networking/database sizing guidance
for the whole stack (this app + OpenVPN + Traefik + Postgres), across
minimum/recommended/production-scale tiers, backed by real deployment
measurements: [Sizing & Infrastructure](https://docs.cyferio.com/sizing/).

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

`docker-compose.yml` and `.env.example` live at the **repo root**, not
here in `app/` — the compose file needs `../openvpn-install.sh` and
`../vpn-status.py` at predictable paths for its bind mounts, and putting
it at the root where those scripts actually live keeps every path in it a
plain `./something` instead of a pile of `../`. Run everything from the
repo root:

```bash
cp .env.example .env   # fill in SECRET_KEY, BOOTSTRAP_ADMIN_USERNAME/PASSWORD
docker compose pull && docker compose up -d
```

The `app` service pulls a pre-built image from GHCR
(`ghcr.io/cloudlative/cyferio-app`, public — no `docker login`
needed) rather than building locally. It's published by
[`.github/workflows/build.yml`](../.github/workflows/build.yml) whenever a
version tag (`vX.Y.Z`) is pushed — see [Releases](#releases) below.
Ordinary commits to `master` only run the test suite, they don't publish a
new image. To deploy an exact version instead of always tracking `latest`,
set `IMAGE_TAG=X.Y.Z` in `.env` -- note: **no leading `v`**, even though the
git tag itself is `vX.Y.Z` (`docker/metadata-action`'s `type=semver` tagging
strips it, so pushing `v1.0.1` publishes the image as `...:1.0.1`, not
`...:v1.0.1`). See the
[Packages page](https://github.com/cloudlative/cyferio/pkgs/container/cyferio-app)
for what's been published, before `docker compose pull`.

Find the latest published version tag from the command line (no `gh`/GitHub
login needed -- GHCR's anonymous token endpoint is enough since the package
is public):

```bash
TOKEN=$(curl -s "https://ghcr.io/token?scope=repository:cloudlative/cyferio-app:pull" | grep -oE '"token":"[^"]+"' | cut -d'"' -f4)
curl -s -H "Authorization: Bearer $TOKEN" "https://ghcr.io/v2/cloudlative/cyferio-app/tags/list" \
  | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' | tr -d '"' | sort -V | tail -1
```

Prints just the version number (e.g. `1.0.5`) -- set that as `IMAGE_TAG` in
`.env` before `docker compose pull` for a reproducible, deliberately-chosen
deploy instead of always tracking `latest`.

Rolling back a bad deploy: either set `IMAGE_TAG` in `.env` to a known-good
previous version tag and re-run `docker compose pull && docker compose up -d`,
or check out the commit before the GHCR-image switch (`build: .` instead of
`image:` in `docker-compose.yml`, and the compose file back under `app/`)
and `docker compose up -d --build`.

`docker-compose.yml` bind-mounts what the container needs from the host
(all paths below relative to the repo root, where the compose file lives):

| Mount | Why |
|---|---|
| `/etc/openvpn:/etc/openvpn` (rw) | `--add-user`/`--revoke-user` write new certs and update `openvpn_db.txt` here |
| `/var/log/openvpn:/var/log/openvpn` (ro) | `vpn-status.py` reads connection/rejection history from here |
| `./openvpn-install.sh`, `./vpn-status.py` (ro) | the actual scripts this app wraps — bind-mounted, not baked into the image, so a `git pull` on the host takes effect without rebuilding |
| `./app/data` | SQLite file persistence (only relevant if `DATABASE_URL` stays on the SQLite default — see below) |

**`OVPN_OUTPUT_DIR` must be under `/etc/openvpn`** — that's the only path
above containing generated `.ovpn` client files that's shared between the
host and this container. If `/etc/openvpn/vpn-tools.conf`'s
`OVPN_OUTPUT_DIR` is left at its script default (a human account's home
directory, e.g. `/home/ubuntu` or `/root`), files really do land there on
the host, but they're invisible to this container — every "View .ovpn" /
"Email .ovpn" action then fails with a "no .ovpn file found" error even
though the file exists. Set `OVPN_OUTPUT_DIR=/etc/openvpn/client` (see
`vpn-tools.conf.example`) before running the app in Docker.

### First-time setup on a new machine

One guided entrypoint, `setup.sh` (repo root), takes a fresh box the rest
of the way to a running portal, but it can't do the very first step itself
(see why below) — so it's still two steps in practice:

**1. `add-machine.sh` (repo root) — run from YOUR OWN machine, not the
target host.** Bootstraps the new box's read-only access to this private
repo and clones it there:

```bash
./add-machine.sh --host 203.0.113.10 --user ubuntu
```

This needs the `gh` CLI authenticated locally (registering a GitHub deploy
key needs *some* already-authenticated session, and that's yours, not a
brand-new box's) and that you can already SSH to the target host as
`--user` — it only bootstraps *repo* access, not your own login to the box.
It generates an ed25519 keypair **on the target host** (the private half
never leaves it), registers the public half as a read-only deploy key on
`cloudlative/openvpn-toolkit` from here, wires up an SSH config alias on
the host so git resolves it unambiguously, and clones (or `git fetch`s, if
already cloned) into `/opt/openvpn-toolkit`. Idempotent — safe to re-run
against a box that already has some or all of this done (as it will be, the
next time you pull newer commits onto an existing box).

**2. `setup.sh` (repo root) — run ON the target host** (`ssh` in first).
Guided prompts by default (OpenVPN only, or OpenVPN + this web app portal?
domain/ACME email if the portal is wanted? MaxMind GeoIP?), or fully
non-interactive via flags:

```bash
sudo /opt/openvpn-toolkit/setup.sh --mode webapp \
  --domain vpn.example.com \
  --acme-email you@example.com \
  --use-staging-first    # first time on a genuinely new domain
```

`setup.sh` orchestrates `openvpn-install.sh` (installs OpenVPN itself, if
not already installed) and, for `--mode webapp`, `setup-new-machine.sh`
(everything else a fresh host needs for this portal: generating the scoped
SSH "host executor" key + forced-command wrapper + sudoers grant, writing
`.env`, enabling the deploy-key volume mount, and bringing the stack up).
See [Roles & Permissions](#roles--permissions) for what the host executor
now backs (live session listing/disconnect, `app/vpnadmin/routes/clients.py`)
— the web app no longer has an install/uninstall page of its own; installing
OpenVPN is `setup.sh`'s/`openvpn-install.sh`'s job, not something triggered
from the UI.

Re-running `setup.sh` (e.g. after changing `--deploy-user`, or just to pick
up config-file changes from a newer commit) is safe — every phase checks
its own current state first, so nothing already correct is redone or
duplicated, and it reports either what changed or "nothing to do". It
refuses to touch a machine it doesn't recognize as its own (e.g. real
production set up some other way) — see `setup.sh --help` for the full
flag list and that safety mechanism's details.

Prefer the three scripts directly instead of `setup.sh`? They still work
exactly as before — `setup.sh` only orchestrates them, it doesn't replace
them. `setup-new-machine.sh --help` has its own full flag list.

**Why the host-executor key logs in as a regular deploy user (`ubuntu` by
default), never root**: even with the forced-command wrapper restricting
*what* the key can run, a root SSH session is categorically higher
blast-radius than a normal user's session escalated via one narrowly-scoped
`sudo` rule for an exact command path — and "root login enabled" gets
flagged by security scanners/compliance checks regardless of what
restricts it. The script grants `NOPASSWD` sudo for exactly
`app/cli/openvpn_admin.py`, nothing broader, via a generated,
`visudo`-validated `/etc/sudoers.d` file.

### Releases

Image builds are tag-triggered, not push-triggered: pushing a version tag
is what cuts a release and publishes a new image.

```bash
git tag v1.0.0
git push --tags
```

That runs the full pipeline (test → build/push → Trivy scan) and publishes
`ghcr.io/cloudlative/cyferio-app:v1.0.0` and `:latest`. A plain
`git push` to `master` only runs the test job — no image is built or
published.

The container runs as root (needed to touch root-owned `/etc/openvpn` and
run `easyrsa`) with `USE_SUDO=false` — no `sudo` binary needed since the
process already has the privilege it would otherwise escalate to.

### Database: SQLite (dev) vs PostgreSQL (production)

`docker-compose.yml` ships a `postgres` service alongside `app`. SQLite
(the `DATABASE_URL` default) remains the zero-setup choice for local/dev —
nothing to stand up, just run `docker compose up`. **Production now runs
PostgreSQL**: set `DATABASE_URL=postgresql://vpnadmin:<password>@postgres:5432/vpnadmin`
in `.env` (host `postgres` is the compose service name, only reachable from
other containers on the same compose network — Postgres itself is never
published to the host), and a `POSTGRES_PASSWORD` (generate one with
`python3 -c "import secrets; print(secrets.token_urlsafe(32))"` — see
`.env.example`). Data persists in the named `pgdata` volume across
container recreation.

Moving an existing SQLite deployment's data into Postgres: use
`scripts/migrate_sqlite_to_postgres.py`, which reuses the app's own
SQLAlchemy models against both databases (never hand-translated SQL) to
copy every row table-by-table, preserving ids/foreign keys/timestamps, and
prints a per-table row-count comparison at the end so you can confirm the
copy is complete before cutting `DATABASE_URL` over:

```bash
python3 scripts/migrate_sqlite_to_postgres.py \
  --sqlite-url sqlite:////opt/openvpn-toolkit/app/data/app.db \
  --postgres-url postgresql://vpnadmin:<password>@localhost:5432/vpnadmin
```

(Run against `localhost:5432` from the host, or temporarily publish the
`postgres` service's port if running the script from outside a container
on the compose network — it doesn't need to run inside a container.) Keep
the original SQLite file around as a safety net even after cutting over —
nothing in this app deletes it automatically.

## Configuration

See `.env.example` for the full list with explanations. Nothing is
hardcoded to any specific server — every path/setting is env-driven.

## Roles & Permissions

Role-based access control is fully dynamic, not a hardcoded enum: every
role (built-in or custom) is a database row with a per-module permission
matrix, editable from the **Roles** page (`/roles`, admin-only). Each
module (Dashboard, VPN Profiles, User Management, Role Management, Teams,
Audit Logs, Settings, Health Screen, Reports) can be granted View / Create
/ Update / Delete / Execute / Manage independently, plus a scope of **Any
record** or **Own record only** (the latter is what makes VPN Self-Service
User possible -- see below). "Manage" is a superset that grants every
action on that module, including on records that aren't the caller's own.

### Built-in roles

| Role | Summary |
|---|---|
| **Admin** | Full control of every module. |
| **Editor** | Can add/revoke/edit VPN clients and manage their MAC addresses. No user management, teams, or settings access. |
| **Viewer** | Read-only: status/list/check, no add/revoke/user-management. |
| **User** | Access to only their own VPN profile and account -- no visibility into other users, teams, audit logs, or settings. |

Custom roles work the same way: create one on the Roles page, name it,
then check the boxes for whatever it should see/do per module. A custom
role can't be assigned Any-scope on a module without being granted the
matching permission first, and system roles can be renamed/described but
never deleted.

### VPN profile ↔ portal account identity

Every VPN client certificate is linked 1:1 to a portal user account
(`VpnProfileLink`). Adding a new client (`/clients`, or the CLI's
`--add-user`) automatically links it to a matching existing portal
username, or creates a brand-new **"User"** (self-service) account for it
if none matches -- the temp password is shown once, immediately, in the
admin UI response; it is never stored or shown again after that, so relay
it to the device's owner right away.

That link then keeps both sides in sync going forward: suspending or
soft-deleting the linked portal account revokes the VPN cert, and revoking
the cert from the Clients page suspends the linked portal account.
**Exception, permanent and by design**: any link created by the one-time
migration below (`protected_from_auto_revoke=True`) is *never* auto-revoked
by anything, in either direction -- a cert that was already live in
production before this feature existed keeps running no matter what later
happens to its linked portal account. An admin can always revoke it
manually from the Clients page; nothing here does it automatically.

### Migrating an existing deployment

Deployments that predate this feature have VPN clients with no linked
portal account yet. Align them once, after upgrading, with the standalone
CLI script (not a web page -- this only ever needs to run once, so it
doesn't earn a permanent page/nav item):

```bash
docker compose exec app python migrate_vpn_profiles.py preview   # read-only, changes nothing
docker compose exec app python migrate_vpn_profiles.py run       # asks for confirmation, then applies it
docker compose exec app python migrate_vpn_profiles.py last-report
```

`run` never revokes, restores, or purges any VPN certificate -- it only
reads the current client list and creates/links portal accounts, every one
of them permanently exempt from auto-revoke (see above). Temp passwords
for newly-created accounts are printed once, to that terminal, at that
moment -- `last-report` intentionally does not (and cannot) show them
again afterward.

### Dropping legacy branding columns

Deployments that predate the Cyferio rebrand still have unused
`app_name`/`app_tagline`/`app_footer_credit` columns on `app_settings` (the
app itself no longer reads or writes them -- branding is now fixed, not
configurable). Same standalone-script pattern as above, since this repo has
no Alembic and `init_db()`'s reconciler only ever adds columns, never drops
them. Safe to skip indefinitely -- these columns being present but unused
breaks nothing.

```bash
docker compose exec app python drop_legacy_branding_columns.py preview  # read-only, changes nothing
docker compose exec app python drop_legacy_branding_columns.py run      # asks for confirmation, then applies it
```

### Guardrails

You can't deactivate, delete, or demote your own account, and you can't
remove the last active admin. The bootstrap admin -- the very first admin
account a deployment ever creates (tracked via `User.is_bootstrap_admin`,
set once by `auth.bootstrap_admin()`) -- has a stricter rule on top of
that: it can never be demoted, deactivated, or deleted (soft or permanent)
by anyone, including another admin, full stop. Every *other* admin account
remains fully demotable/deactivatable/deletable by another admin, same as
any account, subject only to the last-admin/self-lockout guardrails above.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

159 tests, none of which require a real OpenVPN install or root — the CLI
wrapper tests monkeypatch `subprocess.run` and assert on the exact argument
lists constructed (including an explicit injection-safety test); the auth/
role/DB tests run against an in-memory SQLite database (the `db_session`
fixture seeds the same dynamic-RBAC roles `db.init_db()` does in production
-- see `tests/conftest.py`); the .ovpn/email and Settings-page tests
monkeypatch `cli_wrapper`/`mailer` directly (including a simulated SMTP
failure for the test-email path).

## What this app deliberately does NOT expose

Installing or fully uninstalling the OpenVPN server itself (`--remove` in
the CLI) is not in the UI — that's a destructive, whole-server action best
left to a human running the script directly, not a web button. This app
manages **clients**, not the VPN server's own install state.

## TLS / reverse proxy (Traefik)

`docker-compose.yml` includes a `traefik` service fronting `app`: it
terminates TLS, issues/renews a Let's Encrypt certificate automatically via
the HTTP-01 challenge (Traefik's standard ACME provider, configured via
labels on the `app` service — no separate static config file), and
redirects plain HTTP to HTTPS. Configure it via `.env` (see
`.env.example`):

- `APP_DOMAIN` — the public hostname to request a cert for; must already
  resolve to this host's public IP, and ports 80/443 must be reachable from
  the internet (Traefik's HTTP-01 challenge needs port 80; the app itself
  is never exposed on a host port once Traefik is in front of it).
- `ACME_EMAIL` — a real, monitored mailbox; Let's Encrypt sends
  expiry/problem notices here.
- `ACME_CASERVER` — leave unset for Let's Encrypt production. Point at
  `https://acme-staging-v02.api.letsencrypt.org/directory` first when
  standing this up or changing domains, to avoid burning production
  rate-limit attempts on a config that isn't verified yet — staging certs
  aren't browser-trusted, so flip back to production only once a staging
  cert issues cleanly.
- `SESSION_HTTPS_ONLY=true` — once Traefik is actually terminating TLS,
  set this so the session cookie is marked `Secure`.

The ACME account/cert state persists in the named `traefik-acme` volume.
Traefik manages that file's permissions (600) itself; don't hand-edit it.

Direct host-port access to the app (bypassing Traefik) is intentionally
not exposed by default now that Traefik handles all public traffic — see
the commented-out `ports:` block on the `app` service in
`docker-compose.yml` if you need a debug path bound to an internal-only
interface (e.g. the OpenVPN tunnel address). Never bind it to a public
interface alongside Traefik.
