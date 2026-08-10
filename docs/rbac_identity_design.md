# Dynamic RBAC + VPN/Portal Identity Alignment — Design

Status: **design for review, nothing implemented yet** (per your instruction to design
before coding). Answers already locked in from your last round:

1. **Full replace** — the `Role` enum and its 3 hardcoded `require_*` dependencies go
   away entirely; admin/editor/viewer become seeded rows in the new dynamic tables.
2. **Strict 1:1** — one portal user, one VPN profile, no multi-device accounts (for now
   — schema still makes this easy to loosen later, see §6).
3. **Orphan VPN certs get auto-created Self-Service accounts** during migration.
4. **Exact, case-insensitive match only** for migration linking; anything else is an
   orphan/conflict for the report, never guessed.

---

## 0. Ground truth from the current codebase

This matters because it changes what "VPN Profile" means here vs. a typical enterprise
app:

- **VPN clients are not database rows.** They're OpenVPN certs/CCD entries managed by
  shell scripts (`openvpn-install.sh`) through `cli_wrapper.py`, identified only by a
  `name` string (+ a bound MAC). `routes/clients.py` calls `add_client`, `revoke_client`,
  `restore_client`, `purge_revoked` — there's no "disable" primitive, only
  **revoke ↔ restore**. So "suspend a VPN profile" maps naturally onto
  `revoke_client`/`restore_client`, which already exist and are already reversible.
- **Roles today**: `models.py` `Role(str, enum.Enum)` = `admin | editor | viewer`,
  enforced via 3 FastAPI dependencies in `auth.py`: `require_admin`,
  `require_client_manager` (admin+editor), `require_user` (any logged-in user).
- **Sessions are stateless** (signed cookie, no server-side store) — `get_current_user`
  already re-checks `is_active`/`deleted` from the DB on *every* request. This means
  "kill active sessions" for a suspended/deleted account is **already free**: flip
  `is_active` to `False` and their very next request gets rejected. No token-revocation
  list needed.

---

## 1. Schema

### 1.1 Roles + permissions (replaces the `Role` enum)

```python
class RoleKind(str, enum.Enum):
    system = "system"   # the 4 seeded roles below — undeletable, slug is fixed
    custom = "custom"   # anything an admin creates via Roles Management

class RoleDef(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    slug = Column(String(64), unique=True, nullable=False)   # "admin","editor","viewer",
                                                               # "vpn_self_service", or custom
    name = Column(String(128), nullable=False)                # display name, editable even for system roles
    description = Column(Text, nullable=True)
    kind = Column(Enum(RoleKind), nullable=False, default=RoleKind.custom)
    is_system = Column(Boolean, nullable=False, default=False)  # blocks delete + slug rename
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    created_by = Column(String(64), nullable=True)  # username snapshot, same pattern as AuditLog

class ObjectPermission(Base):
    """One row per (role, object). Mirrors the table in your spec directly."""
    __tablename__ = "role_object_permissions"
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    object_key = Column(String(64), nullable=False)  # "dashboard","health","users","vpn_profiles",
                                                        # "roles","audit_log","settings","reports","teams", ...
    can_view = Column(Boolean, nullable=False, default=False)
    can_create = Column(Boolean, nullable=False, default=False)
    can_update = Column(Boolean, nullable=False, default=False)
    can_delete = Column(Boolean, nullable=False, default=False)
    can_execute = Column(Boolean, nullable=False, default=False)  # e.g. "revoke client", "restart", non-CRUD actions
    can_manage = Column(Boolean, nullable=False, default=False)   # superset flag: full control incl. delegation
    __table_args__ = (UniqueConstraint("role_id", "object_key"),)
```

New `objects` aren't a DB table — they're a small constant registry in code
(`permissions.py: OBJECTS = {"dashboard": "Dashboard", "vpn_profiles": "VPN Profiles", ...}`),
same spirit as `AppSettings`' comment about being "discoverable straight from this class."
Adding a future module = one line in that registry, not a migration.

### 1.2 API-level permissions — recommended shape (see tradeoff note)

Your spec asks for literal per-endpoint, per-method grants (`GET /api/vpn/profile`, etc).
Implementing that as a **free-form URL-pattern ACL** is the one place I want to push back
before locking the schema in, because it's a real security footgun: every new route a
future PR adds is unprotected by default until someone remembers to add an ACL row for
it, and pattern-matching against FastAPI's path-param routes (`/api/users/{id}`) is
fragile. The industry-standard fix (what Keycloak/Auth0 fine-grained authz actually do)
is: **routes declare which (object, action) they require at the code level** (a
dependency, fail-closed by default), and the "API permissions" UI becomes a view/editor
*over that same object-permission matrix*, plus one extra dial your spec explicitly
wants that object-permissions alone can't express: **scope**.

```python
class ApiScope(str, enum.Enum):
    any = "any"    # operate on any record of this object type
    own = "own"    # operate only on records the caller owns (self-service)

class RoleApiScope(Base):
    """Per (role, object): does this role's access apply to any record, or only
    the caller's own? This is the mechanism that makes VPN Self-Service User work --
    it holds the *same* can_view/can_update as ObjectPermission but scoped to 'own'."""
    __tablename__ = "role_api_scopes"
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    object_key = Column(String(64), nullable=False)
    scope = Column(Enum(ApiScope), nullable=False, default=ApiScope.any)
    __table_args__ = (UniqueConstraint("role_id", "object_key"),)
```

Every route gets one line like `Depends(require_permission("vpn_profiles", "update"))`;
the dependency resolves the caller's role, checks `ObjectPermission`, and if `scope=="own"`
also checks the resource's owner == caller before allowing it through — so `/api/me/vpn-profile`
and `/api/vpn-profiles/{id}` can literally be the **same route**, with `{id}` defaulting to
"my own profile" for self-service-scoped roles. Fail-closed: no matching permission row =
403, including for objects added after a role was created.

If you want the literal free-text endpoint/method ACL instead (closer to your original
wording, more flexible, but the footgun above is real), say so and I'll design that
variant instead — trade-off is yours to make, not mine.

### 1.3 User table changes

```python
# models.py User — replace:
role = Column(Enum(Role), nullable=False, default=Role.viewer)
# with:
role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
role = relationship("RoleDef")
```

`is_bootstrap_admin` stays exactly as-is — untouched by this whole feature, per your
"except bootstrap admin user" instruction. Bootstrap admin keeps whatever role row maps
to slug `"admin"`; the existing un-demotable check in `routes/users.py` just needs to
compare `user.role.slug == "admin"` instead of `user.role == Role.admin`.

### 1.4 VPN Profile ↔ Portal User link

```python
class VpnProfileLink(Base):
    """The only place the VPN-cert world (file/CLI-based) and the portal-user world
    (DB-based) are tied together. Deliberately NOT a column on User, because a VPN
    client can (transiently, during migration or admin cleanup) exist unlinked."""
    __tablename__ = "vpn_profile_links"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    vpn_client_name = Column(String(64), unique=True, nullable=False, index=True)  # == cli_wrapper client name
    link_source = Column(String(32), nullable=False)  # "created_with_profile" | "migration_exact_match"
                                                         # | "manual_admin_link"
    # Permanent guarantee, not a one-time migration skip: every cert that was already
    # live in production before this feature shipped gets this set True at migration
    # time and it is NEVER flipped back by any code path. The sync hooks in §4 check
    # this before ever calling cli.revoke_client/purge_revoked -- a real, currently-
    # connected user's VPN access must never go down because of a portal-side action,
    # full stop, no matter what happens later to the linked portal account (suspended,
    # deleted, role changed, anything). Only link_source="created_with_profile" (a
    # profile created *after* this feature ships, so cert and account are born
    # together going forward) gets the full bidirectional sync from §4.
    protected_from_auto_revoke = Column(Boolean, nullable=False, default=False)
    linked_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    linked_by = Column(String(64), nullable=True)  # username snapshot; NULL for system-performed migration link

    user = relationship("User", backref="vpn_profile_link", uselist=False)
```

`unique=True` on both columns enforces the strict-1:1 decision at the DB level, not just
in application code.

---

## 2. Enforcement mechanism

```python
def require_permission(object_key: str, action: str):
    """action in {view,create,update,delete,execute,manage}. Replaces require_admin /
    require_client_manager / require_user for anything object-permission-driven."""
    def _dep(user: User = Depends(require_user), db: Session = Depends(get_db)) -> User:
        perm = db.query(ObjectPermission).filter_by(role_id=user.role_id, object_key=object_key).first()
        if perm is None or not getattr(perm, f"can_{action}"):
            raise HTTPException(403, f"Missing {action} permission on {object_key}")
        return user
    return _dep

def require_own_or_permission(object_key: str, action: str, owner_username: Callable[[Request], str]):
    """For /api/me/* and any 'own-record' route -- if the role's scope for this object
    is 'own', additionally requires owner_username(request) == user.username."""
    ...
```

`require_user` (any authenticated user, no object check) stays as-is for read endpoints
that were never role-gated (e.g. `/api/geo/*`). The 3 old dependencies get deleted once
every route referencing them is migrated to `require_permission`.

---

## 3. Seeded roles (system, `is_system=True`)

| slug | object permissions | notes |
|---|---|---|
| `admin` | `can_manage=True` on every object | full control, matches today's admin exactly |
| `editor` | `view+update+execute` on `vpn_profiles` only | matches today's `require_client_manager` scope exactly (add/revoke/MAC — no user mgmt/teams/settings) |
| `viewer` | `view` on everything except `settings`/`roles` | matches today's read-only `require_user`-gated pages |
| `vpn_self_service` | `view+update` on `vpn_profiles` **scoped `own`**, `view+update` on `users` **scoped `own`** (their own account/password) | new role from §3 of your spec; no `manage` on `roles`/`audit_log`/`settings`/`users` (any) |

Migration seeds these 4 rows once, then repoints every existing `User.role` enum value
at the matching row (§5).

---

## 4. Identity lifecycle sync (both directions, guarded by `protected_from_auto_revoke`)

Hooked into the two places that already own each side's lifecycle — no new poller, just
new steps in existing handlers. **Every hook that would call `cli.revoke_client`/
`purge_revoked` first checks `link.protected_from_auto_revoke` — if True, it skips the
VPN-side call entirely, does the portal-side action anyway, and writes an audit row
explaining the cert was deliberately left running.** This is the hard guarantee from
your last message: a live production VPN user's cert is never touched by anything this
feature does, regardless of what happens to their portal account.

**`routes/clients.py add_client`** (VPN profile created — always a *new* cert, so this
path only ever produces `protected_from_auto_revoke=False` links)
→ after cert creation succeeds: if no `VpnProfileLink` exists for that name and no portal
user has that username, auto-create a `vpn_self_service` portal user (random temp
password, `must_reset_password=True` — see §7 open item) + link row
(`link_source="created_with_profile"`, `protected_from_auto_revoke=False`).

**`routes/clients.py revoke_client`** (admin manually revokes a VPN profile through the
existing UI — unrelated to auto-sync, this is a human doing it on purpose)
→ if linked: set the portal user's `is_active=False`. Their session dies on next request
for free (see §0). Reversible: **`restore_client`** → linked portal user `is_active=True`.
This direction (VPN → portal) is unaffected by the protected flag — a real admin
revoking a real cert on purpose should always suspend the matching portal account; the
flag only ever blocks the *reverse* direction (portal action → auto-revoking a cert).

**`routes/clients.py purge_revoked`** (irreversible delete)
→ if linked: soft-delete the portal user (existing `deleted=True` flow) — never a hard
DB delete, matching this app's existing "no hard-delete path" policy for users.

**`routes/users.py` suspend (`is_active=False`)**
→ if linked **and `not protected_from_auto_revoke`**: call `cli.revoke_client(name)`.
→ if linked **and protected**: portal user is suspended as normal, cert is left running,
audit row `vpn_revoke_skipped_protected` records why.
**`routes/users.py` reactivate (`is_active=True`)**
→ if linked and the cert *was* revoked by this app (i.e. not protected): call
`cli.restore_client(name, mac)` — MAC pulled from `cli.list_macs(name)` at the moment of
reactivation, not stored redundantly on the link row.

**`routes/users.py` soft-delete**
→ if linked **and `not protected_from_auto_revoke`**: `cli.revoke_client(name)`.
→ if linked **and protected**: portal account is deleted, cert is left running exactly
as-is, same audit row as above.

All hooks are additive `if user.vpn_profile_link:` branches in existing functions,
wrapped so a `cli_wrapper` failure doesn't roll back the portal-side change silently —
logged via the existing `log_action` audit mechanism as its own audit row
(`action="vpn_sync_failed"`), not swallowed.

---

## 5. Migration plan

Runs once, at startup or via an explicit admin-triggered endpoint (your call — see open
question in §7). Never touches `is_bootstrap_admin` accounts.

1. **Seed roles**: create the 4 system `RoleDef` rows + their `ObjectPermission`/`RoleApiScope` rows per §3, if not already present (idempotent — safe to run every startup, same pattern this app already uses for schema backfills).
2. **Repoint existing users**: for every `User` row still on the old `role` enum column, set `role_id` to the matching seeded row (`admin→admin`, `editor→editor`, `viewer→viewer`). Bootstrap admin included here — this step only maps role, never changes it.
3. **Enumerate VPN clients**: `cli.list_clients()` (active) — revoked/purged clients are explicitly **out of scope**, matching "will not touch existing VPN profile."
4. **Enumerate portal usernames**: all non-deleted `User` rows.
5. **Match**: for each VPN client name, lowercase-compare to lowercased usernames (matches `User._normalize_username`'s existing behavior). **The migration never calls `add_client`, `revoke_client`, `restore_client`, or `purge_revoked` — zero cert-mutating operations, for any client, in any branch below.** It only reads (`list_clients`) and writes DB rows (`VpnProfileLink`, and `User` for newly-created accounts).
   - **Exact match, and that user has no existing link** → create `VpnProfileLink` (`link_source="migration_exact_match"`, **`protected_from_auto_revoke=True`**). Role is **not** changed — an existing admin/editor/viewer who happens to also have a personal VPN cert keeps their role and just gains a linked profile, exactly matching "align existing user with existing profile where possible" without demoting anyone.
   - **No matching username** → per your instruction, do **not** recreate/touch the cert — just create the missing side: a new `vpn_self_service` portal account (random temp password, forced reset) + link (`link_source="migration_exact_match"`, **`protected_from_auto_revoke=True`**). The cert keeps running exactly as it is right now, untouched.
   - **Matches a username that's already linked to a different client** (can't happen with exact-match + unique usernames, but a defensive check) → conflict, reported, no auto-action.
6. **Migration report** (persisted, not just console output — see §7 for exact shape): linked (pre-existing match), newly-created (orphan certs that got accounts), and any conflicts. Every row the migration creates is `protected_from_auto_revoke=True` — this is a closed set fixed at migration time, never reopened later.

### Migration report shape

```json
{
  "run_at": "...",
  "linked_existing": [{"username": "...", "vpn_client_name": "..."}],
  "created_new_accounts": [{"username": "...", "vpn_client_name": "...", "temp_password_delivered": "console|email|shown_once_in_ui"}],
  "unmatched_portal_users": [{"username": "...", "role": "..."}],
  "conflicts": [{"vpn_client_name": "...", "reason": "..."}]
}
```

---

## 6. API design (representative, not exhaustive)

```
Roles Management (require_permission("roles", ...)):
  GET    /api/roles                        list all roles
  POST   /api/roles                        create custom role
  GET    /api/roles/{id}                   detail incl. object+api permission matrix
  PATCH  /api/roles/{id}                   rename/describe (system roles: name/description only, not slug)
  DELETE /api/roles/{id}                   custom roles only (409 if is_system or if any user assigned)
  PUT    /api/roles/{id}/object-permissions   bulk-set the object-permission matrix
  PUT    /api/roles/{id}/api-scopes           bulk-set own/any scope per object

Self-service (require_permission(..., scope enforced via require_own_or_permission):
  GET    /api/me                           already exists
  PUT    /api/me                           already exists (profile fields)
  PUT    /api/me/password                  already exists
  GET    /api/me/vpn-profile               NEW -- own VpnProfileLink + live cli.list_clients()/list_macs() data
  PUT    /api/me/vpn-profile               NEW -- permitted subset only (e.g. MAC re-bind), reuses add_mac/remove_mac under the hood

Migration: NOT a web endpoint (see §7 item 2's revision) -- `migrate_vpn_profiles.py`
(repo root, alongside main.py) is a standalone CLI with `preview` / `run` / `last-report`
subcommands, calling `migration_engine.py`'s `compute_report`/`apply_migration`/
`get_last_report` directly against the DB. Same matching algorithm, same
protected_from_auto_revoke guarantee, same persisted MigrationReport table -- just no
HTTP surface, no page, no permanent nav item for a task that runs once per deployment.
```

---

## 7. Decisions

1. **API-permission shape** (§1.2): **confirmed — object+scope model.** §1.2 stands as
   written, no free-text URL/method ACL.
2. **Migration trigger**: originally built as an admin-clicked web page with a mandatory
   preview step first (§6's `/api/admin/migration/*` endpoints, a `roles.html`-style
   page, a permanent "VPN/User Migration" nav item). **Revised after review**: a task
   that runs once per deployment doesn't earn permanent nav real estate that sits there
   forever after it's been used — moved to `migrate_vpn_profiles.py`, a standalone CLI
   script (`preview` / `run --yes` / `last-report` subcommands) run manually via
   `docker compose exec app python migrate_vpn_profiles.py run`. Same safety properties
   preserved: `run` always shows the full preview and requires an explicit `yes`
   confirmation (or `--yes` to skip it non-interactively) before writing anything, and
   the same `protected_from_auto_revoke` guarantee applies unchanged. No web
   route/page/nav-item exists for this anymore -- `routes/migration.py`, `migration.html`,
   and the nav link were removed; the matching/write logic that used to live in the route
   handler now lives in `migration_engine.py`, imported by both the CLI script and
   (implicitly, via that shared module) any future caller that needs it.
3. **Temp password delivery** for auto-created self-service accounts (migration §5, and
   the `add_client` hook in §4): defaulting to **shown once in the admin UI immediately
   after creation** (same pattern as e.g. showing an API key once) — a VPN client record
   has no email on file (`add_client`'s signature is just `name`+`mac`), so there's
   nothing to email to automatically. The admin relays it out-of-band. **Flagging this as
   an assumption, not a confirmed answer** — say so if you want emailing wired in
   instead (would need collecting an email at creation/migration time first).
4. **`vpn_profiles` "create" permission for `vpn_self_service`**: defaulting to **no
   self-enrollment** — a VPN profile is always admin-provisioned first (via the existing
   Add Client flow); self-service only ever views/updates a profile that already exists
   and is linked to them. **Also flagging as an assumption** — your spec's "My VPN
   Profile" section only lists view/update, never create, which is what this default is
   based on.

Both flagged assumptions are cheap to flip later (they gate a UI affordance and a
notification path, not the schema), so implementation proceeds on these defaults now;
correct me before I build those two specific pieces if either default is wrong.
