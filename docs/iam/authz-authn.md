# Authentication & Authorization Internals

This document explains how NoPressure authenticates users and evaluates roles across the public
and admin surfaces. JWT lifecycle and middleware behavior are documented in
`docs/iam/auth-middleware.md`.

## Components

- `login/` – HTTP routes and SPA shells for logging in, logging out, and updating profiles (`local.rs`, `oidc.rs` placeholder).
- `iam/` – Core services for user lookup (`IamService`), JWT management (`jwt::JwtService`), and
  high-level orchestrator (`UserServices`).
- `util::CsrfTokenStore` – Couples CSRF tokens to JWT IDs; logout routes clear associated tokens.

## Authentication Flow (Local, Modular Login SPA)

This section documents the current SPA-driven login flow described in
`docs/iam/modular-login.md` and `docs/iam/password-login.md`.

1. **Login shell GET** – `/login` (and `/login/profile`) renders the SPA shell with runtime config,
   available providers, and the optional `return_path`.
2. **Bootstrap** – `POST /login/bootstrap`:
   - Validates the client IP is not blocked (`security::is_ip_blocked`).
   - Issues a `login_session_id` with a short TTL and optional validated return path.
3. **Password salt** – `POST /login/pwd/email`:
   - Requires `login_session_id` + `email`.
   - Uses the management bus (`users.password_salt`) to fetch the current front-end salt.
   - Returns the same response shape for unknown users to avoid enumeration.
4. **Password submit** – `POST /login/pwd/password`:
   - Requires `login_session_id`, `email`, and `front_end_hash` (Argon2id phase 1).
   - Uses the management bus (`users.password_validate`) to validate credentials.
   - On success, `JwtService::create_token` issues the auth cookie and returns JSON
     `{ return_path }`.
   - Return path logic:
     - When `return_path` is provided, `security::validate_login_return_path` only allows `/`,
       `/id/<hex>` content ID routes, or markdown aliases that exist in `PageMetaCache`. Admin users
       may also return to valid admin paths (admin root or subpaths). Any scheme/host-prefixed or
       invalid values default to `/`.
     - When `return_path` is absent, admins default to `config.admin.path`; everyone else goes to `/`.
5. **Login failure** – Logs a violation (`record_login_failure`) to throttle repeated attempts and
   returns a typed JSON error.
6. **Logout** – `POST /login/logout-api` clears CSRF tokens (`cleanup_tokens_for_jwt_id`) and
   sets the logout cookie (expires immediately).

OIDC paths are scaffolded (`login/oidc.rs`) but currently return 404; startup also rejects OIDC configuration.

## JWT Issuance and Middleware

- Login flows call `JwtService::create_token` after identity verification and issue the auth cookie.
- Request-time authentication, refresh, cookie rules, and auth helpers live in
  `docs/iam/auth-middleware.md`.
- JWT claims include `password_version` for password-change revocation; legacy tokens that omit it
  default to version `1`, matching the `users.yaml` default.

## Updated Requirements: Modular Login and Password Login

- Modular login architecture, provider contracts, and SPA requirements live in
  `docs/iam/modular-login.md`.
- Modular profile routes, provider modules, and profile APIs live in
  `docs/iam/modular-profile.md`.
- The two-phase Argon2id password login flow is defined in `docs/iam/password-login.md`.
- Password login and profile updates retrieve salts and validation via the management bus so
  `users.yaml` is never accessed directly.

## Authorization & Roles

- IAM consults the public content model when authorizing access to public routes. `PageMetaCache` is
  the systemwide source of content metadata and role requirements; it is the authoritative cache
  for access checks.
- Available roles are sourced from the role store (`roles.yaml`) and are documented in
  `docs/content/role-management.md`. Admin UI pickers fetch them via the roles management domain.
- User role membership is still defined per user in `users.yaml` and is embedded in JWTs.
- `PageMetaCache::user_has_access` enforces tag-based RBAC:
  - Resolves effective roles from the object's tags.
  - Checks if the user has at least one resolved role.
- Public handlers rely on `req.user_info()` for gated navigation; admin handlers use it for bootstrap data
  (for example, current user email) and authorization checks.
- Admin WebSocket management sessions bind the authenticated user to the connection; server-side
  management handlers treat that session identity as authoritative for actor checks.
- For exhaustive RBAC examples and edge cases, see `docs/content/public-rbac.md`.
- Role lifecycle, validation, and CRUD behavior live in `docs/content/role-management.md`.

### Content RBAC Model (Tag-Based)

- **Tag roles** gate access for content objects. Objects do not define roles directly.
- **Access rules** are defined on tags:
  - `intersect` is the default when unspecified.
  - `union` is optional.
  - If any tag sets `intersect`, intersect rules apply across the full tag set.
  - If no tag sets `intersect` but at least one tag sets `union`, union rules apply.
- **Resolved roles** are computed per object and stored in `PageMetaCache` for fast checks.
- **Empty role set** means the object is inaccessible to all users (no public fallback).
- **No tags** means the object is public.
- **Operational tips**:
  - Keep role lists short and re-use canonical names (`editors`, `managers`).
  - Monitor logs for RBAC warnings and tag misconfiguration.
  - When bulk-updating content outside the admin UI, rebuild the cache (restart or expose a maintenance endpoint) so new permissions take effect.

## Configuration

- `config.users.auth_method` – `local` (implemented) or `oidc` (TODO).
- `users.yaml` lives at the runtime root and is wired in via `RuntimePaths` during `UserServices::new`.
- JWT configuration and `dev_mode` behavior are documented in `docs/iam/auth-middleware.md`.

## Users YAML

- Stored under `<runtime-root>/users.yaml` (copy from `examples/users.yaml.example` or let auto-bootstrap generate it). Each entry contains:
  - `email`, `name`, password provider data (see `docs/iam/password-login.md`), `roles` (array of
    strings), `password_version` (u32, starts at 1 and increments on password changes).
- User roles are validated against `roles.yaml` (see `docs/content/role-management.md`).
- `UserServices::add_user/update_user/delete_user` mutate this file via `IamService`, then refresh caches. Admin UI routes user changes through the management bus, which delegates to these services.
- If `password_version` is missing (legacy file), the loader assigns version `1` for all users,
  persists the updated file, and logs a warning.

## Integration Notes

- Always acquire `UserServices` from Actix `web::Data`. Role availability is sourced from
  `roles.yaml` via the role store, while access checks rely on `PageMetaCache`.
- User input validation for emails and names uses `security::validation` helpers to keep limits consistent.
- When adding new middleware or handlers, call `req.user_info()` instead of reparsing cookies
  (see `docs/iam/auth-middleware.md`).
- Ensure new JSON APIs under admin scope require CSRF tokens (see `docs/infrastructure/csrf-protection.md`).
- Tests can simulate auth by inserting `Claims` and `User` into request extensions or by using `JwtService` to generate real tokens.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
