# Modular Login

Status: Developed

## Objectives

- Replace the current server-rendered login UI with a small Svelte SPA that can be reused across
  login surfaces.
- Support multiple login providers (password, OIDC, OAuth, email-based, future) without rewriting
  shared UI or backend glue.
- Keep all login flows converging on a single JWT issuance and request-authentication pipeline.
- Provide a clean, extensible architecture on both frontend and backend with explicit contracts
  and testable boundaries.

## Technical Details

### Modular Login SPA + Provider Framework

#### Login SPA shell

- Serve a dedicated login SPA shell template that mounts a Svelte app into a single root element.
- The shell embeds a runtime config object that includes `loginPath`, `appName`, and a
  `returnPath` (if supplied by the caller).
- The SPA is intentionally small: it covers login, authentication setup, and profile management, but not the admin UI.
- The SPA must call the bootstrap endpoint whenever a new login flow starts to obtain a fresh
  `login_session_id`.
- Provider availability is embedded in the HTML shell so the SPA can render options before calling
  bootstrap. Use MiniJinja JSON-safe rendering (for example, a `tojson` filter or a
  `Value::from_serializable` payload in a `<script type="application/json">` block) to avoid XSS.
- The login page accepts a `return_path` query parameter; the shell passes it into the SPA config
  so the SPA can include it in the bootstrap request and rely on the validated return path from
  the response.
- The shell embeds Argon2id front-end parameters from `config.users.local.password.front_end` so
  the SPA can hash locally without calling a params endpoint.
- The SPA must validate that the return path is same-origin and path-only before sending it, and
  must use the validated return path from the bootstrap response for all provider flows.
- Profile behavior, routes, and provider modules are documented in `docs/iam/modular-profile.md`.

#### Provider registry (backend)

- Introduce a provider registry that exposes provider metadata and wires provider endpoints under
  `/login/<provider>/...`.
- Each provider exposes a stable ID and its own workflow; the registry resolves provider IDs to
  handler implementations.
- Providers are responsible for identity proof, but never issue JWTs directly. They return a
  verified identity to the login orchestrator, which issues the JWT (see
  `docs/iam/auth-middleware.md`).

#### Login session orchestration

- Login is a provider-owned, multi-step handshake:
  - Each provider defines its own endpoints under `/login/<provider>/...`.
  - Every provider endpoint requires `login_session_id` issued by `/login/bootstrap` and treats it
    as mandatory input for request validation.
  - Providers may use `login_session_id` as OAuth/OIDC `state` values for callback validation.
  - Session state must be short-lived, bound to client IP, and rate-limited to mitigate abuse.
- Providers must keep responses shape-consistent to avoid account enumeration.
- If a session ID is expired or invalid, return a typed error and the SPA must return to the main
  login page and call `/login/bootstrap` again.

#### Provider UI modules (frontend)

- The login SPA defines a small provider API:
  - `id`, `label`, `routes`, and `entryComponent` for each provider.
  - Shared components for email entry, error states, loading, and return-path handling.
- Provider UI modules live under `nop/ts/login/src/providers/` (new workspace), each exporting
  their route definitions and step components.
- The app shell wires providers into a router and a shared `loginClient` service for API calls.
- Tailwind defines the visual system for the login SPA to stay aligned with the admin UI.

#### Build pipeline and embedding

- The login SPA builds into a versioned directory under `nop/builtin/` (for example
  `nop/builtin/login-<hash>/`) so `build.rs` can embed the assets into the release binary
  alongside other builtin files.
- Use stable filenames inside the versioned directory (`login.js`, `login.css`) while the
  directory name itself is randomized per build (for example `login-<hash>`). This keeps
  URLs cache-safe without needing a manifest.
- The version hash is derived from the Unix millisecond epoch, hashed with SHA-256 and truncated
  to the first eight hex characters.
- The login shell template receives the versioned directory name and injects asset URLs like
  `/builtin/login-<hash>/login.js` and `/builtin/login-<hash>/login.css`.
- Serve the login HTML with `Cache-Control: no-store` while allowing versioned assets to use long
  cache lifetimes (`immutable`).

#### API contracts (shared)

- `POST /login/bootstrap` returns a new `login_session_id`. This is called each time the SPA
  starts a fresh login flow.
- Login and profile endpoints return errors using `{ "code": "...", "message": "..." }` so the SPA
  can handle failures consistently.
- Provider-specific endpoint contracts are documented in their provider documents (for example,
  `docs/iam/password-login.md`). The framework does not force a uniform step schema or endpoint
  naming, but all provider endpoints must end in shared JWT issuance.

#### JWT convergence

- All providers must funnel into the same JWT issuance path; no provider issues cookies directly.
- The auth middleware is the single request-time source of truth for user identity and refresh
  logic (see `docs/iam/auth-middleware.md`).

### Login Session Store and Rate Limits

- Maintain an in-memory `LoginSessionStore` with a bounded size, TTL cleanup, and write operations
  funneled through an async channel to avoid contention (single-writer, multi-reader).
- Session IDs must be non-sequential, opaque, and easy to validate (for example, 128-bit random
  values encoded as base64url). Reject malformed or unknown IDs.
- Session TTL: 10 minutes. Expired IDs are rejected and require a fresh `/login/bootstrap`.
- The TTL constant is shared with login responses so `expires_in_seconds` matches the store policy.
- Rate limits:
  - **Issuance limit**: throttle `/login/bootstrap` per IP (existing request-based lockouts apply).
  - **Session usage limit**: each successful use of a `login_session_id` increments a per-IP
    counter; defaults to 5 session IDs per 5 minutes, blocking for 10 minutes.
  - Limits are configurable (window, max count, block duration).
- When blocked, return a `429` with a machine-readable code so the SPA can show a polite “login is
  currently unavailable, please try again later” screen.
- Configuration lives under `config.security.login_sessions`:
  - `period_seconds` (default 300)
  - `id_requests` (default 5)
  - `lockout_seconds` (default 600)

### Bootstrap and Error Response Drafts

```json
// POST /login/bootstrap (request)
{
  "return_path": "/admin"
}
```

```json
// POST /login/bootstrap
{
  "login_session_id": "lsn_6x0bH3c5fWw1y1oNh7D4GQ",
  "expires_in_seconds": 600,
  "return_path": "/admin"
}
```

```json
// 429 response (rate limited)
{
  "code": "login_rate_limited",
  "message": "Login is temporarily unavailable. Please try again later."
}
```

```json
// 400/401 response (expired or invalid session)
{
  "code": "login_session_expired",
  "message": "Login session expired. Please start again."
}
```

### Testing Scope

- Provider registry unit tests for registration, metadata, and error handling.
- Integration tests for multi-step login session orchestration.
- End-to-end tests for each provider using Playwright (password, OIDC mock, email code).
- SPA unit tests for provider modules, router guards, and shared components.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
