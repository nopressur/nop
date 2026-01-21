# CSRF Protection

Status: Developed

## Objectives

- Prevent cross-site request forgery on state-changing endpoints.
- Tie CSRF protection to authenticated sessions without hardcoding admin paths.
- Keep CSRF behavior consistent across dev and production modes.

## Technical Details

### Components

- `csrf_helper.rs` defines `CsrfTokenStore`, the single source of truth for CSRF tokens.
- `csrf_helper.rs` also provides `issue_csrf_token` so login and admin token endpoints share the
  same JWT/dev-mode resolution logic.
- `csrf_validation.rs` provides validation helpers (`validate_csrf_token`, `CSRF_HEADER_NAME`, `mark_csrf_validated`).
- `csrf_middleware.rs` wires CSRF validation into Actix middleware.

### Token Model

- Tokens are UUID strings stored server-side and mapped to a JWT ID.
- Tokens expire after one hour; successful validation refreshes the timestamp.
- Token issuance and validation are driven by `CsrfTokenStore`.
- `CsrfTokenStore` uses a single-writer channel worker so token mutations never rely on shared locks.
- Token endpoints return `expires_in_seconds` so clients can refresh before expiry.
- WebSocket tickets are short-lived (20 seconds), single-use tokens tied to the same JWT ID and
  designed for authenticated upgrade flows. The ticket store uses the same single-writer pattern.
  The admin SPA ticket exchange is documented in `docs/admin/ui.md`.

### Validation Flow

1. Mutating requests (POST/PUT/PATCH/DELETE) include `X-CSRF-Token`.
2. `CsrfValidationMiddleware` validates the token and marks the request as CSRF-validated for downstream handlers.
3. Invalid or missing tokens return HTTP 400/403 with warnings logged.

### JWT ID Resolution

The middleware resolves the JWT ID using this priority:

1. JWT claims in the request extensions (`jti`).
2. Dev-mode localhost fallback (`"localhost"`) when dev mode is enabled in debug builds and the request originates from loopback (release builds ignore `dev_mode`).
3. Unauthenticated, non-dev requests skip CSRF validation entirely (auth middleware blocks these routes).

### Exempt Endpoints

- Exempt routes are template-based and resolved at startup with the configured admin path.
- Default exemptions:
  - `POST <admin_path>/csrf-token-api`
  - `POST /login/csrf-token-api`
  - `POST /login`
  - `POST /login/bootstrap`
  - `POST /login/pwd/email`
  - `POST /login/pwd/password`
  - `POST /login/logout-api`
  - `POST /login/oidc/callback`
- Read-only verbs (GET/HEAD/OPTIONS) are always exempt.

### Dev Mode Behavior

- When `dev_mode: "localhost"` is active in debug builds, CSRF protection remains enabled (release builds ignore `dev_mode`).
- The token endpoint issues tokens under the `"localhost"` JWT ID.
- CSRF validation still occurs for state-changing requests, providing realistic coverage during local testing.

### Error Handling and Diagnostics

- Missing CSRF store in app data results in a 500-style error response with a logged error.
- Common failure messages include:
  - "CSRF token required"
  - "CSRF token validation failed"
- Logs include dev-mode markers ("DEV MODE") to highlight bypass contexts.

### Configuration and Initialization

- CSRF exemptions are configured at startup by `CsrfTokenStore::new`, which expands `{ADMIN_PATH}` templates.
- `CsrfTokenStore` is injected via Actix `web::Data` for use by middleware and handlers.
- Admin path configuration (`config.admin.path`) drives CSRF token endpoint resolution.

### Usage Notes

- Handlers behind the CSRF middleware should assume CSRF validation has already run and avoid manual token checks.
- Avoid adding exemptions except for authentication bootstrap routes.
- Login endpoints are unauthenticated and exempt from CSRF; profile endpoints (`/profile/*`)
  require JWT + CSRF.
- The login/profile SPA uses `POST /login/csrf-token-api` after authentication to obtain a
  CSRF token for profile updates. Both SPAs share cache behavior: refresh before expiry, retry
  once on 403, and clear the cache when profile flows refresh JWTs.

### Admin SPA Integration

- The admin SPA is the primary consumer of CSRF tokens and WebSocket tickets. The UI flow, endpoint
  usage, and auth-frame requirements are documented in `docs/admin/ui.md`.

### Testing Expectations

- Integration tests attach CSRF tokens via `CsrfTokenStore::get_new_token`.
- Dev-mode tests can rely on the localhost JWT ID behavior to validate CSRF flows without real logins.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
