# Authentication Middleware and JWT Lifecycle

This document describes the JWT issuance contract and the request-time authentication middleware
used across public and admin surfaces. Login flows feed into this pipeline, but do not replace it
(see `docs/iam/authz-authn.md`).

## Components

- `jwt::JwtService` creates and refreshes JWTs and builds auth cookies.
- `JwtAuthMiddleware` validates JWTs on every request and injects auth context.
- `AuthRequest` provides helpers for handlers (`user_info`, `has_group`, `jwt_id`).
- `RequireAdminMiddleware` gates admin routes based on `has_group("admin")`.

## JWT Issuance

- Login providers call `JwtService::create_token(email, user)` after identity verification.
- Tokens embed: `sub` (email), roles, expiry, `jti`, and `password_version`.
- `create_auth_cookie` issues the HTTP cookie (`cookie_name`, default `nop_auth`).

## Middleware Flow

- `JwtAuthMiddleware` reads the auth cookie and verifies the JWT signature and claims.
- On success, it stores `Claims` and `User` in request extensions for downstream handlers.
- If `password_version` in the token does not match the current user record, the request is
  rejected and the token is considered invalid.
- Refresh behavior:
  - `should_refresh_token` checks percentage and absolute thresholds.
  - `create_refreshed_token` issues a replacement cookie attached to the response.

## Cookie and Session Rules

- Auth cookies are HttpOnly with `SameSite=Lax`.
- The secure flag is enabled outside localhost.
- Logout clears the auth cookie and removes CSRF tokens bound to the JWT ID.

## Request Context Helpers

- `req.user_info()` returns `Option<User>` for route handlers.
- `req.has_group("admin")` drives admin gating and UI decisions.
- `req.jwt_id()` exposes the `jti` claim for CSRF binding.
- WebSocket admin sessions derive the acting user identity from the authenticated JWT and bind it
  server-side; management requests never include identity fields from the client.

## Profile Menu API

`GET /api/profile` returns the authenticated status and any user-menu links. This endpoint is the
only source of user menu links for the public site; public HTML never embeds profile/admin links.

Response shapes:

```json
// Unauthenticated
{
  "authenticated": false
}

// Authenticated (non-admin)
{
  "authenticated": true,
  "display_name": "<user display name>",
  "menu_items": [
    { "key": "profile", "label": "Profile", "href": "/login/profile" },
    { "key": "logout", "label": "Logout", "href": "/login/logout-api", "method": "POST" }
  ]
}

// Authenticated (admin)
{
  "authenticated": true,
  "display_name": "<user display name>",
  "menu_items": [
    { "key": "profile", "label": "Profile", "href": "/login/profile" },
    { "key": "admin", "label": "Admin", "href": "<admin_path>" },
    { "key": "logout", "label": "Logout", "href": "/login/logout-api", "method": "POST" }
  ]
}
```

Notes:
- `menu_items` is only present when `authenticated: true`.
- `display_name` is only present when `authenticated: true` and matches the user's display name.
- The `admin` item is only present when the user has the `admin` role.
- `method` is included only when the action requires a non-GET request.
- Responses are served with `Cache-Control: no-store, private` and `Vary: Cookie`.

## Configuration

- `config.users.local.jwt`:
  - `secret`, `issuer`, `audience`, `expiration_hours`.
  - `cookie_name` for the auth cookie.
  - `disable_refresh`, `refresh_threshold_percentage`, `refresh_threshold_hours`.
- `dev_mode` affects auth in debug builds only (release builds ignore it and log a warning):
  - `Dangerous` bypasses auth checks (local-only).
  - `Localhost` allows unauthenticated admin access from loopback addresses while still logging.

## CSRF Integration

- CSRF tokens are bound to JWT IDs; `req.jwt_id()` is the authoritative link.
- Login flows should not bypass the middleware. All post-login requests rely on JWT + CSRF
  validation (see `docs/infrastructure/csrf-protection.md`).

## Integration Notes

- All login providers must funnel into this JWT pipeline; do not mint custom cookies.
- When adding new handlers, use `AuthRequest` instead of reparsing cookies.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
