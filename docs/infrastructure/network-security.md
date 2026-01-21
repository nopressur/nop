# Network and Routing Security

This document covers request routing guards and well-known route handling in `nop/src/security/`.
Login lockouts and threat tracking are documented in `docs/iam/security.md`.

## Route Validation

- `route_checks(path, req, config)` is the primary guard for public routes:
  - URL-decodes the path and rejects any containing `./` or `../`.
  - Denies direct `.md` requests (case-insensitive).
  - Records violations when request/context is provided (see `docs/iam/security.md`).
- `route_checks_legacy` is a context-free wrapper for places that cannot provide `HttpRequest`
  (kept for backwards compatibility).

## Well-Known Routing

- `/.well-known/*` routes are served by listeners with role `well-known` and resolved via in-memory
  handlers.
- ACME HTTP-01 tokens are served from an in-memory token store registered with the well-known
  handler registry.
- No filesystem reads/writes are permitted for well-known responses; unknown paths return 404.

## Integration Notes

- Place `route_checks` as early as possible in public handlers to drop suspicious paths before
  further processing.
- These helpers return public-facing error pages; for API routes, prefer explicit error formats
  per handler.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
