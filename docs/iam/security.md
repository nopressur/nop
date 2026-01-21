# IAM Security

Status: Developed

This document covers security controls that are specific to authentication and login flows.
Routing guards and filesystem safety are documented in `docs/infrastructure/network-security.md`
and `docs/infrastructure/filesystem-security.md`.

## Objectives

- Define IAM-specific lockout and return-path rules for login flows.
- Align the threat tracker with the async single-writer pattern used across the codebase.

## Login Lockouts and Threat Tracking

- `extract_client_ip(req, config)` resolves the caller IP, honoring
  `config.security.use_forwarded_for`. It inspects `X-Forwarded-For`, `X-Real-IP`, then falls back
  to `peer_addr`.
- `ThreatTracker` records suspicious behavior per IP (`ViolationRecord { count, last_violation,
  blocked_until }`) via a single-writer channel worker. Configuration knobs:
  - `max_violations`: number of detections before blocking.
  - `cooldown_seconds`: block duration.
- `record_violation(req, config, path)` submits an async command to increment the counter for path
  traversal violations, logs a warning, and blocks the IP when the threshold is exceeded.
- `record_login_failure(req, config, reason)` records failed login attempts using the same
  thresholds, without treating the reason as a request path.
- `is_ip_blocked(req, config)` queries the worker and returns a 404 if the IP is still cooling down.
- Login session issuance and usage rate limits are defined in `docs/iam/modular-login.md`.

## Auth Action Rate Limits

- Profile password salt/change, login CSRF token issuance, and admin WS ticket issuance are rate
- limited per IP and per user when available (both buckets are enforced).
- The `AuthActionLimiter` worker enforces limits for:
  - `POST /login/csrf-token-api`
  - `POST /profile/pwd/salt`
  - `POST /profile/pwd/change`
  - `POST <admin_path>/ws-ticket`
- The limits reuse `config.security.login_sessions` (`period_seconds`, `id_requests`,
  `lockout_seconds`) to keep auth throttles consistent; login/profile endpoints respond with
  `429` + `code=auth_rate_limited` when blocked.

## Login Return-Path Validation

- `validate_login_return_path(path, cache, config, allow_admin)` sanitizes post-login redirects:
  - Rejects scheme/host-prefixed values (must start with `/`, but not `//`).
  - Allows `/`, `/id/<hex>` content ID routes, or markdown aliases that exist in `PageMetaCache`.
  - Allows admin paths (root or subpaths) only for admin users.
- The hidden `return_path` field is rendered verbatim in the login form; validation happens on
  submission (see `docs/iam/modular-login.md` and `docs/iam/password-login.md`).

## Integration Notes

- Login handlers should call `is_ip_blocked` before validating credentials, and call
  `record_login_failure` on failed attempts.
- Treat the login return path as untrusted input and always run it through
  `validate_login_return_path` before issuing redirects.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
