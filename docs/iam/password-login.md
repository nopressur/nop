# Password Login (Argon2id)

Status: Developed

## Objectives

- Replace the current SHA-256 pre-hash + bcrypt verification with Argon2id using per-user salts
  and configurable parameters.
- Move password login into the modular login SPA so the flow is a reusable provider.
- Use a two-phase login to fetch the front-end salt before computing the hash client-side.
- Keep a double-hash storage model so the front-end hash is never stored or replayable.
- Preserve the shared JWT issuance and middleware behavior across all login methods.

## Technical Details

### Argon2id Two-Phase Login

#### Flow overview

1. **Email**: Client submits the email address (with `login_session_id`) to obtain the front-end salt.
2. **Hash**: Client computes Argon2id using the supplied front-end salt and standard defaults.
3. **Password**: Client submits the front-end hash to the server, which validates and issues JWT.

#### Provider endpoints

- `POST /login/pwd/email` -> `PasswordEmailResponse { front_end_salt }`
  - Return the same response shape for unknown users to avoid enumeration.
  - Argon2id parameters are standard defaults; the API does not return params.
- `POST /login/pwd/password` -> standard login completion response (JWT cookie + redirect).
  - Payload includes `login_session_id`, `email`, and `front_end_hash`.
- Future steps may extend the flow without breaking this contract:
  - `POST /login/pwd/totp` for second-factor verification.
  - Each step requires the `login_session_id` issued by `/login/bootstrap` and rejects expired IDs.

#### Password Provider Request/Response Drafts

```json
// POST /login/pwd/email
{
  "login_session_id": "lsn_6x0bH3c5fWw1y1oNh7D4GQ",
  "email": "admin@example.com"
}
```

```json
// 200 response
{
  "front_end_salt": "9a9d2c0d8f0c4d3d8c84f3b8778c4a6e",
  "expires_in_seconds": 600
}
```

```json
// POST /login/pwd/password
{
  "login_session_id": "lsn_6x0bH3c5fWw1y1oNh7D4GQ",
  "email": "admin@example.com",
  "front_end_hash": "2ab5c7ef8e3c0fb6f4f1a83f92b0d4d59e3b6a8d2b43f1c9f08f7e0a1c9b3f77"
}
```

```json
// 401 response (no auth hash or invalid credentials)
{
  "code": "invalid_credentials",
  "message": "Invalid email or password."
}
```

#### Hash format and storage

- Client computes `front_end_hash = Argon2id(password, front_end_salt, default_params)`.
- Server computes `stored_hash = Argon2id(front_end_hash, back_end_salt, default_params)` and stores
  the Argon2id PHC string (includes salt and parameters).
- `users.yaml` groups credentials by provider module. Each user has core identity fields plus
  per-provider blocks (for example `password`, `oidc`, `email`). The password block stores
  front-end and back-end salts plus the server-side stored hash; Argon2id parameters are standard
  defaults and may be stored for auditing.
- Config includes Argon2id parameter defaults (memory, iterations, parallelism, output length)
  under `config.users.local.password` for both steps. The frontend uses the standard defaults;
  parameters are not sent over the wire.
  - Front-end defaults: `memory_kib=65536`, `iterations=2`, `parallelism=1`, `output_len=32`,
    `salt_len=16`.
  - Back-end defaults: `memory_kib=131072`, `iterations=3`, `parallelism=2`, `output_len=32`,
    `salt_len=16`.
- `front_end_hash` and the front/back-end salts are validated as hex strings with exact lengths
  derived from the configured `output_len`/`salt_len` values (lengths are doubled for hex).
- Front-end and back-end salts are generated automatically; clients never supply Argon2 parameters.
- Manual user creation must run the same two-step hashing server-side: compute the front-end hash
  from the raw password, then compute the stored hash.
- Users without an auth hash (email/name only) are not allowed to authenticate; login attempts
  must fail and log a warning that the user has no auth tokens.
- On the first update of a user, remove any legacy password fields and write the provider
  sub-blocks instead.

Example password provider block in `users.yaml`:

```yaml
password:
  front_end_salt: "9a9d2c0d8f0c4d3d8c84f3b8778c4a6e"
  back_end_salt: "e7b2f1c44b0d4e9aa5c92f6f3a4f8d11"
  stored_hash: "$argon2id$v=19$m=131072,t=3,p=2$e7b2f1c44b0d4e9aa5c92f6f3a4f8d11$C1uFZTF3L2OU1h3zGfU4vQh96Wc3VQqj7/7Wv/5yM8w"
```

#### Hashing utilities

- Password hashing is centralized in helper utilities so all callers follow the same two-phase
  flow. These helpers are used by login verification, profile password changes, user management,
  and auto-bootstrap.
- Required helpers:
  - `derive_front_end_hash(password, front_end_salt, params)` - Phase 1 Argon2id.
  - `derive_back_end_hash(front_end_hash, back_end_salt, params)` - Phase 2 Argon2id (stored hash).
  - `verify_front_end_hash(front_end_hash, stored_hash)` - Compares Phase 1 output against the stored
    back-end hash.
  - `build_password_provider_block(password)` - Generates new front-end + back-end salts/params,
    derives both phases, and returns the password provider block for `users.yaml`.
  - `params` are the standard defaults from configuration; callers do not pass custom values.
- User management and auto-bootstrap call `build_password_provider_block` when they have access to
  the plaintext password.
- Login verification and profile password changes call `verify_front_end_hash` and
  `derive_back_end_hash` with the Phase 1 hash supplied by the SPA. Profile password changes use
  salts issued by `/profile/pwd/salt` (see `docs/iam/modular-profile.md`).

#### Management bus password operations

- The user store is only accessed through the management bus; password login and admin workflows
  request salts and validation via management actions instead of reading `users.yaml` directly.
- Standard Argon2id parameters are used for all flows; requests do not carry params.
- Required management bus actions:
  - **PasswordSalt**: returns `current_front_end_salt` and `next_front_end_salt` for the target
    user. Login uses the current salt; resets/updates use the next salt. Includes a `change_token`
    for replay protection.
  - **PasswordValidate**: accepts a front-end hash, applies back-end hashing, and reports whether
    it matches the stored credential. Used by login.
  - **PasswordUpdate**: accepts the current front-end hash, the new front-end hash, and the new
    front-end salt; validates the current password, generates a new back-end salt, and stores the
    new credentials. Used by profile updates.
  - **PasswordSet**: accepts plaintext passwords (CLI/bootstrap) or a UI payload with a front-end
    hash + salt, generates a back-end salt, and stores the new credentials. UI payloads must
    include the `change_token` issued by **PasswordSalt**. Used by admin resets.
  - `/login/pwd/email` uses **PasswordSalt** and `/login/pwd/password` uses **PasswordValidate** so
    the login provider never reads the user file directly.

#### Legacy accounts

- Legacy bcrypt-of-SHA-256 hashes are ignored; users must reset their password via CLI or admin
  user management to receive Argon2id credentials.

#### Security considerations

- Treat the front-end hash as a password-equivalent secret; require HTTPS and never log it.
- The stored hash must never be accepted as an authentication input; only the front-end hash is
  verified, and it is re-hashed server-side to prevent replay.
- `login_session_id` must be short-lived, rate-limited, and bound to client IP or a signed
  nonce to prevent replay across clients.
- Failed verification must record a violation via `record_login_failure` and honor lockout behavior
  (see `docs/iam/security.md`).

#### SPA integration

- The password provider is a module in the login SPA and uses shared UI components for email
  entry, errors, and progress states.
- Hashing runs client-side via a dedicated Argon2id implementation (WASM or native), and the
  module reports progress to the UI using the standard Argon2id defaults.

### Testing Scope

- Unit tests for Argon2id hashing and verification helpers, including parameter validation.
- Integration tests for the email/password endpoints, including lockout behavior and JWT issuance.
- Tests for accounts with missing auth hashes (reject login, log warning).
- SPA unit tests for the password provider steps and error handling.
- Playwright coverage for multi-step password login, including invalid credentials and lockouts.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
