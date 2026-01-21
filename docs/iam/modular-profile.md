# Modular Profile

Status: Developed

## Objectives

- Move the profile editor into the login SPA so authentication and profile workflows share a single shell.
- Provide core profile fields (email read-only, name editable) plus a modular area for auth providers.
- Require CSRF + JWT for all profile APIs and keep return-path handling consistent with login.
- Allow future auth providers to expose their own profile modules without reworking the shell.

## Technical Details

### Profile SPA shell

- `/login/profile` serves the login SPA shell (MiniJinja template) with an initial route pointing to the profile view.
- The shell embeds `appName`, `loginPath`, `profilePath`, `profileApiPath`, `csrfTokenPath`, and
  `returnPath` (if supplied). The profile view uses the validated return path when the user clicks Back.
- The login SPA CSRF client refreshes tokens before expiry, retries once on 403 by clearing the cached token, and clears the cache after profile/password updates refresh the JWT.
- Enabled providers are embedded in the shell so the SPA can render profile modules without an extra bootstrap call (see `docs/iam/modular-login.md`).

### Core profile form

- The profile view contains a core profile form with:
  - Email (read-only; not changeable in this release).
  - Full name (editable; validated and sanitized on the server).
    - Validation: 2..256 characters, Unicode allowed; control characters are stripped and
      whitespace is collapsed.
- API contract:
  - `POST /profile/update`
  - Requires JWT and CSRF token.
  - Payload: `{ "name": "Display Name" }`
  - Response: `{ "success": true, "message": "Profile updated successfully" }`
- Error response: `{ "code": "invalid_request", "message": "Profile update failed." }`
- The backend dispatches profile name updates through the management bus (`users.change`)
  so profile mutations follow the same domain rules as admin/CLI updates.

### Provider modules (profile)

- Each enabled auth provider supplies a profile module registered with the profile router.
- Modules are collapsed by default and revealed by an explicit action (for example, a Change button).
- Each module owns its own form and submit lifecycle; cancelling re-collapses the module without submitting.
- Modules should reuse shared form components and error handling from the login SPA.

### Password profile module

- The password module renders a Change button that reveals a dedicated form with:
  - Current password
  - New password
  - Confirm new password
  - Cancel + Save actions
- Salt preflight:
  - On first reveal, the module calls `POST /profile/pwd/salt` to fetch the front-end salts for
    the current password verification and the next password. Argon2id parameters use standard
    defaults and are not returned by the API.
  - The backend obtains the current front-end salt through the management bus so `users.yaml`
    is never accessed directly.
  - Salts are generated automatically by the backend and invalidated after use or expiry.
  - Requires JWT and CSRF token.
  - Response payload example:
    ```json
    {
      "change_token": "pc_6x0bH3c5fWw1y1oNh7D4GQ",
      "current": { "front_end_salt": "..." },
      "next": { "front_end_salt": "..." },
      "expires_in_seconds": 600
    }
    ```
  - Error response: `{ "code": "password_salt_failed", "message": "Unable to fetch password salts." }`
  - The SPA caches the response while the page is open; if the user cancels and re-opens the module, the cached salts are reused.
  - Password fields are cleared after each submission attempt (success or error) to avoid lingering sensitive values.
  - The backend invalidates `change_token` after a successful password change or when the TTL expires.
- Password change:
  - `POST /profile/pwd/change`
  - Requires JWT and CSRF token.
  - Payload:
    ```json
    {
      "change_token": "pc_6x0bH3c5fWw1y1oNh7D4GQ",
      "current_front_end_hash": "...",
      "new_front_end_hash": "...",
      "new_front_end_salt": "..."
    }
    ```
  - Error response: `{ "code": "password_update_failed", "message": "Password update failed." }`
- The client computes `current_front_end_hash` and `new_front_end_hash` using the Phase 1 hashing
  described in `docs/iam/password-login.md` and the SPA-configured
  `config.users.local.password.front_end` parameters.
  - The backend verifies the current hash and then stores the new password using the Phase 2 hashing helpers described in `docs/iam/password-login.md`.
  - The backend validates the `change_token` and that `new_front_end_salt` matches the preflight
    response, generates a new back-end salt, and stores both salts with the updated hash.
  - On success, the auth cookie is refreshed so `password_version` is up to date.

### Back navigation

- The profile view exposes a Back action for the whole page that returns the user to `returnPath`.
- `returnPath` is validated server-side using the same rules as login return-path validation
  (see `docs/iam/security.md`).

### Testing Scope

- Unit tests for profile update validation and password change verification.
- SPA tests for the core profile form and password module reveal/hide behavior.
- Playwright coverage for profile editing and password change flows.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
