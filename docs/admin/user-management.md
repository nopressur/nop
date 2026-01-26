# Admin User Management (WebSocket)

Status: Developed

## Objectives

- Move admin user management CRUD to the WebSocket management connector.
- Provide CLI user management via `nop user` subcommands through the management bus.
- Keep validation rules aligned across UI, CLI, and domain handlers.
- Preserve UI-only guardrails (password confirmation, delete confirmation, self-delete).
- Use the management bus for all reads and mutations (no direct IAM access).
- Implement the user management frontend module in TypeScript and compile to JS assets.
- Support incremental role mutations without replacing the full role list when requested.

## Technical Details

### Canonical Scope

- This document is the single source of truth for user management behavior and the management bus
  contract used by the admin UI and CLI.
- Admin session integration is documented in `docs/admin/ui.md`, with auth/CSRF internals in
  `docs/iam/authz-authn.md`, `docs/iam/auth-middleware.md`, and
  `docs/infrastructure/csrf-protection.md`.
- Management bus architecture and connectors live in:
  - `docs/management/architecture.md`
  - `docs/management/connector-socket.md`
  - `docs/management/connector-cli-bypass.md`
  - `docs/management/cli-architecture.md`

### Shared Field Rules (UI + CLI)

- `email`
  - Required; max 128 characters.
  - Full email validation in the domain module (reject invalid formats).
  - Normalized to lowercase for storage and comparisons (internal only).
- `name`
  - Required.
  - Length: 2..256 characters.
  - Allow Unicode (UTF-8); no ASCII-only sanitization.
  - Server sanitizes names by trimming, collapsing whitespace, and removing control characters.
- `password`
  - UI and CLI follow the password hashing contract in `docs/iam/password-login.md`.
  - Domain validates the submitted password payload using the shared hashing helpers and stores
    the password provider block (no hashing details are duplicated here).
  - Salts are generated automatically by the backend; callers never send Argon2id parameters.
  - Admin UI must submit `front_end_hash` + `front_end_salt` with a `change_token`; plaintext is
    reserved for CLI workflows.
- `roles`
  - Optional, max 64 entries.
  - Each role must exist in `roles.yaml` and follow role validation rules
    (`docs/content/role-management.md`).
- Confirm fields (password confirmation, delete confirmation) are UI/CLI workflows only and are not
  part of the management bus payloads.

### UI Field Controls (End State)

- `email`
  - Required for add; immutable identifier on edit.
  - UI accepts mixed case; domain normalizes internally for storage/comparison.
- `password`
  - Required for add; optional for update.
  - UI validates confirmation, then submits the password using the hashing flow in
    `docs/iam/password-login.md`.
- `password_confirm` (UI workflow only)
  - Must match `password` before submit.
  - Not sent to the management bus.
- `new_role`
  - Optional; same validation as `roles`.
- `delete_confirm` (UI workflow only)
  - UI requires the admin to re-enter the target email before deletion.
  - Not sent to the management bus.
- `self-delete`
  - UI must prevent the current user from deleting themselves.

### Management Bus Contract

- Domain ID (u32): `1` (Users).
- Action IDs (u32):
  - `1`: Add
  - `2`: Change
  - `3`: Delete
  - `4`: PasswordSet
  - `5`: List
  - `6`: Show
  - `7`: RoleAdd
  - `8`: RoleRemove
  - `9`: RolesList
  - `10`: PasswordSalt
  - `11`: PasswordValidate
  - `12`: PasswordUpdate
  - `101`: AddOk (response payload: `MessageResponse { message }`)
  - `102`: AddErr (response payload: `MessageResponse { message }`)
  - `201`: ChangeOk (response payload: `MessageResponse { message }`)
  - `202`: ChangeErr (response payload: `MessageResponse { message }`)
  - `301`: DeleteOk (response payload: `MessageResponse { message }`)
  - `302`: DeleteErr (response payload: `MessageResponse { message }`)
  - `401`: PasswordSetOk (response payload: `MessageResponse { message }`)
  - `402`: PasswordSetErr (response payload: `MessageResponse { message }`)
  - `501`: ListOk (response payload: `UserListResponse`)
  - `502`: ListErr (response payload: `MessageResponse { message }`)
  - `601`: ShowOk (response payload: `UserShowResponse`)
  - `602`: ShowErr (response payload: `MessageResponse { message }`)
  - `701`: RoleAddOk (response payload: `MessageResponse { message }`)
  - `702`: RoleAddErr (response payload: `MessageResponse { message }`)
  - `801`: RoleRemoveOk (response payload: `MessageResponse { message }`)
  - `802`: RoleRemoveErr (response payload: `MessageResponse { message }`)
  - `901`: RolesListOk (response payload: `UserRolesListResponse`)
  - `902`: RolesListErr (response payload: `MessageResponse { message }`)
  - `1001`: PasswordSaltOk (response payload: `PasswordSaltResponse`)
  - `1002`: PasswordSaltErr (response payload: `MessageResponse { message }`)
  - `1101`: PasswordValidateOk (response payload: `PasswordValidateResponse`)
  - `1102`: PasswordValidateErr (response payload: `MessageResponse { message }`)
  - `1201`: PasswordUpdateOk (response payload: `MessageResponse { message }`)
  - `1202`: PasswordUpdateErr (response payload: `MessageResponse { message }`)

### Requests/Responses

All requests and responses require a monotonic `workflow_id` per connection and echoed in responses.

- `UserAddRequest { email, name, password: PasswordPayload, roles, change_token: Option<String> }`
- `UserChangeRequest { email, name: Option<String>, roles: Option<Vec<String>> }`
- `UserRoleAddRequest { email, role }`
- `UserRoleRemoveRequest { email, role }`
- `UserRolesListRequest {} -> UserRolesListResponse { roles: Vec<String> }`
- `UserDeleteRequest { email }`
- `UserPasswordSetRequest { email, password: PasswordPayload, change_token: Option<String> }`
- `UserPasswordSaltRequest { email } -> PasswordSaltResponse`
- `UserPasswordValidateRequest { email, front_end_hash } -> PasswordValidateResponse { valid }`
- `UserPasswordUpdateRequest { email, current_front_end_hash, new_front_end_hash, new_front_end_salt, change_token }`
- `UserListRequest {} -> UserListResponse { users: Vec<UserSummary { email, name }> }`
- `UserShowRequest { email } -> UserShowResponse { email, name, roles }`

Password fields in management requests follow the hashing contract in
`docs/iam/password-login.md`. Front-end hash and salt fields must match the exact hex lengths
derived from `output_len`/`salt_len` (not just maximums).
`PasswordPayload` is a discriminated payload (JSON uses `kind`):
- UI payload: `{ "kind": "front_end_hash", "front_end_hash": "...", "front_end_salt": "..." }`
  (front-end hashing only; backend completes Phase 2).
- CLI payload: `{ "kind": "plaintext", "plaintext": "..." }`
  (backend performs both phases).
UI payloads require `change_token` from `users.password_salt` when used with `users.add` or
`users.password_set`.
Password helper responses:
- `PasswordSaltResponse { change_token, current_front_end_salt, next_front_end_salt, expires_in_seconds }`
- `PasswordValidateResponse { valid }`
`current_front_end_salt` is used for login/profile validation; `next_front_end_salt` is used for resets and updates. `users.password_validate` is intended for credential checks (login flows). `users.password_update` is intended for profile updates that include the current password. Admin resets should use `users.password_set`.
`change_token` is single-use and expires with the salt TTL; updates must echo it back to prevent replay.

### Read Operations

- `list` returns user summaries (`email`, `name`) only.
- `show` returns user details (`email`, `name`, `roles`) only; never return passwords.
- Admin UI and CLI must use the bus for list/show (no direct IAM access).

### Role Mutations

- `role_add` accepts a single role for a user without replacing the role list.
- `role_remove` removes a single role for a user without replacing the role list.
- `change` may still replace the full role list when explicitly requested (bulk operations).
- `roles_list` returns available roles from `roles.yaml` for UI pickers; no user data is included.

### User Mutation Rules

- `add`:
  - Fails if the user already exists.
  - Requires `name` and a valid password payload per `docs/iam/password-login.md`.
- `change`:
  - Requires at least one of `name` or `roles`.
  - `roles` replaces the existing role list when provided (full overwrite).
- `role_add`/`role_remove`:
  - Mutate a single role without replacing the full list.
- `password`:
  - Changes only the password of an existing user; accepts plaintext payloads for CLI and uses
    backend two-phase hashing (`users.password_set`).
  - Admin UI password resets should use `users.password_salt` + `users.password_set` with a UI payload.
  - Increments `password_version` in `users.yaml`, invalidating existing JWTs for that user.
- `delete`:
  - Fails if the user does not exist.
  - Rejects when the authenticated admin attempts to delete themselves (self-delete).

### Password Flow (UI vs CLI)

- Admin UI:
  - Calls `users.password_salt` with the target email to receive a new front-end salt and a change token.
  - Computes `new_front_end_hash` using standard defaults.
  - Submits `users.password_set` with `{ front_end_hash, front_end_salt }` and the `change_token`.
  - For user creation, the same salt + hash flow is used and the `change_token` is attached to `users.add`.
  - The admin UI never sends plaintext passwords over the WebSocket.
- CLI:
  - Sends plaintext in `users.password_set`; the backend generates both salts and performs both hashing phases.

### Shared IAM State

- Domain handlers operate on the live in-memory IAM data used by the running server.
- `users.yaml` is accessed only through the management bus, including password salt/validate/update operations.
- Mutations persist to `users.yaml` and update the in-memory cache in the same operation.
- Mutations commit by atomically writing a temp file and renaming it to `users.yaml`.
- The in-memory cache is updated only after the atomic write succeeds; failed writes leave memory
  unchanged.
- Manual edits to `users.yaml` while the daemon is running are unsupported (restart required).
- The system assumes a single writer; concurrent mutations are not coordinated.
- Creating a new `UserServices`/`IamService` instance inside the domain is not allowed.
- The management context provides access to the shared IAM services.
- Update flow:
  - Handlers call the shared IAM service mutation APIs.
  - The IAM service updates the in-memory `UsersData` and persists via the backing `UserStore`.
  - Changes are immediately visible to auth middleware, admin UI, and role pickers without restart.

### Core Operation Rules

- Core operations require `config.yaml` to exist and be writable.
- `users.yaml` is required and must be writable only when `users.auth_method` is `local`.
- The operation fails if `users.auth_method` is not `local`.
- Password handling:
  - UI/CLI follow the hashing flow in `docs/iam/password-login.md`.
  - Domain uses the shared hashing helpers to store the password provider block in `users.yaml`.
  - Argon2id parameters are standard defaults; callers never send params.

### WebSocket UI Flow

- The admin shell is a Svelte SPA, and all user management data is fetched and mutated via
  WebSocket frames.
- Connection sequence:
  1. Fetch long-lived CSRF token via `POST <admin_path>/csrf-token-api` (existing flow).
  2. Fetch short-lived ticket via `POST <admin_path>/ws-ticket`.
  3. Open WebSocket `GET <admin_path>/ws`.
  4. Send the auth frame `{ ticket, csrf_token }`.
  5. On `AuthOk`, begin sending management request frames.

### Backend Endpoints

- `GET <admin_path>/users`
  - Serves the user management page shell only.
  - UI loads the user list via WebSocket (`users.list`).
- `GET <admin_path>/users/new`
  - Serves the new user page shell only.
  - UI submits `users.add` over WebSocket.
- `GET <admin_path>/users/edit/{email}`
  - Serves the edit page shell only.
  - UI loads user details via WebSocket (`users.show`).
- `POST <admin_path>/ws-ticket`
  - Issues the short-lived WebSocket ticket (20 seconds, single-use).
  - Requires valid JWT and long-lived CSRF token.

### Management Bus Mapping

- All user operations are sent over WebSocket using the domain/action IDs defined in this
  document:
  - `users.list`, `users.show`
  - `users.add`, `users.change`, `users.password_set`, `users.password_salt`, `users.password_validate`, `users.password_update`, `users.delete`
  - `users.role_add`, `users.role_remove`
- Available roles are sourced from the roles domain (`roles.list`) in
  `docs/content/role-management.md`.
- Responses map 1:1 to the management bus response actions; the UI handles success and error
  messages from `MessageResponse`.

### Frontend Behavior

- The user management UI lives in the Svelte SPA:
  - `nop/ts/admin/src/routes/UserListView.svelte`
  - `nop/ts/admin/src/routes/UserEditorView.svelte`
- WebSocket transport + coordinator:
  - `nop/ts/admin/src/transport/wsClient.ts`
  - `nop/ts/admin/src/transport/ws-coordinator.ts`
- Protocol codecs:
  - `nop/ts/admin/src/protocol/users.ts`
  - `nop/ts/admin/src/protocol/ws-protocol.ts`
- Domain services and helpers:
  - `nop/ts/admin/src/services/users.ts`
  - `nop/ts/admin/src/services/password.ts`
  - `nop/ts/admin/src/services/roles.ts`
- The SPA is bundled into `nop/builtin/admin/admin-spa.js` (plus `admin-spa.css`).
- UI uses the WebSocket coordinator module to:
  - Fetch list/show data and available roles (from `roles.yaml`).
  - Submit mutations and wait for response frames.
  - Display inline errors based on response actions.
- Password changes in the UI:
  - Call `users.password_salt` to receive the current front-end salt, a new front-end salt, and a change token.
  - Compute `current_front_end_hash` and `new_front_end_hash` using the standard Argon2id defaults.
  - Submit `users.password_update` with the hashes and `new_front_end_salt`.
- Role changes:
  - Compute deltas in the UI.
  - Send `role_add`/`role_remove` per change to avoid replacing role lists.
- Confirm fields remain UI-only guardrails; they never go over the bus.

### Backend Behavior

- The WebSocket connector validates payloads with the management codecs and dispatches to the bus.
- The bus applies mutations via the shared IAM services and persists changes to `users.yaml`.
- The UI never calls IAM directly.

### CLI Command Syntax

- `nop [-C <root>] user list`
- `nop [-C <root>] user show <email>`
- `nop [-C <root>] user add <email> --name <display-name> --roles <role> [--roles <role> ...] [--password <password>]`
- `nop [-C <root>] user change <email> [--name <display-name>] [--roles <role> ...] [--clear-roles]`
- `nop [-C <root>] user password <email> [--password <password>]`
- `nop [-C <root>] user delete <email>`

Notes:
- `<email>` is the identifier stored in `users.yaml` (normalized internally to lowercase).
- `--roles` may be repeated; omitting `--roles` on `add` creates a user with no roles.
- `--clear-roles` removes all roles on `change` (mutually exclusive with `--roles`).
- If `--password` is omitted for `add` or `password`, the CLI prompts for the password twice.
- CLI sends plaintext passwords to the management bus so the backend performs both hashing phases.

### CLI Behavior

- Runtime root is `.` by default or overridden by `-C <root>`.
- CLI requests are dispatched to the management bus using connectors:
  - Socket connector: `docs/management/connector-socket.md`
  - CLI bypass connector: `docs/management/connector-cli-bypass.md`

### Output and Exit Codes

- Success: single-line confirmation to stdout, exit code `0`.
- Failure: single-line error to stderr, non-zero exit code.

### Security Expectations

- Only authenticated admins can open the WebSocket; JWT cookie + CSRF tokens are required.
- The UI must block self-delete requests before sending a bus command.
- The authenticated WebSocket session is the authoritative source of the acting user identity.
  Management requests never include client-supplied identity fields.
- The server enforces self-delete rejection using the WebSocket session identity; CLI and other
  non-admin connectors do not supply an acting identity and are not subject to the self-delete guard.
- Manual edits to `users.yaml` while the daemon is running remain unsupported.

### Testing Scope

- WebSocket handshake tests for missing/expired tickets and CSRF tokens.
- Integration tests for list/show/add/change/delete over WebSocket.
- `nop/tests/admin_users.rs` exercises the WebSocket user CRUD flow.
- CLI end-to-end tests live in `nop/tests/cli_e2e.rs` and run the compiled `nop` binary.

### Related Documents

- `docs/admin/ui.md`
- `docs/iam/authz-authn.md`
- `docs/iam/auth-middleware.md`
- `docs/infrastructure/csrf-protection.md`
- `docs/management/architecture.md`
- `docs/management/connector-socket.md`
- `docs/management/connector-cli-bypass.md`
- `docs/management/cli-architecture.md`
- `docs/content/role-management.md`

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
