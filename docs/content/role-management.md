# Role Management

Status: Developed

## Objectives

- Add a single source of truth for available roles stored in `roles.yaml`.
- Provide role CRUD + list via CLI, WebSocket admin UI, and management bus.
- Keep role validation consistent across tags, users, and access control.
- Enforce admin role immutability and cascade deletions across tags/users.

## Technical Details

### Roles Storage

- File path: `<runtime-root>/state/sys/roles.yaml`.
- Format: YAML sequence of role IDs only.
- Example:

```yaml
- admin
- editor
- viewer
```

- Roles are persisted in sorted order for stable diffs.
- The file is managed via the role management APIs only; manual edits while the daemon is running
  are unsupported (restart required).

### Validation and Conventions

- Role IDs are trimmed; empty strings are invalid.
- Allowed characters: `A-Z`, `a-z`, `0-9`, `-`, `_`.
- Max length: 64 characters.
- Role IDs are case-sensitive; normalization only trims whitespace.
- `admin` is reserved:
  - Must always exist.
  - Cannot be renamed or deleted.

### RoleStore

- In-memory store backed by `roles.yaml`, using read/write locks and atomic write + rename.
- Provides snapshot, add, rename, delete, and validate helpers.
- RoleStore is the single source of truth for available roles.

### Management Domain (Roles)

- Domain ID: `13` (Roles).
- Actions:
  - `1`: Add
  - `2`: Change (rename)
  - `3`: Delete
  - `4`: List
  - `5`: Show
  - `101`: AddOk (response payload: `MessageResponse { message }`)
  - `102`: AddErr (response payload: `MessageResponse { message }`)
  - `201`: ChangeOk (response payload: `MessageResponse { message }`)
  - `202`: ChangeErr (response payload: `MessageResponse { message }`)
  - `301`: DeleteOk (response payload: `MessageResponse { message }`)
  - `302`: DeleteErr (response payload: `MessageResponse { message }`)
  - `401`: ListOk (response payload: `RoleListResponse`)
  - `402`: ListErr (response payload: `MessageResponse { message }`)
  - `501`: ShowOk (response payload: `RoleShowResponse`)
  - `502`: ShowErr (response payload: `MessageResponse { message }`)

### Requests and Responses

All requests and responses require a monotonic `workflow_id` per connection and echoed in responses.

- `RoleAddRequest { role }`
- `RoleChangeRequest { role, new_role }`
- `RoleDeleteRequest { role }`
- `RoleListRequest {} -> RoleListResponse { roles: Vec<String> }`
- `RoleShowRequest { role } -> RoleShowResponse { role }`

### Cascades and Consistency

- Role additions only update `roles.yaml`.
- Role rename updates:
  - `roles.yaml` (rename).
  - All tag records (replace the role string).
  - All users (replace the role string).
  - Page/meta caches are invalidated to reflect new access outcomes.
- Role deletion updates:
  - `roles.yaml` (remove role).
  - All tag records (remove role).
  - All users (remove role).
  - Page/meta caches are invalidated to reflect new access outcomes.
- Attempts to delete or rename `admin` must fail with a clear error.

### CLI Commands

- `nop [-C <root>] role list`
- `nop [-C <root>] role show <role>`
- `nop [-C <root>] role add <role>`
- `nop [-C <root>] role change <role> --new-role <role>`
- `nop [-C <root>] role delete <role>`

### Admin UI

- Add Roles list + editor routes in the SPA.
- Role pickers (tags/users) consume `roles.list`.
- Deletion confirmation must warn:
  - The change is irreversible.
  - Access to content may change.
  - Tags/users referencing the role will be updated.

### Integration Points

- Tag and user management must validate roles against RoleStore (unknown roles are rejected).
- File migration must ensure roles discovered in legacy front matter exist in RoleStore before tag
  creation (create missing roles via the role store).
- Auth flows continue to use user roles for JWT claims; role availability is sourced from RoleStore.

### Testing Scope

- RoleStore unit tests for load, add, rename, delete, and validation.
- Codec tests for field limits and invalid role IDs.
- CLI end-to-end tests for CRUD + list.
- WebSocket integration tests for CRUD + list.
- Cascade tests for tag/user updates and cache invalidation.
- Playwright UX/E2E coverage for role list/editor and role pickers.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
