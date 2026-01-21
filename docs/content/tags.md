# Tags (Management, Admin UI, CLI)

Status: Developed

## Objectives

- Define tag storage in the system state directory with strict ID validation and flexible display names.
- Provide full CRUD + list operations through the management bus only (no direct file access).
- Add admin UI list/editor pages that use the management WebSocket connector.
- Add a full CLI command set for tag management via the management connectors.
- Allow tag ID changes with safe propagation to all tag references, and keep role assignment limited to existing roles.

## Technical Details

### Tag Deletion Cleanup

- Tag deletion is a management-layer behavior (admin UI + CLI) that cascades across all content.
- When a tag is deleted, traverse all cached content metadata and remove the tag.
- Persist tag removals by updating each affected sidecar file and the in-memory cache.
- Admin UI delete confirmation must warn that access rules can change and the operation is irreversible.

### Tag Rename Cleanup

- Tag renames are a management-layer behavior (admin UI + CLI) that cascade across all content.
- When a tag ID is renamed, traverse all cached content metadata and replace the old ID with the new ID.
- Renames must reject invalid IDs and collisions with any existing tag ID.
- Persist renamed tag IDs by updating each affected sidecar file and the tag store.

### Tag Storage

- File path: `<runtime-root>/state/sys/tags.yaml`.
- The tag file is only read or mutated through the management bus; no direct filesystem access from
  admin UI, CLI, or public handlers.
- Suggested YAML shape (map keyed by `id`):

```yaml
sample/tag:
  name: "Sample Tag"
  roles:
    - "editor"
    - "admin"
  access_rule: "union"
```

- Persistence uses an atomic write-and-rename flow, mirroring `users.yaml` behavior.
- If the file does not exist, treat the tag set as empty and create it on first mutation.

### Field Rules

- `id`
  - Required.
  - Allowed characters only: lowercase `a-z`, digits `0-9`, dash (`-`), slash (`/`), underscore (`_`).
  - Regex: `^[a-z0-9/_-]+$`.
  - No whitespace or other characters allowed.
  - Max length: 128 characters.
- `name`
  - Required.
  - Any UTF-8 characters allowed.
  - Max length: 256 characters.
- `roles`
  - Optional list, max 64 entries.
  - Each role must exist in `roles.yaml` (see `docs/content/role-management.md`).
  - Role semantics are enforced for content access via tag-based RBAC.
- `access_rule`
  - Optional.
  - Allowed values only: `union`, `intersect`.
  - Role semantics are enforced for content access via tag-based RBAC.

### Management Domain

- Domain ID: `11` (Tags).
- Actions:
  - `1`: Add
  - `2`: Change
  - `3`: Delete
  - `4`: List
  - `5`: Show
  - `101`: AddOk (response payload: `MessageResponse { message }`)
  - `102`: AddErr (response payload: `MessageResponse { message }`)
  - `201`: ChangeOk (response payload: `MessageResponse { message }`)
  - `202`: ChangeErr (response payload: `MessageResponse { message }`)
  - `301`: DeleteOk (response payload: `MessageResponse { message }`)
  - `302`: DeleteErr (response payload: `MessageResponse { message }`)
  - `401`: ListOk (response payload: `TagListResponse`)
  - `402`: ListErr (response payload: `MessageResponse { message }`)
  - `501`: ShowOk (response payload: `TagShowResponse`)
  - `502`: ShowErr (response payload: `MessageResponse { message }`)

### Requests and Responses

All requests and responses require a monotonic `workflow_id` per connection and echoed in responses.

- `TagAddRequest { id, name, roles, access_rule }`
  - `roles` may be empty to indicate no roles.
  - `access_rule` is optional.
- `TagChangeRequest { id, new_id: Option<String>, name: Option<String>, roles: Option<Vec<String>>, access_rule: Option<AccessRule>, clear_access: bool }`
  - Requires at least one of `new_id`, `name`, `roles`, `access_rule`, or `clear_access`.
  - `new_id` requests a tag ID rename and must not match any other tag ID.
  - `roles = Some(vec![])` clears roles; omitted means unchanged.
  - `clear_access = true` removes any existing access rule (mutually exclusive with `access_rule`).
- `TagDeleteRequest { id }`
- `TagListRequest {} -> TagListResponse { tags: Vec<TagSummary { id, name }> }`
- `TagShowRequest { id } -> TagShowResponse { id, name, roles, access_rule }`

### Core Operation Rules

- All tag mutations are applied to in-memory tag state and persisted to `state/sys/tags.yaml` in the
  same operation (no daemon restart).
- Tag handlers must use existing `security` helpers for path validation and safe atomic writes.
- Manual edits to `state/sys/tags.yaml` while the daemon is running are unsupported (restart required).
- Tag management is admin-only; the connector enforces authentication and CSRF for admin UI use.

### CLI Commands

- `nop [-C <root>] tag list`
- `nop [-C <root>] tag show <id>`
- `nop [-C <root>] tag add <id> --name <display-name> [--roles <role> ...] [--access <union|intersect>]`
- `nop [-C <root>] tag change <id> [--new-id <id>] [--name <display-name>] [--roles <role> ...] [--clear-roles] [--access <union|intersect>] [--clear-access]`
- `nop [-C <root>] tag delete <id>`

Notes:
- `<id>` must satisfy the tag ID charset rules.
- `--roles` may be repeated; omit `--roles` to keep roles unchanged on `change`.
- `--clear-roles` clears all roles and is mutually exclusive with `--roles`.
- `--clear-access` removes any access rule and is mutually exclusive with `--access`.
- CLI requests are dispatched through the management bus using the socket connector or CLI bypass
  connector; no direct file access.

### Admin UI Integration

- Add a tags list page that fetches `TagListRequest` via the management WebSocket connector.
- Add a tag editor page for create/edit/delete:
  - Create uses `TagAddRequest`.
  - Edit uses `TagChangeRequest`.
  - Delete uses `TagDeleteRequest` with confirmation.
- The editor validates `id` client-side using the same regex and length limit as the bus.
- The editor allows tag ID edits for existing tags and updates references on save.
- Role assignment uses the existing role selection list only (no free-text role entry).
- UI uses existing admin auth + CSRF ticket flow for WebSocket connections.
- Tag list entries link to the editor, which loads details via `TagShowRequest`.

### Testing

- Unit tests for tag ID validation and access rule parsing.
- Codec tests for field length limits and invalid role entries.
- CLI end-to-end tests covering add/change/delete/list/show/rename with valid/invalid inputs.
- Playwright E2E tests under `tests/playwright/tests/e2e/` covering admin tag list,
  create/edit/delete/rename flows, and admin-only access enforcement.

### Related Documents

- `docs/management/architecture.md`
- `docs/management/domains.md`
- `docs/management/operations.md`
- `docs/management/connector-socket.md`
- `docs/management/connector-cli-bypass.md`
- `docs/management/cli-architecture.md`
- `docs/admin/user-management.md`
- `docs/infrastructure/storage.md`
- `docs/content/role-management.md`

### Content Tag Integration

- Content objects will reference tags in sidecar metadata rather than front matter.
- Tag access rules are enforceable by the public pipeline; behavior must be documented and implemented.
- Role definitions and validation rules live in `docs/content/role-management.md`.
- Tags default to `intersect` when no access rule is specified.
- If any tag explicitly specifies `intersect`, intersect rules apply to the full tag set.
- If no tag explicitly specifies `intersect` but at least one tag specifies `union`, union rules apply to the full tag set.
- Tags without roles do not participate in role resolution when at least one tag contributes roles.
- If tag resolution yields an empty role set, the object is inaccessible to all users.
- The tag-list shortcode will use tag IDs and the tag registry to build filtered listings.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
