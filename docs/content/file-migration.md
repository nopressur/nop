# Flat Storage Migration

Status: Developed

## Objectives

- Migrate legacy hierarchical `content/` trees into the flat hashed storage layout.
- Preserve aliases, titles, and tag metadata where possible.
- Avoid data loss and ensure migration is idempotent and observable.

## Technical Details

### Detection and Trigger

- Migration runs at startup before cache initialization.
- If any legacy files exist outside shard directories, migration is required.
- A migration marker file (`state/sys/migrations/flat-storage-v1`) prevents re-running and records counts.

### Source Scope

- Scan `content/` recursively, excluding:
  - Shard directories named with two lowercase hex digits (`content/aa/`, `content/0f/`).
  - `content/legacy/` (for previously migrated trees).
  - Hidden files and directories.

### Alias Derivation

- Aliases are optional in the current model; migration still derives aliases from legacy paths when
  possible so existing links remain meaningful.

- Markdown aliases:
  - Use the legacy relative path without the `.md`/`.markdown` extension.
  - `index.md` becomes the parent alias (`content/docs/index.md` -> `docs`; root `content/index.md` -> `index`).
  - Example: `content/docs/getting-started.md` -> `docs/getting-started`.
- Binary aliases:
  - Use the legacy relative path including the extension.
  - Example: `content/assets/logo.png` -> `assets/logo.png`.
- Apply canonicalization rules (lowercase, trim slashes, collapse `//`, allow only URL-safe ASCII
  characters, reject dot segments, percent-encoded bytes, and the reserved `id/`, `login`, and
  `builtin` prefixes).
- Deduplicate aliases by appending `-2`, `-3`, and so on.

### Placeholder Home Page

- If the legacy root lacks `index.md`/`index.markdown` and no existing `index` alias exists, migration creates a placeholder markdown page:
  - Alias: `index`
  - Title: `Home`
  - Content: clearly notes that a placeholder was created and needs updating.
- The migration marker records `index_placeholder_created=true` when this happens.

### Sidecar Metadata Mapping

- Create a new blob with version `0` for each migrated object.
- Write a sidecar alongside the blob containing:
  - `alias`
  - `title` (Markdown: front matter `title` or cleaned filename; assets: cleaned filename)
  - `mime` (detected at migration time)
  - `tags` (see role mapping below; optional if none)
  - `nav_title`, `nav_parent_id`, `nav_order` (omitted; migration does not create navbar entries)
  - `original_filename` (basename of the legacy file)
  - `theme` (from front matter if present)
- Strip front matter from Markdown before storing the blob.
- Store the migrated blob under the shard directory derived from the new ID: `content/aa/<id>.0`.

### Navbar Metadata

- Migration must not generate any navbar metadata.
- Legacy `nav` front matter is ignored (no `nav`, `nav_title`, `nav_parent_id`, or `nav_order` is written).

### Legacy Role Mapping

Legacy front matter roles must be converted into tag-based access rules.

- For each unique role list encountered, create (or reuse) a tag:
  - Tag ID: `legacy/roles/<hash>` derived from the role list.
  - Tag name: `Legacy roles: <role list>` (truncated to 256 chars if needed).
  - Tag roles: the normalized legacy role list.
  - Tag access_rule: `union` (to preserve OR semantics).
- Ensure all roles in the legacy list exist in `roles.yaml` before creating tags
  (see `docs/content/role-management.md`).
- Assign the generated tag to the migrated object.
- Directory inheritance is not preserved; only file-level roles are migrated.
- If this yields no roles, the object is public unless other tags are assigned.

### Tag Registry Updates

- Tag creation and updates go through the tag store to enforce validation.
- Tags are persisted to `state/sys/tags.yaml` using the same atomic write process as other tag mutations.

### File Moves and Cleanup

- After successful migration, legacy files are moved to `content/legacy/` with the same relative path.
- A failed migration leaves the legacy tree intact and produces no partial aliases.

### Error Handling

- Any per-file failure should be logged with the source path and error.
- Migration should be all-or-nothing per file; a failure must not leave a sidecar without a blob.
- If migration fails, startup should abort with a clear error message.

### Testing

- Migrate a mixed tree of Markdown and assets with nested folders.
- Confirm alias deduplication when collisions occur.
- Confirm front matter stripping and title/theme preservation.
- Confirm role mapping creates tags and preserves access semantics.
- Confirm idempotency when the migration marker exists.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
