# Content Storage and Disk Management

Status: Developed

## Objectives

- Define the canonical on-disk content contract for flat, hashed storage.
- Document sidecar metadata, alias rules, and versioned blobs.
- Provide a single storage reference for public and admin documentation.

## Technical Details

### Canonical Scope

This document is the single source of truth for how NoPressure stores and manages content on disk. Other documentation should link here for storage details instead of restating them.

### ID-Only Identity and Optional Aliases

- Content IDs are the only identifiers on the management bus and in internal APIs; aliases are
  optional metadata and must never be used as identifiers for admin operations.
- Aliases exist only for public routing and user-friendly links.
- Sidecar metadata must allow `alias` to be missing or empty. When absent, no alias mapping exists.
- If an alias is provided, it must pass canonicalization and remain globally unique.
- Aliases must not begin with the reserved `id/`, `login`, or `builtin` prefixes, or the configured
  admin path prefix (all prefixes are checked after trimming slashes and lowercasing).
- ID-based addressing uses `/id/<hex>` and is reserved for ID routing only (never stored as an
  alias).

### Runtime Root Layout

- The runtime root is resolved from `-C <root>` (defaults to the current working directory).
- Content, themes, and state live alongside `config.yaml` and `users.yaml`:
  - `content/` for flat hashed storage and sidecar metadata.
  - `themes/` for public layout templates (HTML fragments).
  - `state/` for runtime state (`state/sys`, `state/sc`).
- The server ensures required directories exist at startup and expects them to be writable when admin features are enabled.
- `content/legacy/` is reserved for migrated trees and must be ignored by the cache and runtime scanners.

### Flat Hashed Storage Layout

- Each stored object receives a randomized 64-bit ID.
- The ID is the filename for the blob and the sidecar; no ID is repeated inside metadata.
- The ID is used as the canonical internal identifier in management APIs and parent references.
- Blobs are sharded into subdirectories by byte to avoid large single directories.
- A canonical layout uses a single shard level directly under `content/`:

```
content/aa/<id>.<version>
content/aa/<id>.<version>.ron
```

- `aa` is a byte-derived shard (two hex digits) from the object ID (least or most significant byte; rule must be consistent).

### Versioned Blobs

- File versions are encoded in the blob filename: `<id>.<version>` where version is `0`, `1`, `2`, and so on.
- Metadata is mutable; updating alias, title, tags, or navbar metadata does not create a new blob version.
- Content updates create a new blob version and a new sidecar for that version.

### Sidecar Metadata (RON)

Each blob version has a sidecar stored alongside it. The sidecar is authoritative and mutable for metadata.

Fields:

- `alias` (optional string, globally unique, canonicalized when present)
- `title` (optional string; Markdown authoring tools should prompt for one)
- `mime` (string, detected on upload)
- `tags` (list of tag IDs)
- `nav_title` (optional string; presence includes the item in navigation)
- `nav_parent_id` (optional ContentId hex string; defines parent/child grouping)
- `nav_order` (optional integer; controls ordering within root and child lists)
- `original_filename` (optional string; preserved from upload)
- `theme` (optional string; if themes remain supported per object)

Notes:

- Roles are not stored on content objects. Access is derived from tags only.
- If a blob exists without a sidecar, it is ignored by the cache and not served.

Example:

```ron
(
    alias: "docs/getting-started",
    title: "Getting Started",
    mime: "text/markdown",
    tags: ["docs", "getting-started"],
    nav_title: Some("Getting Started"),
    nav_parent_id: None,
    nav_order: Some(10),
    original_filename: "getting-started.md",
    theme: Some("minimal"),
)
```

### Alias Canonicalization

- Aliases are globally unique and case-insensitive.
- Canonicalization rules:
  - Lowercase.
  - Trim leading and trailing slashes.
  - Collapse repeated slashes (`//` -> `/`).
  - Allow only URL-safe ASCII characters (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`, `!`, `$`, `&`,
    `'`, `(`, `)`, `*`, `+`, `,`, `;`, `=`, `:`, `@`) plus `/` separators.
  - Reject dot segments (`.` or `..`), control characters, backslashes, and percent-encoded bytes.
  - Reject the reserved `id/`, `login`, and `builtin` prefixes.
  - Ignore trailing slash for lookup (`docs` == `docs/`).
- Alias changes take effect immediately; old aliases do not redirect.
- For non-Markdown assets, the cache also exposes `id/<hex>` as a stable download alias.

### MIME Type Handling

- MIME type is detected at upload and stored in the sidecar.
- There are no `.mime-types` manifests or directory-based MIME caches.

### Migration

- Legacy hierarchical trees under `content/` must be migrated into the flat layout before caching.
- Migration rules and sidecar mapping live in `docs/content/file-migration.md`.

### Write Expectations and Atomicity

- The runtime expects `content/` to be writable when admin features are enabled.
- Sidecar writes should be atomic (write then rename) to avoid partial updates.
- Blob writes should complete before a sidecar is made visible to avoid dangling metadata.

### Cache Build Expectations

- The in-memory cache scans sidecars and builds:
  - Alias to object mapping.
  - Title and navbar metadata for listing.
  - Tag membership for access checks and tag-list shortcodes.
  - Resolved access roles per object (derived from tags).

### Operational Notes

- Treat `content/` as public content storage; do not place secrets there.
- Backups should include `content/`, `themes/`, `state/`, `config.yaml`, `users.yaml`, and
  `state/sys/roles.yaml`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
