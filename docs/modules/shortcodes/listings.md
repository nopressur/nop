# Listing Shortcodes

Status: Developed

## Objectives

- Document shortcodes that render lists of pages selected by metadata (tags, etc.).

See `docs/modules/shortcodes.md` for the parser, registry, and substitution mechanism that all shortcodes share.

## Technical Details

### `tag-list`

Renders an HTML list of pages matching tag criteria. Replaces directory-based listings for tag-driven pages.

**Syntax**: `((tag-list ...))`

**Attributes**:

- Exactly one of `tags`, `or`, or `and` must be provided.
  - `tags` and `or` are OR lists (synonyms).
  - `and` is an AND list.
- `limit` (optional): when absent, renders all matches.

**List parsing**:

- Lists are comma-separated.
- Whitespace around commas is ignored.
- Tag IDs must use the tag ID charset (lowercase letters, numbers, dashes, underscores, slashes).

**Examples**:

```markdown
((tag-list tags="docs,getting-started" limit=20))
((tag-list or="news,blog"))
((tag-list and="internal,private" limit=10))
```

**Rendering rules**:

- Reuses the existing HTML listing helper (`generate_tag_listing_html`).
- Matches are filtered by access rules before rendering.
- Registered with `ShortcodeType { dynamic: true, container_escape: false }` because it depends on content metadata; pages containing it are served with `Cache-Control: no-store`.

**Implementation notes**:

- Handler: `tag_list::handle_tag_list_shortcode` in `nop/crates/nop-public/src/shortcode/tag_list.rs`.
- Renderer: `crate::markdown::listing::generate_tag_listing_html`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
