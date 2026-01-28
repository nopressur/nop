# Public Content Model

Status: Developed

## Objectives

- Define how public requests map to flat, alias- and ID-based content.
- Document sidecar metadata, access control, and caching used by the public pipeline.
- Provide a single canonical reference for public routing, rendering, and navigation.

## Technical Details

### Canonical Scope

This document is the single source of truth for public content resolution and rendering. On-disk storage rules live in `docs/infrastructure/storage.md`.

### ID-First Routing

- Public routing must recognize `/id/<hex>` and resolve content by ID for all content types
  (markdown renders, binaries stream).
- Alias-based routing remains only when an alias exists; missing aliases return 404.
- Aliases are optional and must not use reserved paths (see "Alias Resolution" for the canonical
  registry).
- Cache lookups must support direct ID resolution; alias maps remain optional overlays when aliases
  are present.

### Entry Points and Ownership

- `GET /` routes to `handlers::index` and resolves the configured home alias.
- `GET /{path:.*}` routes to `handlers::handle_route` and resolves aliases.
- Requests whose path starts with the configured admin prefix are routed to the admin module.
- Requests starting with `/login` are routed to the login module.

### Request Lifecycle (`handle_route`)

1. **Security gate**: `security::is_ip_blocked` and `security::route_checks` reject throttled or invalid paths.
2. **Alias canonicalization**: normalize the incoming path to a canonical alias (lowercase, trim slashes, collapse `//`, reject invalid URL characters).
3. **Alias lookup**: consult `PageMetaCache` for the canonical alias.
4. **Access check**: validate the requester against the cache-resolved roles for the object.
5. **Render or stream**:
   - Markdown files render through the Markdown pipeline.
   - Non-Markdown assets stream directly with range support when enabled.
6. **Auth outcomes**: access denial redirects anonymous users to `/login?return_path=...` or serves 404 to authenticated users.
7. **Response headers**:
   - Public content (HTML + assets) is cacheable but always includes `Vary: Cookie` so shared caches
     separate anonymous and authenticated responses.
   - Restricted content (RBAC-required) is served with `Cache-Control: no-store, private` and
     `Vary: Cookie`.
   - Login and profile pages (`/login`, `/login/profile`) are served with
     `Cache-Control: no-store, private` and `Vary: Cookie`.

### Alias Resolution

- Aliases are globally unique, case-insensitive, and canonicalized.
- Canonicalization rejects dot segments, control characters, backslashes, percent-encoded bytes,
  and non-URL-safe characters.
- Aliases that start with reserved prefixes are rejected. Reserved paths are defined in a single
  registry used by alias validation, sitemap exclusion, and robots rules. Initial entries include
  `robots.txt`, `sitemap.xml`, `id/`, `login/`, `builtin/`, `api/`, and the configured admin path
  prefix.
- Trailing slashes are ignored (`docs` and `docs/` are the same alias).
- Non-Markdown assets also resolve by `id/<hex>` for stable download links.
- If no alias is found, respond with 404.

### Page Metadata Cache

- `PageMetaCache::rebuild_cache` scans sidecar metadata files at startup.
- Cached metadata includes content ID, `alias`, `title`, `tags`, `mime`, `nav_title`, `nav_parent_id`, `nav_order`, `original_filename`, and theme when provided.
- Cached metadata includes `last_modified`, derived from the latest modification time between the
  content blob and its sidecar.
- The cache supplies canonical content IDs and navbar parent candidates to management APIs.
- The cache stores resolved access roles per object after tag evaluation.
- Admin changes update the cache via `cache.update_file` or `cache.remove_file`.
- The cache is treated as authoritative; external filesystem edits require a rebuild or restart.

### Sidecar Metadata

The public pipeline reads metadata from RON sidecar files, not front matter.

- `title` is used for page titles and navigation labels.
- `theme` selects `<runtime-root>/themes/<theme>.html` and falls back to `default.html`.
- `tags` drive access control and tag-list shortcodes.

### Access Control and RBAC

- Roles are defined on tags, not on content objects.
- Tag access rules determine the resolved role set for each object (see `docs/content/public-rbac.md`).
- Role storage and validation are defined in `docs/content/role-management.md`.
- If the resolved role set is empty, the object is inaccessible to all users.
- Objects with no tags are public.

### Markdown Rendering

- `generate_html` configures `pulldown_cmark` with tables, strikethrough, footnotes, and task lists enabled.
- `process_event` enforces security rules:
  - Image sources are validated against traversal attempts and must exist locally.
  - Local links are normalized and checked against cached routes; invalid references render inline warnings.
- Output HTML is sanitized by `ammonia` (`HTML_CLEANER`) and then post-processed:
  - External anchors open in a new tab with safe `rel` attributes.
  - Eligible local file links become download links.

### Shortcodes

- Raw Markdown is first passed through `process_text_with_shortcodes`, which replaces valid invocations with placeholders and records rendered HTML.
- Rendered shortcode HTML is keyed by unique `SHORTCODE_HASH_*` placeholders so it can be reinserted after sanitization without escaping.
- After Markdown rendering and sanitization, `replace_shortcode_placeholders` swaps placeholders back in.
- Built-in shortcodes live under `public/shortcode/` and include `start-unibox`, `video`, and `link-card`.
- The `tag-list` shortcode renders lists of content based on tags and uses the same listing HTML style as the existing listing helpers.

### Themes and Layout

- Themes live under `themes/` as HTML fragments; `default.html` is required.
- `generate_html_page_with_user` loads themes via `load_theme_content` with canonical path checks.
- Theme fragments are injected into `public/templates/main_layout.html` alongside user navigation fragments.
- Admin code never reads `themes/`; only the public renderer loads themes.
- Public markdown pages apply a content-width cap in the main layout: 1152px when any paragraph (including tight list items) exceeds `rendering.short_paragraph_length` (default 256), otherwise 960px. Set `rendering.short_paragraph_length` to `0` to disable compact width entirely. The navbar container is not affected.

### Admin Edit Button (Public Navbar)

- Markdown pages render `data-site-content-id` (hex) in `public/templates/main_layout.html` for frontend use.
- The site menu script (`nop/ts/site/src/userMenu.ts`) calls `/api/profile`; when the response includes the
  admin menu item and a content ID is present, it inserts an `Edit` button immediately to the left of the
  profile dropdown.
- The edit button opens a new tab to `<admin_path>/pages/edit/<content_id>`. Admin access is treated as
  all-or-nothing; if the profile payload reports the admin menu item, the button is shown.

### Navigation

- The top navigation bar is explicit; no hierarchy is derived from paths.
- `nav_title` (string) determines inclusion; items without `nav_title` are excluded from navigation.
- Navigation labels are treated as plain text and HTML-escaped at render time.
- `nav_parent_id` (ContentId hex string) defines parent/child grouping; only root items (no parent) render top-level links.
- `nav_order` (integer) defines ordering for both top-level items and their children; lower numbers render first.
- Children are rendered under their parent in `nav_order` order; ties are resolved by alias for determinism.
- Missing parent IDs or nodes are skipped with a warning so navigation generation never panics.
- Parent selection data is sourced from the page metadata cache and exposed via the content management domain.

### Static Assets and Streaming

- Non-Markdown files are served via `serve_static_file`.
- MIME types are read from sidecar metadata.
- Range requests are supported when `config.streaming.enabled` is true.

### Error Handling

- 404: `public::error::serve_404` handles missing aliases, invalid routes, and access-denied responses for authenticated users.
- 500: `public::error::serve_500` covers filesystem read failures and unexpected panics.
- Access denial redirects anonymous users to `/login?return_path=...`.

### Extension Tips

- New shortcodes should register in `create_default_registry_with_config` and ship templates under `public/shortcode/templates/`.
- New public endpoints must be registered in `public::configure` and should respect the same cache and security checks.
- For content-derived routes, use `PageMetaCache` to validate existence and permissions before touching the filesystem.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
