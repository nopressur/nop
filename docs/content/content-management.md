# Admin Content Management

Status: Developed

## Objectives

- Define how the admin UI manages content and related assets in flat storage.
- Document sidecar metadata editing, listing, and upload flows.
- Provide a canonical reference for admin content operations and side effects.

## Technical Details

### Canonical Scope

This document is the single source of truth for admin content management. On-disk storage rules live in `docs/infrastructure/storage.md`, and public serving rules live in `docs/content/content-model.md`.

### ID-First Editing and Optional Aliases

- Content editing must be addressed by content ID (path parameter), not by alias query parameters.
- Management bus requests for read/update/delete/update-stream must use IDs only; aliases are never
  accepted as identifiers in admin operations.
- Aliases are optional for all content types (markdown, images, video, binaries); editors must allow
  aliases to be cleared.
- Alias validation only applies when a non-empty alias is provided; aliases must not start with
  `id/`, `login`, `builtin`, or the configured admin path prefix.
- The content list should continue to display aliases when present, but must fall back to IDs when
  no alias exists and always use IDs for navigation.
- Insert behavior (modal + upload drop): insert `/alias` when an alias exists, otherwise insert
  `/id/<hex>` for all content types (links, images, videos, markdown).

### Admin Base Path and Layout

- Admin routes are mounted under `config.admin.path` (default `/admin`).
- All admin routes are protected by `RequireAdminMiddleware` (admin role or dev-mode bypass in debug builds; release builds ignore `dev_mode`).
- The admin UI is a Svelte SPA served by the MiniJinja shell template
  `nop/src/admin/templates/spa_shell.html`, with assets built from `nop/ts/admin` into
  `/builtin/admin/admin-spa.{js,css}`.
- The SPA pulls content data over WebSocket; server-side shells do not pre-render content lists.
- CSRF tokens are refreshed via `/csrf-token-api` and required for mutating APIs.

### File Manager (Flat Storage)

The file manager replaces hierarchical browsing with a flat, paginated list.

#### Listing and Search

- Display a paginated list of files.
- Support title-only search (no full-text search).
- Markdown-only toggle (default view shows all files).
- Tags filter supports multi-select and matches all selected tags.
- Creating a new page from the list seeds the page tags from the currently selected tag filters.
- Do not display object IDs.
- Display the canonical alias for each entry.
- Copy URL actions are available from the list (see **Copy URL actions** below).
- The list uses the sidecar `title` field; if a title is missing, the entry renders as `Untitled`.
- The original filename is preserved in sidecar metadata and stored in the in-memory cache for display in edit views.
- Content list responses must include content IDs for internal references such as navbar parents.

#### Copy URL actions

The admin UI provides copy buttons that place the fully qualified public URL on the clipboard:

- `ID` is always available and copies `origin + /id/<hex>`.
- `Alias` appears only when an alias exists and copies `origin + /<alias>`; `index` aliases copy `/`.
- On the editor toolbar only, Ctrl/Cmd-clicking `ID` or `Alias` opens the public URL in a new tab
  without copying or showing a toast.

#### Content List Sorting

- Sorting is controlled by the content list request and is mandatory on every request.
- Default sort is Title ascending; the admin UI must send Title + Ascending explicitly.
- Sortable columns: Title, Alias, Tags, Type (mime), Navbar (nav title). Actions column is not sortable.
- Null/empty values always sort last, regardless of direction.
- Tags sort on the joined tag display string; when tags are empty, render a dash and treat as null for sorting.
- Navbar sort uses `nav_title`; items without a navbar title are treated as null.
- Tiebreaker is the content ID (ascending) for deterministic ordering.
- UI indicators:
  - Column headers are clickable with a pointer cursor.
  - Active column uses a stronger contrast (lighter in dark mode, darker in light mode).
  - Use up/down arrow glyphs (U+2191/U+2193) at a smaller font size for direction.

##### Protocol: `ContentListRequest` (Management Bus)

Add two required fields and wire them into the request payload:

```
ContentListRequest {
  page: u32,
  page_size: u32,
  sort_field: ContentSortField,
  sort_direction: ContentSortDirection,
  query: Option<String>,
  tags: Option<Vec<String>>,
  markdown_only: bool,
}
```

Enums (u32 over the wire):

- `ContentSortField`:
  - `0` = Title
  - `1` = Alias
  - `2` = Tags
  - `3` = Type (mime)
  - `4` = Navbar (nav_title)
- `ContentSortDirection`:
  - `0` = Asc
  - `1` = Desc

Wire encoding order (after OptionMap for `query`/`tags`):

1. `page` (u32)
2. `page_size` (u32)
3. `sort_field` (u32)
4. `sort_direction` (u32)
5. `query` (string, optional)
6. `tags` (vec<string>, optional)
7. `markdown_only` (bool)

Validation:

- `sort_field` and `sort_direction` are required and must match known enum values.
- Apply existing limits for query/tags; reject invalid sort values with a validation error.

#### Selection and Editing

- Clicking a Markdown entry opens the editor with the Markdown body.
- Clicking a non-Markdown entry opens metadata-only details with a download link.
- Copy URL actions are available next to the editor toolbar buttons (see **Copy URL actions** above).
- The editor header shows sidecar metadata instead of front matter:
- Alias (editable).
- Alias must be URL-safe and cannot start with reserved prefixes (`id/`, `login`, `builtin`, or
  the configured admin path prefix).
- Alias validation runs on change in the editor and shows inline errors; save still re-validates.
- When the details panel is open, pressing Enter in a details field saves and collapses the panel.
- Title.
- Tags.
- Navbar title, parent, and order.
- Theme (if enabled per object).
- Original filename (read-only).
- Saving metadata updates the sidecar without altering blob versions.

#### Editor Insert Modal

- Cmd/Ctrl+Shift+I opens an insert modal for linking or embedding content at the cursor.
- The modal provides type-ahead search, a tag filter, and a keyboard-controllable results list.
- The tag filter defaults to the page’s first tag (if set) and filters the results immediately.
- Selecting a result does not close the modal; users choose the insertion mode first.
- Insertion mode options depend on the selected item:
  - Images: link or Markdown image.
  - Videos: link or `video` shortcode.
  - Markdown/other files: link only.
- When only link is available, the insertion toggle is disabled and skipped in tab order.
- Link text falls back in order: title → alias → ID.
- Keyboard support:
  - Up/Down selects results; Page Up/Down moves between pages.
  - Left/Right changes insertion mode when available.
  - Enter inserts; Escape closes the modal.

#### Unsaved Changes

- When no edits exist, the header action reads `Close`.
- When edits exist, the header action reads `Cancel` and opens an unsaved-changes modal.
- The modal provides `Save` (persist and return to list), `Discard` (return to list), and `Cancel`
  (stay in the editor).
- Keyboard (modal only): Escape = Cancel, Enter = Save, D = Discard.

#### Navbar Fields

- Replace the navigation flag with:
  - `Navbar title` (text input).
  - `Navbar parent` (select from pages that have a navbar title and no parent).
  - `Navbar order` (integer; ordering within root/child lists).
- Navbar parent options are supplied via the content management WebSocket using page cache data (`content.nav_index`).
- Removing a navbar title from a page that has children must show a warning dialog:
  - "Removing the navbar title from this page will also remove the navbar titles of its children."
  - Actions: Remove / Cancel.
- If a navbar title is cleared, its children lose their navbar titles.
- Navbar edits bump the release tracker (`X-Release`) so cached HTML navigation refreshes.

#### Drag-and-Drop Uploads

Uploads are available from the Markdown editor and content list.

- Upload buttons in the content list and Markdown editor open a full-screen drop zone overlay.
- The overlay accepts single or multiple files dropped anywhere on the screen and provides a
  keyboard-accessible file picker.
- Dropped or selected files open a multi-file upload modal:
  - One block per file with alias, title, and tags.
  - Each block can be saved or cancelled independently.
  - Tags are selected from existing tags using a dropdown selector (no free-text entry).
  - Pressing Enter in a file block saves/uploads that file only.
  - When multiple files are queued, "Save all" actions appear at the top and bottom of the modal.
- The content list includes a tag selector that filters the list and sets default tags for new uploads.
- Content editor uploads inherit the page’s current tag selection (including unsaved tag changes).
- Default alias prefixes:
  - Images -> `images/<original-filename>`
  - Videos -> `videos/<original-filename>`
  - Other files -> `files/<original-filename>`
- If the page has a valid alias, editor uploads default to `<page-alias>/<original-filename>` instead
  of the type-based prefixes.
- Aliases are deduplicated by appending numeric suffixes.
- MIME type is auto-detected and stored in the sidecar.
- Original filename is preserved in the sidecar and cache.
- Dragging files over the Markdown editor shows a stable drop hint and never navigates away;
  drag/drop defaults are prevented outside intended drop zones.

Insertion behavior on drop:

- Video uploads insert a video player shortcode at the cursor.
- Image uploads insert a Markdown image link at the cursor.
- Other files insert a Markdown link that targets `id/<hex>` when available, otherwise the alias.
- Content list uploads create new content entries only; no editor insertion occurs.

#### Management Bus Requirement

- All file CRUD, listing, and metadata edits must flow through the management bus.
- The admin UI must not perform direct filesystem access or use direct upload endpoints.

### Markdown Create/Update vs Binary Uploads

- Markdown create/update remains on the existing content commands and validation rules, including nav/title/theme handling.
- Binary asset uploads are a separate command path and must not include nav/theme fields.
- Binary protocol details and action IDs are documented in `docs/management/connector-socket.md` to avoid duplication.

### Binary Upload Pipeline

- Binary uploads use a two-step validation flow:
  - Pre-validation uses filename, mime, and size to decide if the file can be queued.
  - Upload validation runs right before streaming and validates alias, tags, filename, mime, and size.
- Pre-validation runs immediately on drop/selection:
  - Rejected files render as a placeholder block explaining why they will not upload.
  - Accepted files render as editor blocks with alias/title/tags inputs.
- Upload validation runs on per-item upload (Save or Enter):
  - If alias/tags/other inputs are invalid, show an error at the top of the block and keep the editor.
  - If validation passes, replace the editor block with a progress tracker and start streaming.
- Streaming writes to temp files on disk (not in-memory), using the final blob path plus a `.upload` or `.tmp` suffix to mirror the final destination.
- Streaming must honor `upload.max_file_size_mb` exactly; `0` means unlimited with no hidden safety cap.
- The backend must enforce size during streaming and reject when streamed bytes exceed the negotiated size or config limit.
- Upload progress replaces the editor block for the single item being uploaded; on failure, the editor returns with the error; on success, the item is removed.
- Pressing Enter in an item editor triggers upload for that single item only; "Save all" uploads sequentially and does not override per-item behavior.
- When all uploads succeed, the modal closes automatically. If any errors remain, the modal stays open until dismissed.
- Temp files are removed on WebSocket disconnects/timeouts and on any management commit rejection.
- On startup, the server deletes any `.upload`/`.tmp` files found under the content root.

### Markdown Content Robustness

- Markdown create/update must support large content without relying on single-frame payloads.
- For small content, existing inline payloads are still valid.
- For large content, the client must use stream-backed create/update actions that:
  - Negotiate size and metadata up front.
  - Stream UTF-8 bytes to temp files.
  - Commit via management commands that read from the temp file.
- Size enforcement for markdown uses `upload.max_file_size_mb` (0 = unlimited) with no hard-coded caps.

### Security and Session Notes

- Every mutating endpoint requires a valid CSRF token retrieved from `/csrf-token-api`.
- Admin middleware redirects unauthenticated users to `/login?return_path=...` and non-admins to `/`.
- Use `security` helpers for any filesystem operations performed by the backend services.

### Extending the Admin SPA

- Add new UI routes under `nop/ts/admin/src/routes` and wire them into
  `nop/ts/admin/src/app/App.svelte`.
- Extend `nop/ts/admin/src/services` or `nop/ts/admin/src/transport` for new data flows,
  reusing existing WebSocket/REST helpers where possible.
- If server-provided bootstrap data is required, pass it through
  `render_admin_spa_shell_response` in `nop/src/admin/shared/mod.rs` and populate it in the
  relevant handler.
- Always refresh `PageMetaCache` after content mutations so public navigation stays coherent.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
