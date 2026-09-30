# Admin Content Management

Status: Developed

## Objectives

- Define how the admin UI manages content and related assets in flat storage.
- Document sidecar metadata editing, listing, and upload flows.
- Provide a canonical reference for admin content operations and side effects.
- Add non-Markdown upload versioning so uploading an existing non-Markdown alias keeps the content
  ID and creates a new blob version.
- Surface alias-version intent in the admin upload modal as soon as an alias is set.
- Default detected font uploads to the `fonts/` alias prefix.
- Load large Markdown editor sources without depending on a single WebSocket response frame.

## Technical Details

### Canonical Scope

This document is the single source of truth for admin content management. On-disk storage rules live in `docs/infrastructure/storage.md`, and public serving rules live in `docs/content/content-model.md`.

### Page Editor Toggle and Width

- The admin page editor exposes page-level navbar state through the reusable toggle documented
  in `docs/admin/ui.md`: `Navbar Enabled` persists `disable_navbar = false`, and `Navbar Disabled`
  persists `disable_navbar = true`.
- The admin page editor adds a Markdown page width mode using the same reusable toggle pattern:
  `Auto Width`, `Wide`, and `Narrow`.
- Width mode is Markdown metadata and follows the same management-bus sidecar update path as title,
  tags, theme, navbar fields, and `disable_navbar`.
- The public rendering behavior for each width mode is owned by `docs/content/content-model.md`.

### Search, Image Identity, and Hero Width

- A public page that sets `disable_navbar = true` omits the navbar only. The public search overlay
  remains initialized from the page layout, and passive typing plus keyboard shortcuts continue to
  open search without requiring a navbar search button.
- Non-Markdown editor previews and editor download links are object-identity actions. They use
  `/id/<hex>` for the content item being edited, including image previews. Alias URL copy/open
  actions remain available as explicit alias actions.
- Binary image aliases are mutable public routing metadata. Sequential alias changes made through
  management-bus updates must update the live public alias map without restarting the executable.
  For metadata-only alias changes, ID URLs remain stable and must continue to return the same object
  bytes.
- Non-Markdown uploads that reuse an existing non-Markdown alias create a new blob version under the
  existing content ID. After commit, the alias and `/id/<hex>` public URLs resolve to the latest
  committed version for that ID.
- Hero-image container escape/reopen behavior preserves the page's content width decision. Reopened
  containers use the same compact or wide width as the page layout.

### Non-Markdown Upload Versioning

- The content management domain adds an alias-status query for upload workflows. The request carries
  an alias string. The response returns:
  - `canonical_alias`
  - `exists`
  - `id` when an object exists
  - `version` when an object exists
  - `mime` when an object exists
  - `is_markdown` when an object exists
  - `title` when an object exists and has a title
- The admin upload modal must call the alias-status query for each generated alias and after alias
  edits. Alias edits use a debounced background check and do not show a transient "checking" state.
  The UI shows durable alias outcomes only: an existing non-Markdown alias creates a new version, an
  existing Markdown alias blocks the upload, and failed verification shows "Alias could not be
  verified."
- Binary uploads with an alias that resolves to existing non-Markdown content retain the existing
  content ID and write a new version. The response returns the retained ID, canonical alias, detected
  MIME type, and `is_markdown = false`.
- Binary uploads with an alias that resolves to Markdown content are rejected because Markdown body
  updates must use the Markdown update path.
- Binary uploads with an empty alias always create a new content ID.
- Version reservation happens during binary upload initialization. The backend selects the next
  available version for the target ID while considering committed versions and pending `.upload` or
  `.tmp` files, then creates the upload temp file with create-new semantics so concurrent same-alias
  uploads cannot reserve the same version.
- Binary upload commit writes a sidecar for the new version using the submitted alias, title, tags,
  detected MIME type, and original filename. The public cache must select the highest committed
  version for alias and ID routing.
- Successful binary uploads bump the release tracker so public asset URL consumers can refresh when
  an alias is versioned.
- Old versions remain on disk until the content ID is deleted. Deleting a content ID removes all
  versions for that ID.

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
- The editor header's `View Page` link is a public route, not an editor route: saved Markdown content
  links to `/<alias>` when an alias exists, `/` for the `index` alias, and `/id/<hex>` only when no
  alias exists.

### Admin Base Path and Layout

- Admin routes are mounted under `config.admin.path` (default `/admin`).
- All admin routes are protected by `RequireAdminMiddleware` (admin role or dev-mode bypass in debug builds; release builds ignore `dev_mode`).
- The admin UI is a Svelte SPA served by the MiniJinja shell template
  `nop/crates/nop-admin/src/templates/spa_shell.html`, with assets built from `nop/ts/admin` into
  `/builtin/admin/admin-spa.{js,css}`.
- The SPA pulls content data over WebSocket; server-side shells do not pre-render content lists.
- CSRF tokens are refreshed via `/csrf-token-api` and required for mutating APIs.

### File Manager (Flat Storage)

The file manager replaces hierarchical browsing with a flat, paginated list.

#### Listing and Search

- Display a paginated list of files.
- Use management search (`search.find`) for queries between 3 and 256 characters (inclusive);
  shorter queries do not issue search requests and show the unfiltered list.
- Search results prioritize title matches and then append relevance-ranked hits from the search index;
  the UI still applies the selected column sort after receiving results.
- Search results are capped at 128 hits (domain limit) and then paginated client-side.
- Markdown-only toggle (default view shows all files).
- Tags filter supports multi-select and matches all selected tags.
- Tag filter selections persist in-memory across list/editor navigation and must not be cleared while
  tag options are still loading.
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
- Clicking a non-Markdown entry opens metadata-only details with a download link; images also render
  an inline preview.
- Copy URL actions are available next to the editor toolbar buttons (see **Copy URL actions** above).
- The editor header shows sidecar metadata:
- Alias (editable).
- Alias must be URL-safe and cannot start with reserved prefixes (`id/`, `login`, `builtin`, or
  the configured admin path prefix).
- Alias validation runs on change in the editor and shows inline errors; save still re-validates.
- When the details panel is open, pressing Enter in a details field saves and collapses the panel.
- Title.
- Tags.
- Navbar title, parent, and order.
- Theme (if enabled per object; see `docs/content/themes.md` for file format and selection).
- Navbar render state (boolean, default enabled). The public effect is defined in
  `docs/content/content-model.md`.
- Width mode (Markdown only, default `Auto Width`). The public effect is defined in
  `docs/content/content-model.md`.
- Original filename (read-only).
- Saving metadata updates the sidecar without altering blob versions.

#### Markdown Paste-Merge

- Markdown editors include a `Paste-Merge` toolbar action for appending clipboard text to the current
  document.
- Clipboard content is accepted when it is readable text with non-whitespace content; no full Markdown
  validation is required.
- If the existing document has a trailing numbered reference definition block, that block is moved to
  the final end of the document after the pasted body.
- Pasted numbered reference-style link labels and pasted numbered reference definitions are renumbered
  after the highest existing numbered reference label in the document.
- Orphaned pasted in-text reference labels are also renumbered, but no missing definition is created.
  This preserves the pasted text's missing-definition state without making the label point at an
  existing reference.
- After a successful merge, the Markdown editor cursor moves to the end of the pasted body text,
  before the final reference definition block when one exists.
- Markdown editors include a `Link-Card` toolbar action that converts the selected inline Markdown
  link, or the inline Markdown link containing the cursor, into
  `((link-card title="..." link="..." noblank))`. The conversion uses the link label as the
  shortcode title and the link destination as the shortcode link.

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
- The page editor exposes navbar render state as the reusable `Navbar Enabled`/`Navbar Disabled`
  toggle in the details panel. It is independent of `Navbar title`: a disabled-navbar page can still
  have `nav_title`, `nav_parent_id`, and `nav_order` so other pages can link to it from their navbar.
- The page editor exposes floating document navigation render state as a separate reusable
  `Floating Nav Enabled`/`Floating Nav Disabled` toggle. It maps to `disable_floating_nav` and
  suppresses only the page-local document navigation panel and mobile heading links.
- Removing a navbar title from a page that has children must show a warning dialog:
  - "Removing the navbar title from this page will also remove the navbar titles of its children."
  - Actions: Remove / Cancel.
- If a navbar title is cleared, its children lose their navbar titles.
- Navbar edits bump the release tracker (`X-Release`) so cached HTML navigation refreshes, including
  alias changes for navbar items and cascaded child title removals.

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
  - Fonts -> `fonts/<original-filename>`
  - Other files -> `files/<original-filename>`
- Theme font-face rules should reference uploaded fonts by their public alias path, normally
  `/fonts/<original-filename>`.
- If the page has a valid alias, editor uploads default to `<page-alias>/<original-filename>` instead
  of the type-based prefixes.
- Generated aliases are checked against the backend. Alias edits are debounced and checked in the
  background without transient pending text. An existing non-Markdown alias is treated as a pending
  new version instead of being deduplicated or rejected.
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

### CLI Integration

- CLI file operations must use the content management bus domain and never access the filesystem directly.
- Command syntax and CLI examples live in `CLI.md`; this section only defines behavior and constraints.
- `content store` sends `ContentUploadRequest` with ID-first metadata rules (alias optional) and the file bytes as the payload.
- `content store` derives `mime` from the file contents on the server side (no CLI flag).
- `content store` passes tags as tag IDs and relies on existing validation/limits.
- `content store` takes a required positional file argument (last argument). Use `-` to read from standard input.
- `content store` requires a file extension when a filename is provided and fails when missing.
- `content store` requires `--title` for markdown content.
- `content store --disable-navbar` sets the page-level navbar render flag for markdown content.
- `content store --disable-floating-nav` sets the page-level floating document navigation render
  flag for markdown content.
- `content store` sets `original_filename` from the provided file name. When reading from standard input, it generates `cli-store-YYYY-MM-DD-HH-MM-SS.<ext>` where `<ext>` is derived from the detected MIME type (fallback `application/octet-stream` uses `.bin`).
- `content change` targets content by ID only.
- `content change` allows metadata-only updates
  (alias/title/tags/theme/nav/disable-navbar/disable-floating-nav fields as applicable).
- `content change --disable-navbar` sets the flag, and `content change --enable-navbar` clears it.
- `content change --disable-floating-nav` sets the flag, and `content change --enable-floating-nav`
  clears it.
- `content change` accepts an optional positional file argument (last argument) for markdown body updates only; when omitted, it performs a metadata-only change. Use `-` to read markdown content from standard input.
- `content change` rejects content body updates for non-markdown objects (the management bus already enforces this rule).
- `content change` requires markdown file input (`.md`/`.markdown`) when a file path is supplied and rejects empty file/stdin content.
- `content stream` reads content by ID and writes to the required file argument; use `-` to write to standard output.
- `content stream` writes the raw source bytes for Markdown and the raw object bytes for
  non-Markdown content.
- `content stream` sets `stream_content` on `content.read`; connectors may return inline content
  for small Markdown and stream bytes for large Markdown or binary content. CLI bypass streaming
  writes raw bytes from the content blob when the read response carries stream metadata.
- `content delete` deletes by ID only and returns the management bus response message.
- CLI execution must work via the socket connector when the daemon is running.
- CLI execution must work via the CLI bypass connector when no socket is available.

Field applicability:

| Field | Applies To | Notes |
| --- | --- | --- |
| Alias | Markdown + non-markdown | Optional; must pass canonicalization and reserved-path rules. |
| Title | Markdown + non-markdown | Required for markdown; stored in the sidecar for display. |
| Tags | Markdown + non-markdown | Optional list of tag IDs. |
| Theme | Markdown | Used by the renderer; omit for non-markdown assets. |
| Navbar title | Markdown | Required to include a page in navigation. |
| Navbar parent | Markdown | Only valid when navbar title is set; must reference a root navbar item. |
| Navbar order | Markdown | Only valid when navbar title is set. |
| Disable navbar | Markdown | Stores page-level navbar render state; defaults to false. |
| Width mode | Markdown | Stores selected width mode: `auto`, `wide`, or `narrow`. |

### Markdown Create/Update vs Binary Uploads

- Markdown create/update remains on the existing content commands and validation rules, including nav/title/theme/disable-navbar/width-mode handling.
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
- Size enforcement for Markdown create/update uses `upload.max_file_size_mb` (0 = unlimited) with
  no hard-coded total-size caps. Editor read responses still choose inline versus streamed transfer
  using the shared WebSocket response budget.
- Markdown editor reads use `content.read(stream_content = true)` through the admin WebSocket. The
  response includes inline Markdown source when the encoded content-read response fits the shared
  WebSocket response payload budget, which is the common case.
- When the encoded response would exceed the shared inline budget, the response omits inline
  `content`, includes `stream_id`, `chunk_bytes`, and `size_bytes`, and delivers raw Markdown source
  bytes through the generic backend-to-frontend WebSocket blob stream defined in
  `docs/management/connector-socket.md`.
- The admin content service decodes streamed Markdown bytes as UTF-8 before updating the editor.
  Inline and streamed reads must produce byte-identical source text after UTF-8 decoding.
- Oversized Markdown source reads that do not set `stream_content = true` return a content-read
  error instead of attempting to materialize and send a too-large inline response.
- Public `/id/<hex>` and alias URLs are not used for Markdown editor source loads because they serve
  public rendering behavior rather than editable Markdown source.

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
  `render_admin_spa_shell_response` in `nop/crates/nop-admin/src/shared/mod.rs` and populate it in the
  relevant handler.
- Always refresh `PageMetaCache` after content mutations so public navigation stays coherent.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
