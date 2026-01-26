# Admin UI

Status: Developed

## Objectives

- Replace the server-rendered admin UI (Bulma + Alpine + MiniJinja) with a Svelte 5 SPA.
- Keep full admin feature parity (content, tags, themes, users); login/profile remain separate and use the login SPA shell.
- Centralize WebSocket, REST, and CSRF handling in a single TypeScript transport layer.
- Migrate all frontend code to TypeScript and refresh the visual system with Tailwind.
- Ensure the SPA build is embedded into the Rust binary (reuse existing builtin asset pipeline).
- Reduce admin UI complexity by consolidating shared behaviors and removing legacy assets.

## Technical Details

### Admin UX refinements

- Content list search should update rows in place without clearing the table while fetching.
- Editor UX:
  - Provide a Close/Cancel action plus Escape behavior that opens an unsaved-changes modal when edits exist.
    - Modal actions: Save (persist and return to list), Discard (return to list), Cancel (stay).
    - When no edits exist, the action label reads `Close`.
    - Keyboard (modal only): Escape = Cancel, Enter = Save, D = Discard.
  - Support Cmd/Ctrl+S to save in place (prevent default browser behavior).
  - Cancel/Escape return to the last list/filter state stored in memory (not query params or session).
  - Keep the title input always visible and editable.
  - Collapse sidecar fields behind a right-aligned chevron toggle that expands downward.
- Form controls:
  - Theme selection uses a dropdown populated from a lightweight REST endpoint that returns theme names.
  - Navbar fields include title, parent selection, and numeric order.
  - Tags use a chip-style multi-select from existing tags; missing tags are removed and not shown.
  - Tag roles use a chip-style multi-select from existing roles (`roles.yaml`).
- Table UX:
  - Action buttons (edit/delete) must not trigger row navigation.
  - Disabled actions are visually distinct from enabled actions (for example, current-user delete).
  - Default theme cannot be deleted.
  - List row interaction and keyboard navigation follow `docs/admin/list-control-guideline.md`.
  - Content list headers are clickable for sorting (pointer cursor).
  - Active sort header uses stronger contrast (lighter in dark mode, darker in light mode) and a small arrow indicator.
- Upload UX:
- Upload buttons open a full-screen drop zone overlay with a keyboard-accessible file picker.
- The upload modal supports multiple files with per-file save/cancel, plus "Save all" controls when
    more than one file is queued.
- The content list includes a multi-select tag filter that matches all selected tags and seeds
  default tags for new uploads.
  - Binary uploads run a two-step validation:
    - Pre-validation (filename, mime, size) builds placeholder blocks for rejected files.
    - Upload validation (alias, tags, filename, mime, size) runs on Save/Enter before streaming.
  - Upload progress replaces only the active item; errors restore the editor block with a message.
  - Enter uploads a single item; "Save all" uploads sequentially; the modal closes when all succeed.

### Navbar Fields

- Replace the legacy nav checkbox with:
  - `Navbar title` (text input).
  - `Navbar parent` (select from pages that have a navbar title and no parent).
  - `Navbar order` (integer input).
- Populate the parent selector from the content management WebSocket using content IDs (`content.nav_index`).
- Clearing a parent navbar title must warn and cascade to children.

### SPA Architecture
#### SPA shell and runtime config

- Serve a single SPA shell HTML for all admin routes (except login). The shell is a MiniJinja template
  (`nop/src/admin/templates/spa_shell.html`) and mounts the app into a single root element (for example
  `<div id="admin-app"></div>`).
- Inline a runtime config object so the SPA never hardcodes `/admin`:
  - `adminPath`, `appName`, `csrfTokenPath`, `wsPath`, `wsTicketPath`.
  - `userManagementEnabled` derived from server-side OIDC config.
- Expose the CSP nonce as `window.nopAdminCspNonce` so the admin SPA can attach it to
  dynamically-inserted styles (for example, Ace themes).
- Inline optional bootstrap data (`window.nopAdminBootstrap`) for server-provided payloads (for example,
  theme list data on `/themes`, theme content on `/themes/new` and `/themes/customize/:theme`, and
  errors on missing themes).
- The admin shell also includes the authenticated user's email for UI-only guardrails (for example,
  self-delete disabling). This value is held in memory only; admin identity must never be cached in
  `sessionStorage` or `localStorage`.
- Keep backend endpoints and auth middleware unchanged; only the HTML shell replaces per-page SSR.

#### Routing and navigation

- History API routing with a configurable base path (`adminPath`).
- Default route `/` redirects to `/pages` inside the SPA.
- Client-side guards:
  - Hide Users navigation when `userManagementEnabled` is false.
  - Redirect `/users*` to `/pages` when users are disabled.
- Keep existing query params for compatibility where they remain in use (for example,
  `/tags/edit?id=...`).

#### App structure (TypeScript only)

- `nop/ts/admin/src/app/App.svelte` provides layout, navigation, and route outlet.
- `nop/ts/admin/src/routes/*` holds view-level routes (content, tags, users, themes).
- `nop/ts/admin/src/components/*` contains shared UI (tables, forms, modals, notification, editors).
- `nop/ts/admin/src/stores/*` provides global state (runtime config, notifications, modal stack).
- `nop/ts/admin/src/services/*` encapsulates domain logic (content, tags, users, themes).
- `nop/ts/admin/src/transport/*` holds the centralized WebSocket + REST + CSRF clients.

#### Component conventions

- Shared components dispatch Svelte events for interaction (`createEventDispatcher` + `on:` handlers)
  instead of callback props, with payloads provided via `event.detail`.
- Store access uses exported store objects (for example, `route`, `notifications`) and `$store`/`get()`
  for reads; avoid wrapper getters or ad-hoc set/reset helpers.
- Browser APIs are accessed through `nop/ts/admin/src/services/browser.ts` for timeouts, listeners,
  location navigation, and storage access.
- Confirmations use the shared Svelte modal (no native `window.confirm` dialogs).

#### Centralized transport layer

- `transport/csrf.ts` handles token caching, refresh on 403, and exposes `getCsrfToken()`.
- `transport/wsClient.ts` wraps the WebSocket coordinator:
  - Fetches CSRF token and WS ticket.
  - Performs auth handshake and request/response routing.
  - Handles stream chunk acknowledgements.
- `transport/restClient.ts` wraps `fetch` with CSRF headers, standard error mapping, and retries.
- All mutating admin requests (including WS ticket requests) must go through the CSRF-aware transport
  (no raw `fetch` in the SPA).
- WebSocket and REST endpoints remain unchanged from the existing admin UI.

#### Admin Session and CSRF Integration

- Admin routes are guarded by `RequireAdminMiddleware`:
  - Unauthenticated requests redirect to `/login?return_path=<current path>`.
  - Authenticated non-admins redirect to `/`.
  - Dev-mode bypass is allowed only in debug builds with localhost settings (release builds ignore it).
- The admin SPA uses the same JWT cookie as the public site; no separate admin session cookie is minted.
- The authenticated WebSocket session is the authoritative source of the acting user identity; the
  client does not send identity fields in management requests.
- Login return-path validation only allows `/`, `/id/<hex>`, known markdown aliases, or admin paths for admins; invalid values default to `/`.
- CSRF flow for the SPA:
  - Fetch token from `<admin_path>/csrf-token-api`.
  - Include `X-CSRF-Token` for mutating REST calls and for `POST <admin_path>/ws-ticket`.
  - WebSocket auth frames include both the CSRF token and the short-lived ticket obtained from `<admin_path>/ws-ticket`.
- Keep mutating admin endpoints under the admin scope so admin + CSRF middleware apply automatically.

#### Protocol and validation

- Protocol encoders/decoders live under `src/protocol/`:
  - `content`, `tags`, `users`, and `ws` frame codecs.
- Validation helpers live in `src/validation/`:
  - Alias normalization, tag ID validation, role validation (see `docs/content/role-management.md`),
    file name validation.
  - All validation helpers return `{ valid, value?, error? }` results (normalized output lives in
    `value`).
  - The `admin` role is reserved and immutable; disable rename/delete actions and surface that it is
    locked (see `docs/content/role-management.md`).

#### Editor integration

- Ace is wrapped as a Svelte component to preserve existing editing behaviors.
- The editor API supports:
  - Setting/getting content.
  - Cursor tracking for upload insertions.
  - Theme selection based on system preference.

#### Editor Insert Modal

- Cmd/Ctrl+Shift+I opens a modal for inserting links or embeds at the cursor.
- The modal provides:
  - A type-ahead search field that filters the content list.
  - A tag filter that defaults to the page’s first tag (if set) and filters results.
  - A keyboard-controllable results list with Up/Down and Page Up/Down navigation.
- The modal includes explicit Insert and Cancel buttons.
- Selecting an item does not close the modal; users must confirm insertion.
- Insertion modes depend on the selected item:
  - Images: link or Markdown image.
  - Videos: link or `video` shortcode.
  - Markdown/other files: link only.
- Link insertion uses the best available display text: title first, then alias, then ID.
- The insertion mode control is a left/right toggle, keyboard reachable with Tab:
  - When only link is valid, the control is disabled and removed from tab order.
- Enter confirms insertion, Escape closes the modal, and Shift+Tab cycles backward through fields.

### ID-First Editor Routing

- Content editor routes must use ID path parameters (for example, `/admin/pages/edit/<id>`).
- Alias query parameters are no longer required for editor addressing.
- Content services should resolve and mutate content by ID; alias is optional metadata only.
- Content list navigation should use IDs even when aliases are present.
- Insert modal and upload insertions must use `/alias` when present, otherwise `/id/<hex>` for all
  content types.

#### UI system and cleanup

- Tailwind (core utilities only) defines the visual system. No Bulma usage.
- Use system light/dark preferences only (no manual toggle) and keep sharp edges with a small radius.
- Prefer compact controls with consistent sizing to maximize editor/listing space.
- Shared components replace current duplicated JS helpers:
  - `NotificationToaster`, `Pagination`, `Button`, `Input`, `Select`, `AceEditor`.
- Toast notifications must emit a console log with the same message and a tone-based severity.
- Legacy global utilities are removed after the SPA cutover.

### Build Pipeline and Embedding

- The Svelte 5 + TypeScript project lives under `nop/ts/admin/`.
- Vite output goes to `nop/builtin/admin/` to preserve the existing Rust embed pipeline:
  - Deterministic, non-hashed file names (for example `admin-spa.js`, `admin-spa.css`).
  - `emptyOutDir: false` to avoid deleting login/profile assets stored in `nop/builtin/admin/`.
  - `base: "/builtin/admin/"` so asset URLs resolve in both dev and release.
- Tailwind is built via PostCSS within the SPA project, emitting a single CSS file.
- `nop/ts/admin/src/app.css` uses Tailwind v4 CSS-first directives (`@import`, `@config`, `@source`).
- `nop/build.rs` runs `npm run build` when the SPA output is missing or older than its sources.
- Release builds embed SPA assets via the existing `nop/build.rs` scan of `nop/builtin/`.
- Dev mode uses the filesystem-served assets automatically (no embed changes required).
- Serve admin HTML and builtin admin assets with `Cache-Control: no-store`.

### Required Parity Features (SPA scope)

- Content list with search, filters, pagination, and delete.
- Content editor with metadata, markdown editor, upload overlay + modal, drag/drop insertion,
  insert modal with search, tag filtering, and insertion modes.
- Tag list and editor with validation and access rule support.
- Role list and editor with rename/delete workflows and warnings.
- User list and editor with role management and password hashing.
- Theme list, create, customize, and delete flows (via REST unless moved to WS).
- Responsive navigation and shared notification system.

### Route and Component Map

- `/admin` -> redirect to `/admin/pages` (client-side).
- `/admin/pages` -> `ContentListView` with search/filter controls, table listing, and pagination.
- `/admin/pages/new` -> `ContentEditorView` (create mode).
- `/admin/pages/edit/<id>` -> `ContentEditorView` (edit mode).
- `/admin/tags` -> `TagListView` with list and delete controls.
- `/admin/tags/new` -> `TagEditorView` with validation and access rule controls.
- `/admin/tags/edit?id=...` -> `TagEditorView` (edit mode).
- `/admin/roles` -> `RoleListView` with list + delete controls.
- `/admin/roles/new` -> `RoleEditorView` (create mode).
- `/admin/roles/edit?role=...` -> `RoleEditorView` (edit mode).
- `/admin/users` -> `UserListView` with list + role summaries (hidden when OIDC is enabled).
- `/admin/users/new` -> `UserEditorView` (create mode).
- `/admin/users/edit/:email` -> `UserEditorView` (edit mode).
- `/admin/themes` -> `ThemeListView` with list + delete controls.
- `/admin/themes/new` -> `ThemeEditorView` (create mode) with theme name + HTML editor.
- `/admin/themes/customize/:theme` -> `ThemeEditorView` (edit mode) with HTML editor.

### Documentation Coverage

Admin extensibility guidance lives in `docs/content/content-management.md` and
`docs/admin/user-management.md`; backend details remain in their authoritative docs (management bus,
CSRF, etc.).

### Testing Scope

- Playwright admin tests drive the SPA screens (`tests/playwright`).
- UX navigation lives in `tests/playwright/tests/ux/01-admin-navigation.spec.ts`.
- WebSocket handshake, CSRF refresh, and REST theme flows are covered.
- Role-based access and OIDC behavior are validated (user management redirects or hides when OIDC is enabled).
- SPA build verification relies on builtin asset embedding in release builds.
- Protocol codecs and validation helpers have unit coverage in the SPA workspace (`nop/ts/admin`).

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
