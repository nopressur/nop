# Search UX and Public API

Status: Developed

## Objectives

- Define the content-domain search user experience for the public site.
- Define the public search API contract used by the site TypeScript bundle.
- Keep infrastructure indexing/query internals in `docs/infrastructure/search.md`, while documenting
  public endpoint and frontend behavior here.
- Enforce public query length bounds (`min=3`, `max=256`) on both backend and frontend.
- Prevent internal error details from being exposed in API error responses while preserving server-side logging.

## Technical Details

### Scope and Ownership

- This document owns:
  - public HTTP search endpoint contract (`/api/search`);
  - public-site search interaction and overlay behavior;
  - TypeScript integration points for the site bundle.
- This document does not own:
  - Tantivy index internals, ingestion worker design, reindex mechanics, or storage layout
    (`docs/infrastructure/search.md` and `docs/infrastructure/search-ingest.md`);
  - admin-side search transport and UX (out of scope for this document).

### Public Search API

Endpoint:

- `GET /api/search`

Request contract:

- Query parameter: `q` (string).
- Query length must be between `3` and `256` characters (after trimming leading/trailing whitespace).
- The endpoint is public-facing and uses the search module public query capability.
- Public query semantics are RBAC-filtered and tag-excluded, as defined by infrastructure.

Response contract:

- JSON array of hits.
- Each hit contains:
  - `id` (canonical content ID, hex string);
  - `alias` (canonical alias when present; may be empty);
  - `title` (display title).
- URL is not returned explicitly:
  - alias is the route when present;
  - `id` is always sufficient to construct `/id/<hex>`.

Behavioral requirements:

- API path is `/api/search` (public only).
- `len(trim(q)) < 3` or `len(trim(q)) > 256` returns `400 Bad Request`.
- Internal query execution failures return `500 Internal Server Error` with generic client-facing text.
- Detailed internal failure causes must be written to server logs and must not be returned in API JSON.
- Admin-side API/UX flows are out of scope for this document.

### Public Query Bounds and Error Handling

- Backend validation is authoritative and must be applied in the public endpoint handler before invoking search infrastructure.
- Frontend validation is UX support only; it reduces invalid requests but is not the security boundary.
- Shared bounds for this feature:
  - minimum: `3` characters
  - maximum: `256` characters
- Frontend enforcement contract:
  - do not issue `/api/search` requests for queries shorter than `3`;
  - clamp/limit query input to `256` characters before request dispatch;
  - preserve existing debounce and in-flight cancellation behavior.
- Backend error response contract:
  - `400` returns a validation message suitable for clients;
  - `500` returns a generic message without internal parser/service details;
  - internal error details are logged with context (for example query length) in server logs.

### Frontend Search UX

The public site supports two entry paths into search:

1. Passive typing trigger:
   - when a public page is open, user typing is interpreted as the start of a search query.
2. Explicit trigger:
   - a search button opens the search overlay.
3. Keyboard shortcuts:
   - `/` opens the overlay without seeding a query and works even when focus is on `audio` or
     `video` elements.
   - `Ctrl+/` or `Cmd+/` opens the overlay from any focus target, including inputs and selects.

Responsive trigger rules:

- Desktop/tablet:
  - passive typing trigger is enabled;
  - search button is also available.
- Mobile:
  - search button is available and visible;
  - passive typing trigger remains enabled when keyboard input events are available (for example,
    external keyboard use on phone/tablet).

Search button placement:

- Search button is always visible in the navbar at every breakpoint.
- Search button must not be placed inside the hamburger/collapsed menu.
- In mobile view, the search button remains directly accessible without opening the menu.
- Button visual is icon-only (magnifying glass).
- Icon source is inline SVG in the site template/component (theme-colored via `currentColor`), not a
  Unicode glyph.
- Accessibility requirements for icon-only button:
  - `aria-label="Search"`
  - keyboard focusable and visually focus-indicated.

Overlay requirements:

- Rendered centered on screen.
- Uses a prominent, larger-font query input.
- Displays type-ahead search results only after the query reaches at least 3 characters.
- When open, focus is trapped inside the overlay until close.
- When open, page-body scrolling is locked; scroll behavior is restored on close.

Result behavior:

- Result list uses the API payload (`id`, `alias`, `title`).
- Navigation target resolution:
  - if `alias` is present: navigate to `/<alias>`;
  - otherwise: navigate to `/id/<id>`.

### Frontend Integration (No Framework Addition)

- Search UX is implemented in the existing site TypeScript bundle under `nop/ts/site/src/`.
- No JavaScript framework is introduced for this feature.
- Expected integration points:
  - `nop/ts/site/src/main.ts` initializes a new search module alongside existing navigation/user
    menu initialization;
  - `nop/src/public/templates/main_layout.html` hosts required search trigger/overlay mount
    elements (data-attribute based);
  - output remains the compiled site bundle served as `site.js`.

### Query Timing Contract

- The frontend enforces minimum query length before search requests:
  - `len(q) < 3`: no search request, and no results/empty-state/error-state UI is shown.
  - `3 <= len(q) <= 256`: call `/api/search?q=...` and render returned hits.
  - `len(q) > 256`: clamp to `256` before issuing request.
- Search requests are debounced on input changes:
  - trailing debounce delay: `250ms`;
  - new keystrokes reset the debounce timer.
- Passive typing guard:
  - passive typing trigger does not activate when the event target is `input`, `textarea`, `select`,
    `video`, `audio`, or an editable element (`contenteditable`).
- In-flight request handling:
  - when a new debounced request is issued, any previous in-flight request is cancelled;
  - stale responses from older requests are ignored and must not overwrite newer results.
- When input drops below 3 characters:
  - cancel any in-flight request;
  - clear visible results and return overlay to idle state.

### Theme and Overlay Behavior

- The search overlay must follow existing theme variables used by the public site so it stays
  visually consistent with the active page theme.
- Overlay colors and typography must be derived from existing light/dark variable sets from theme
  files (`*.theme`) and `theme-preset.css`; this feature must not introduce a separate theme source.
- No new theme variables are added for search overlay styling in this scope.
- Dark-mode behavior follows the same `prefers-color-scheme: dark` pattern already used by the site
  preset stylesheet.
- If the system light/dark preference changes while the overlay is open, overlay styling updates via
  CSS only; query text, focus state, and current results remain intact.

Overlay visual effects:

- Opening the overlay fades in a full-screen backdrop.
- Backdrop applies blur to underlying page content (`backdrop-filter: blur(6px)`), with a color
  fade layer.
- If blur is unavailable in the browser, the color fade remains and must keep text legible.

Theme variable mapping (light/dark):

- Backdrop fade:
  - base color: `color-background-primary-light` / `color-background-primary-dark`
  - rendered as alpha overlay (target ~65% opacity).
- Overlay panel:
  - background: `color-content-background-light` / `color-content-background-dark`
  - border: `color-border-light` / `color-border-dark`
  - shadow: `color-shadow-light` / `color-shadow-dark`
- Query input:
  - background: `color-background-secondary-light` / `color-background-secondary-dark`
  - border: `color-border-light` / `color-border-dark`
  - text: `color-text-primary-light` / `color-text-primary-dark`
  - placeholder: `color-text-secondary-light` / `color-text-secondary-dark`
- Results list container:
  - background: `color-content-background-light` / `color-content-background-dark`
  - border/separators: `color-border-light` / `color-border-dark`
- Result entry text:
  - title: `color-text-primary-light` / `color-text-primary-dark`
  - secondary/meta text: `color-text-secondary-light` / `color-text-secondary-dark`
- Active/hovered result entry:
  - background: `color-background-secondary-light` / `color-background-secondary-dark`
  - optional accent (selected row marker or matched text): `color-content-link-light` /
    `color-content-link-dark`
- Overlay typography:
  - query input + result text use `font-body-family`
  - optional section labels use `font-heading-family`

### Cross-Module Contract

- Backend public endpoint uses the infrastructure query API intended for public consumers.
- Public flow applies RBAC-filtered query behavior.
- Admin-side integration remains out of scope for this document.

### Keyboard Interaction Contract

- Regular character input:
  - updates the query text in the search input;
  - triggers the normal debounced search request flow;
  - clears active result selection so navigation focus returns to the new query result set.
- `ArrowDown`:
  - when results are visible, move active selection to the next result;
  - if selection is on the last result, wrap to the first result;
  - if nothing is selected, select the first result.
- `ArrowUp`:
  - when results are visible, move active selection to the previous result;
  - if selection is on the first result, wrap to the last result;
  - if nothing is selected, select the last result.
- `Enter`:
  - when a result is selected, navigate to that result;
  - when no result is selected, no navigation occurs.
- `Escape`:
  - closes the overlay;
  - clears active selection and results view state.
- Keyboard navigation updates visual active-row styling and scrolls the active row into view when needed.
- While overlay is open, keyboard handling for these keys is owned by the search module.

### Empty and Error States

- Empty results state text: `No results`.
- Empty results state is shown only when `len(q) >= 3` and a completed search response contains
  zero hits.
- For `len(q) < 3`, overlay shows no results content at all (no `No results` text).
- Search failure state text: `Search didn't work.`.
- Search request errors are logged to browser console with `console.error(...)` and include enough
  context to diagnose request failures.
- API `500` responses must not include internal service error details in client-visible text.

### Testing Scope

- Backend API integration tests:
  - `/api/search` returns only RBAC-allowed public results;
  - tag-only query terms do not produce public matches;
  - response payload includes `id`, `alias`, `title` and excludes URL field.
  - invalid query lengths (`<3`, `>256`, and missing/blank after trim) return `400`.
- Frontend TypeScript tests:
  - typing trigger opens/focuses search overlay;
  - search button opens overlay;
  - search button remains visible at mobile breakpoints and is not moved into hamburger content;
  - `/` opens the overlay (including when focus is on `audio`/`video`);
  - `Ctrl+/` and `Cmd+/` open the overlay from editable targets;
  - passive typing trigger remains available when keyboard input events are produced on mobile/tablet;
  - passive typing guard ignores key events from
    `input`/`textarea`/`select`/`video`/`audio`/`contenteditable` targets;
  - query threshold (`>= 3`) gates network requests;
  - query maximum length (`256`) is enforced before request dispatch;
  - query length below threshold renders no results content (including no `No results` text);
  - debounce delay (`250ms`) coalesces rapid typing into a single request;
  - in-flight cancellation/stale response protection preserves latest-result correctness;
  - keyboard support:
    - regular character typing updates query, triggers debounced search, and clears active selection;
    - `ArrowUp`/`ArrowDown` changes active result selection with wrap-around at list edges;
    - `Enter` opens selected result;
    - `Escape` closes overlay and clears active state;
  - focus trapping and body scroll lock apply while overlay is open and restore on close;
  - overlay styles remain readable/consistent in both light and dark theme modes;
  - backdrop fade is rendered and blur gracefully degrades when unsupported;
  - empty and error state copy renders as specified;
  - search request failures emit `console.error` logging;
  - result selection resolves alias/ID routing correctly.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
