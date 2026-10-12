# Chip Select

Status: Developed

## Objectives

- Replace the `ChipSelect` dropdown with a filter field plus clickable unselected chips; active chips render green/success and stay removable.
- Show top-used tags beside the filter from backend usage counts, with the full alphabetical list in a horizontally scrollable row below; a tag may appear in both rows.
- In filter mode show only the matching alphabetical subset; selecting a chip never clears the filter.
- Collapse intelligently: when all unselected chips fit in one row, render that row only with no filter and no top row; roles (no counts) degrade to alphabetical-only.
- Serve content-editor tags and tag-editor roles from the one shared component, carrying `usage_count` in the existing tag-list response, memory-only, sourced from the page cache.

## Technical Details

### Scope and non-goals

- In scope: `ChipSelect.svelte` and its two consumers, page tags in `ContentEditorView.svelte` and roles in `TagEditorView.svelte`.
- Out of scope: `CompactMultiSelect` (content-list tag filter, upload-modal per-file tags) and `InsertContentModal`; the `content-management.md` upload-modal dropdown line stays valid.

### UI contract

- Row 0 (top): active chips, success/green, each with a remove button (`aria-label="Remove <value>"`); empty selection renders `emptyLabel` (`No tags` / `No roles`).
- Row 1: filter field (max 150px wide) plus top-used grey chips; whole chips only, never clipped, wrapped, or overflowed.
- Row 2: all unselected options alphabetically in a single non-wrapping row with horizontal scroll only (`min-w-0 w-full overflow-x-auto overflow-y-hidden`, chip-tall plus anti-clip padding, no vertical growth). The bounded width is required so the row scrolls inside the card on viewports below `md` instead of stretching the details grid.
- Filter mode (non-empty text): the filter field plus row 2 showing only matches; row 1 top chips are hidden while filtering.
- Filtered-empty shows a muted `No matches` note in the row 2 area; fully empty options render only `emptyLabel` with no filter or rows.
- `disabled` disables the filter input and all chip buttons, preserving current disabled semantics including the loading state.

### Collapse and fit rules

- If every unselected chip fits in one row, render that single alphabetical row only: no filter field and no top row. This applies in both count and no-count modes.
- Otherwise render the filter field; the top row shows as many top-used candidates as fit whole, and row 2 shows the full alphabetical list.
- No-count mode (roles) never renders a top row: alphabetical row only, with the filter field appearing only when the list overflows one row.
- Fit is measured, not guessed: a `ResizeObserver` on the row container re-evaluates on resize, option, selection, and filter changes.
- When measurement is unavailable (widths read 0, e.g. jsdom), fall back to showing all candidates: the fallback must never hide an option.

### Filter behavior

- Match is a case-sensitive substring anywhere in the option (`includes`), sorted with `localeCompare` as today.
- Selecting a chip appends it to `selected` (selection order preserved) and leaves the filter text untouched; the chip drops out of the grey lists live.
- Focusing the filter field preselects its text (`input.select()`), so one keystroke replaces it and one click/arrow press continues editing.
- The filter field reuses `SearchInput.svelte`, which already provides the clear button, `input`/`change` dispatches, and error styling.
- Placeholders: `Filter tags` / `Filter roles`; loading keeps `Loading tags...` with the control disabled.

### Component API

- Keep the existing props (`options`, `selected`, `disabled`, `placeholder`, `emptyLabel`, `id`) and add `counts: Record<string, number> | undefined`.
- `counts` present means tag mode (top row enabled); `undefined` means role mode (alphabetical only).
- The `id` prop moves to the filter input so the existing `<label for="content-tags">` / `<label for="tag-roles">` associations and the `#content-tags` / `#tag-roles` Playwright locators keep working.
- Grey chips are real `<button>` elements with `aria-label="Add <value>"`; unselected options never render as non-interactive spans.
- Keep Svelte legacy syntax (`export let`, `$:`) to match the file and its siblings; reach `window`/`document` only through `services/browser.ts`.

### Layout helpers

- New `nop/ts/admin/src/components/chipSelect.ts` holds the pure, unit-tested logic; the component only measures and renders.
- `filterChips(options, selected, filter)`: excludes selected, applies the case-sensitive substring, sorts with `localeCompare`.
- `topChips(options, selected, counts)`: unselected options with count > 0, sorted by count descending then `localeCompare`; no fixed Top-N, truncation is by fit only.
- `fitChipCount(availableWidth, chipWidths, gap)`: returns how many leading chips fit whole given the measured widths and the row gap.

### Call-site wiring

- `ContentEditorView.svelte` `loadTags` keeps alphabetical `availableTags` and additionally builds `tagCounts: Record<string, number>` from the new `usage_count` field, passed as `counts`.
- `TagEditorView.svelte` passes `options`/`selected` as today with no `counts` prop.
- Both views keep their `syncTagsWithAvailable`-style pruning behavior; no save-path or validation changes.

### Backend: usage counts

- Counts come from the existing in-memory `tag_index: HashMap<String, Vec<ContentKey>>` in `PageMetaCache`: usage of a tag is its entry length.
- The index is populated at startup (`PageMetaCache::rebuild_cache` in `main.rs`) and rebuilt on every content/tag mutation via `invalidate_cache`, so counts stay correct with zero new tracking and zero persistence.
- New `PageMetaCache::tag_usage_counts() -> HashMap<String, u32>` clones lengths under the existing read lock; on lock poisoning it logs with the established `CRITICAL` pattern and returns empty.
- `handle_list` joins the `TagStore` snapshot with the counts map; tags absent from the index report 0 and are excluded from the top row by the frontend rule above.
- Read cost is O(#tags) per list call; write-path cost is zero marginal because the `tag_index` insert already happens during rescan.

### Wire format

- `TagSummary` is `{ id: string, name: string, usage_count: u32 }`, encoded in that field order on both sides.
- Rust: extend `WireEncode`/`WireDecode` for `TagSummary` in `nop-management-contract`; TS: extend `decodeTagListResponse` (and any encoder) with `readU32`/`writeU32`; `ensureFullyConsumed` stays enforced.
- Regenerate `management-wire-vectors.json` via the `management_wire_vectors` binary after updating `tag_entries`; both vector suites must pass unchanged in shape.
- All wire peers (server, embedded admin SPA, CLI) ship in one binary, so this lockstep field addition needs no compat shim.

### Accessibility

- Chips and the clear button are keyboard-operable native buttons with visible focus; no `page.evaluate` or pointer-only paths in tests.
- The filter input keeps its programmatic label; rows use plain flex layout with no roving tabindex (unlike table rows in `list-control-guideline.md`, chips are independent actions).
- Decorative marks (`x`, checkmarks) stay `aria-hidden` with the accessible name on the button.

### Styling

- Active chips mirror the `StateToggle` success variant: transparent background with `border-success`/`text-success`.
- Unselected chips keep the current neutral treatment (`border-border bg-surface-2 text-text`) with a hover state toward `text-text`.
- Row 1 filter wrapper is capped at 150px; rows use the existing `gap-2` spacing so the `fitChipCount` gap constant matches the rendered CSS.
- The filter field renders compact (`SearchInput` `compact` prop: `text-xs` with chip padding, no fixed control height) so row 1 stays chip-tall.
- The root, filter row, and alphabetical row are `min-w-0 w-full` so they shrink to the editor card. Call sites put the same constraint on the details grid (`grid-cols-1 md:grid-cols-2`, which is `minmax(0, 1fr)` at every breakpoint) and on the tags/roles wrappers.
- Rows 1 and 2 carry `py-0.5` anti-clip padding so chip bottoms never touch the overflow clip edge; row 1 additionally centers its content. The alphabetical row also uses `overflow-y-hidden` and `overscroll-x-contain` so it stays a horizontal scrollport.

### Testing scope

- Rust: `tag_usage_counts` unit tests (counts, zero/absent tags); `admin_tags.rs` integration (list returns counts; counts track content create/update/delete/rename); Rust + TS wire-vector suites.
- Vitest: helper unit tests plus `ChipSelect.test.ts` covering filter narrowing, select-keeps-filter, focus preselect, clear button, top-row ordering, single-row collapse and overflow via mocked element widths, no-count mode, empty states, and `min-w-0 w-full` on the root and alphabetical row.
- View tests: update tag/role interactions in `ContentEditorView.test.ts` and `TagEditorView.test.ts`; `npm run check` and `npm run test` green with zero a11y warnings.
- Playwright: convert `#content-tags` `selectOption` and `#tag-roles` flows to type/click chip interactions; assert rendered top-row order by usage, filter narrowing, collapse with few tags, and horizontal-only scroll of row 2; assert filter-to-chip height match and no vertical overflow of either row. At a 390px viewport, assert row 2 is bounded by the viewport and still scrolls internally, title and alias inputs stay within the viewport, and the document width stays below the chip-strip scroll width.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
