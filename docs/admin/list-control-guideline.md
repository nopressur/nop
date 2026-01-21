# Admin List Control Guidelines

Status: Developed

## Objectives

- Standardize list-row interaction behavior across the admin SPA.
- Provide keyboard navigation for list rows with consistent Enter-to-open behavior.
- Define reusable helper functions so list views share the same accessibility and event logic.

## Technical Details

### Row Click Pattern

- Use a clickable row (`tr`) as the primary navigation target.
- Apply `cursor-pointer` + `hover:bg-surface-2` to rows that navigate and keep the row `on:click` handler for navigation.
- Action cells must stop propagation (`on:click|stopPropagation` and `on:keydown|stopPropagation`) so buttons do not trigger row navigation.
- Rows should expose `aria-selected` based on the current selected index for screen readers and styling hooks.

### Keyboard Navigation (Table Rows)

- Use a roving tabindex: only the selected row has `tabindex="0"`, other rows use `tabindex="-1"`.
- Arrow keys move selection:
  - `ArrowDown` selects the next row.
  - `ArrowUp` selects the previous row.
  - Optional: `Home`/`End` move to first/last row.
- `Enter` triggers the same navigation as row click (open the selected item).
- When selection changes, the newly selected row should be focused and scrolled into view (`scrollIntoView({ block: "nearest" })`).
- If focus is inside the action cell, keyboard handling must not hijack action buttons.

### Helper Function Requirements

- List views should use `useListViewLogic` from `nop/ts/admin/src/routes/useListViewLogic.ts`
  to centralize loading/error/delete flows and row navigation wiring.
- Use `createListRowNavigation` from `nop/ts/admin/src/components/listRowNavigation.ts`
  when wiring list views manually.
- The helper exposes a `selectedIndex` store and event handlers:
  - `handleRowClick(index)` to navigate on click.
  - `handleRowFocus(index)` to track focus changes.
  - `handleKeydown(event)` for Arrow/Enter navigation.
- Provide the helper with:
  - `setItemCount(items.length)` to clamp selection when data changes.
  - `setListRef(tbodyRef)` so the helper can focus/scroll the selected row.
- Table rows must include:
  - `data-row-index={index}` for row lookup.
  - `tabindex={$selectedIndex === index ? 0 : -1}` and `aria-selected`.
  - `on:click`, `on:focus`, and `on:keydown` wired to the helper.
- Action cells must include `data-row-actions` plus `on:click|stopPropagation` and
  `on:keydown|stopPropagation` to avoid triggering row navigation.

### Testing Scope

- Unit tests for the helper to verify selection movement and Enter-to-open behavior.
- Update list-view tests (if present) to validate keyboard navigation wiring.
- Playwright E2E checks in:
  - `tests/playwright/tests/e2e/01-users.spec.ts`
  - `tests/playwright/tests/e2e/02-tags.spec.ts`
  - `tests/playwright/tests/e2e/03-content-management.spec.ts`
  - Any additional list-based suites touched by the updates.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
