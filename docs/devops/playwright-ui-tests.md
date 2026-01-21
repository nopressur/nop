# Playwright UI E2E and UX Tests

Status: Developed

## Objectives

- Establish the standard Playwright harness for all UI testing areas.
- Keep runs predictable, repeatable, and isolated in temp runtime roots.
- Split tests into E2E (full Playwright power) and UX (user-visible cues only).
- Humanize all input with randomized per-key typing while remaining deterministic.
- Add UX coverage for core admin navigation and login flows.

## Technical Details

### Flat Storage UI Coverage

- Admin flows must validate ID-based editor routing, alias edits/removals, tag updates, and navigation flags.
- Public flows must validate alias routing, `/id/<hex>` routing, and tag-list pages rendered from shortcodes.

### Suite Types

- **E2E tests**: may use any Playwright feature (network interception, storage state,
  programmatic eval, test IDs, forced actions) to validate system behavior and edge cases.
- **UX tests**: must interact only via user-visible cues and controls
  (roles, labels, placeholders, visible text). No hidden selectors, no `page.evaluate`,
  no force clicks, no test IDs, no DOM queries that are not visible to the user.
- **UX coverage status**: UX rules apply with the SPA navigation model; initial admin UX coverage is in place.

### Location and Scope

- Playwright lives under `tests/playwright` and is the standard harness for all UI testing.
- Tests are not tied to a specific area; new suites should reuse the shared utilities and fixtures.

### Harness and Isolation

- Use a unique temp root per test or suite under `/tmp/nop-test/` with a
  `nopressure-pw-<run-id>` prefix to avoid polluting repo or user state.
- Seed the temp root with `config.yaml`, `users.yaml`, `content/`, `themes/`, and `state/`.
- Launch the server as a child process pointing to the temp root and terminate it
  during teardown; always delete temp roots after the run.
- Ensure all network requests target the local server only; no external network access.
- Keep each test isolated and hermetic; no shared state outside the temp root.

### Data Seeding (Predictable and Repeatable)

- Pre-generate known users in `users.yaml` and roles in `roles.yaml`, including at minimum:
  - `admin` (full access),
  - `editor` (content edit access),
  - `viewer` (read-only).
- Seed content and themes with stable, known fixtures to validate permissions and renders
  (public page, restricted page, tag-based listing, and a basic theme switch).
- Use deterministic fixture names and slugs so assertions stay consistent across runs.

### Humanized Input (both suites)

- No rapid-fire steps and no full-text `fill` calls for user input fields.
- Use a shared `humanType` helper that emits per-key presses with randomized delays.
- Randomization must be deterministic: use a seeded RNG derived from test name or
  an explicit environment variable so runs are repeatable.
- Use `locator.click()` with natural waits for visible state; prefer UI state assertions
  over hard sleeps. If waits are needed, keep them small and deterministic.

### Shared Utilities (Reusable)

- Utilities must be shared across suites, including:
  - `createTempRoot()` to build and clean the fixture runtime root under `/tmp/nop-test/`.
  - `seedFixtureData()` to write config, users, roles, content, and themes.
  - `launchServer()` to start and stop the Actix process for the temp root.
  - `humanType()` and `humanClick()` to enforce humanized input rules.
  - `loginAs()` helpers that reuse seeded users instead of ad-hoc data.

### E2E Coverage (Initial Baseline)

- **00 smoke test**: render a known public page and validate a stable element to prove the harness.
- **User flows**: login/logout, role-based access checks for admin/editor/viewer, user CRUD, user listing,
  login SPA error states + return-path fallback, profile password error states + logout.
- **Content flows**: paginated file list, title search, Markdown/all filter, sidecar metadata edit,
  upload overlay + multi-file modal, upload tag defaulting, editor drag/drop insertion,
  insert modal keyboard flows and insertion mode selection.

### UX Coverage (Current)

- **Admin navigation**: login, content list, content editor, tag list/editor, theme list/customize, user list/editor.

### Artifacts

- E2E: capture video + trace on failure, screenshots on all failures.
- UX: capture screenshots on failure, optional trace (once UX tests exist).

### Environments

- Headless by default; allow headed runs for debugging.
- Stable timeouts, no dependency on system clock or external services.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
