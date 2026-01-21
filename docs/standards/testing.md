# Testing Standards

Reliable tests keep regressions out and make changes easier for AI assistants to reason about. This guide covers expectations for unit, integration, frontend, and end-to-end tests.

## Core Principles

- Tests must be **deterministic** and **hermetic**: no external network calls, stable filesystem fixtures, predictable random values.
- Prefer **table-driven** tests for parsing, validation, and helpers.
- Name tests by behaviour (`saves_markdown_sidecar`, `rejects_invalid_csrf_header`).
- Run the baseline suite locally before PRs:
  ```bash
  scripts/cargo.sh fmt --all
  scripts/cargo.sh clippy -- -D warnings
  scripts/cargo.sh test
  ```
- When changing the admin SPA, also run `cd nop/ts/admin && npm run test` (and `npm run check` for type validation).

## Unit Tests

- Place unit tests alongside the code in `#[cfg(test)] mod tests` blocks.
- Keep small, pure unit tests inline; when a module grows heavy, move multi-step tests into a sibling `tests.rs` submodule and leave unit tests in the main file.
- Use `actix_web::test` to simulate requests/responses when testing handlers.
- For async tests, use `#[actix_web::test]` or `#[tokio::test]` as appropriate.
- Mock dependencies by:
  - Supplying simplified configs (see helpers in `nop/tests/common`).
  - Seeding runtime roots with `util::test_fixtures::TestFixtureRoot`.
  - Building full app state via `TestHarness` in `nop/tests/common` when a handler needs auth/cache wiring.
- Validate logging via expected state changes, not string matching (unless necessary).
- Example structure:
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[actix_web::test]
      async fn returns_404_for_missing_page() {
          // arrange
          let req = TestRequest::get().uri("/missing").to_http_request();
          // act
          let response = handle_route(req, config, cache, registry).await.unwrap();
          // assert
          assert_eq!(response.status(), StatusCode::NOT_FOUND);
      }
  }
  ```

## Integration Tests

- Use the `tests/` directory at the crate root (`nop/tests/`) for cross-module integration tests.
- Integration tests import the crate via `nop::...` (see `nop/src/lib.rs` for the exposed module surface).
- Boot a minimal Actix app via `test::init_service(App::new()...)` with in-memory or fixture-root assets.
- Use the shared harness in `nop/tests/common/mod.rs` for API-level suites (auth, admin APIs, public render/assets, security).
- Validate multiple components together—for example:
  - Markdown rendering + navigation output.
  - Management bus uploads updating the page cache.
  - Admin page lifecycle (create/edit/delete) reflected in public cache state.
- When filesystem state matters, build fixtures under `target/test-fixtures` using `TestFixtureRoot` to avoid `/tmp` and keep paths deterministic.
- Run integration tests with `scripts/cargo.sh test --tests`.

## Frontend (SPA) Tests

- All current and future SPAs must ship unit + integration tests (Vitest or equivalent).
- Playwright remains the end-to-end layer; it does not replace SPA unit/integration coverage.

## Frontend (Admin SPA) Tests

- Frontend unit tests live under `nop/ts/admin/src/**/*.test.ts`.
- Run with `cd nop/ts/admin && npm install` (first time) and `npm run test` (Vitest).
- Use `npm run check` for TypeScript-only validation when changing admin types or protocol contracts.
- Fix accessibility warnings surfaced during the test run (Svelte a11y warnings are not optional).

## Frontend (Login SPA) Tests

- Login SPA unit/integration tests live under `nop/ts/login/src/**/*.test.ts`.
- The login SPA should use Vitest for local logic, UI state, and API-mocking coverage; end-to-end coverage stays in Playwright.
- Run with `cd nop/ts/login && npm install` (first time) and `npm run test` once Vitest is wired in.
- Use `npm run check` for TypeScript-only validation when changing login types or runtime config contracts.

## API Coverage

- A comprehensive API suite lives in `nop/tests/` covering auth/CSRF, admin pages/themes/users, public render/assets, and security traversal.
- When adding or changing API endpoints, add integration tests in `nop/tests/` that exercise the full Actix pipeline and response payloads, and update this section.
- Do not introduce production-only routes or handlers just to satisfy tests; create test-only Actix apps/endpoints inside `#[cfg(test)]` modules instead.

## Smoke / System Tests (Playwright)

We ship Playwright-based E2E/UX coverage under `tests/playwright`. Use it for end-to-end scenarios,
including the login/profile flows, while keeping SPA unit/integration logic in Vitest:

1. **Harness**: Use `tests/playwright/fixtures.ts` (it creates a temp runtime root under `/tmp/nop-test/`, seeds config/users/roles/content, starts the server, and tears down per test).
2. **Server launch**: Defaults to `scripts/cargo.sh run -- -C <temp> -F` (`-F -C <temp>` is equivalent); set `NOP_BINARY` to use a prebuilt binary. `CARGO_TARGET_DIR` is redirected to a temp dir to keep artifacts isolated.
3. **Input rules**: Use `humanType`, `humanClick`, and `humanClearAndType` from `tests/playwright/utils/humanInput.ts`. Randomization is deterministic via `PW_RNG_SEED` or the test title path.
4. **Suite split**: `tests/playwright/tests/e2e` can use full Playwright power; `tests/playwright/tests/ux` must stick to user-visible selectors (roles, labels, text) without hidden selectors or `page.evaluate`.
5. **Artifacts**: HTML report plus trace/screenshot/video on failure under `PW_OUTPUT_DIR` or the OS temp dir `nopressure-pw-<run-id>` (`PW_RUN_ID`).

Run commands:
```bash
cd tests/playwright
npm install
npx playwright install
npm run test
npm run test:e2e
```

## Test Utilities

- Use helper modules to avoid duplication (`nop/tests/common/` or submodules).
- If a helper becomes widely useful, consider adding it to `util/` with a test-specific feature flag.
- Prefer `serde_json::json!` to build JSON bodies and assert equality against `serde_json::Value`.
- For time-sensitive logic, inject clocks or use helper functions to freeze time rather than sleeping.

## Coverage Focus Areas

1. **Security**: Path traversal guards, CSRF middleware, threat tracking.
2. **Auth**: JWT creation/refresh, login flow, role resolution.
3. **Content Pipeline**: Markdown parsing, shortcode rendering, navigation generation.
4. **Admin Actions**: Page create/edit/delete, binary upload pre-validation, stream uploads, cache updates, temp cleanup on failure/disconnect/startup.
5. **Error Handling**: Ensure 404/500 responses render correctly and log useful details.

## AI Assistant Tips

- Before writing tests, read existing examples in the same module to copy fixture patterns.
- Prefer small, focused tests; large integration tests should still assert specific behaviours.
- When adding features without existing test coverage, include tests in the same change to demonstrate the contract.
- Document any gaps (e.g., missing e2e coverage) in PR descriptions so they can be tracked.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
