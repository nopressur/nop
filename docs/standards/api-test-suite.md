# API Test Suite (Cargo Test)

Status: Developed

## Objectives

- Provide comprehensive API-level coverage for public and admin HTTP endpoints using `scripts/cargo.sh test`.
- Keep tests hermetic, fast, and filesystem-scoped.
- Prevent test-only routes from leaking into production builds.

## Technical Details

### Flat Storage and Tag Listings

- Public render tests must cover alias lookups, `/id/<hex>` routing, and 404 behavior for missing aliases/IDs.
- Admin tests must cover ID-based CRUD, sidecar metadata edits, and optional alias updates/removals.
- Tag-list shortcode behavior should be validated with access control and limit handling.
- RBAC tests must validate tag-based role resolution, including union/intersect precedence and empty-role denial.

### Structure

- Integration tests live in `nop/tests/` with focused modules:
  - `auth_csrf.rs`
  - `admin_pages.rs`
  - `admin_tags.rs`
  - `admin_themes.rs`
  - `admin_users.rs`
  - `public_render.rs`
  - `public_assets.rs`
  - `security.rs`
- Shared helpers in `nop/tests/common/mod.rs` to avoid repetition.

### Harness

- Build a real Actix app using the production `configure` functions.
- Provide helpers for:
  - `build_config()` returning a `ValidatedConfig` with local auth enabled.
  - `build_app()` wiring routes and shared state (`AppState`, `PageMetaCache`, `CsrfTokenStore`).
  - `call_get` and `call_post_json` helpers for admin and public flows.
  - Management-bus helpers for content CRUD, list, and metadata updates.

### Data and Fixtures

- Use `TestFixtureRoot` to build a repo-local root under `target/test-fixtures`.
- Provide helper functions to:
  - Write blob files and RON sidecars for Markdown and binary content.
  - Seed tags and tag access rules in `state/sys/tags.yaml`.
  - Seed themes with known templates.

### Auth and Session

- Helpers to mint JWTs and attach auth cookies for requests.
- Helpers to mint CSRF tokens and attach headers.
- Provide a `login_as_admin()` flow helper where endpoint paths require authentication middleware.

### Coverage

- **Admin content**: paginated list, title search, Markdown/all filters, ID-based CRUD, alias updates/removals, sidecar metadata edits.
- **Admin uploads**: management bus upload flows, alias dedupe, MIME detection, snippet insertion rules.
- **Admin themes**: list/select/update theme; missing theme errors.
- **Admin users**: list/create/update/delete; RBAC enforcement.
- **Public render**: alias routing, `/id/<hex>` routing, Markdown render, assets, 404 masking, tag-based access control.
- **Shortcodes**: tag-list rendering with OR/AND rules and limit handling (`public/shortcode/tag_list.rs`).
- **Security**: traversal rejection and access control outcomes.

### Assertions

- Validate status codes, JSON bodies, and cache-control headers.
- Verify filesystem side effects and cache updates.
- Keep assertions focused on observable behavior, not internal logs.

### Non-goals

- UI/DOM behavior and JS-driven interactions (handled by Playwright suites).

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
