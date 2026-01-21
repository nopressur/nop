# Repository Guidelines

## Important: Required Reading Before Work
Always read these documents before making changes or proposing work:
- `docs/README.md` for the documentation map and module boundaries.
- `docs/standards/coding.md` for Rust style, structure, and logging conventions.
- `docs/standards/testing.md` for test placement, naming, and execution expectations.

After that baseline, read the area-specific doc under `docs/` that matches the module you are touching.

## Project Structure & Module Organization
- `nop/` is the Rust crate; core sources live under `nop/src/` with domain modules like `public/`, `admin/`, `iam/`, and `security/`.
- `nop/ts/admin/` contains the admin SPA sources; build output is embedded under `nop/builtin/admin/`.
- `nop/ts/site/` contains the public site bundle sources; build output is embedded under `nop/builtin/site.js`.
- `assets/` holds seed content and themes used to bootstrap local runtime roots.
- `tests/` contains Rust integration tests; `tests/playwright/` hosts Playwright E2E/UX tests.
- `docs/` is the canonical documentation tree; `scripts/` and `nop/*.sh` provide tooling; `examples/` has Docker workflows.

## Build, Test, and Development Commands

**Ensure scripts/cargo.sh build without warnings and npm run check without warnings!**

- `scripts/cargo.sh run -- -C ../runtime -F` runs the server with a local runtime root and stays in the foreground.
- `./scripts/watch.sh` restarts `scripts/cargo.sh run` on Rust/config/asset changes and creates `runtime/` as needed.
- `scripts/cargo.sh check` runs a fast type check.
- `scripts/cargo.sh fmt --all` formats Rust; `scripts/cargo.sh clippy -- -D warnings` lints.
- `scripts/cargo.sh test` runs unit + integration tests; `scripts/cargo.sh test --tests` targets integration only.
- `scripts/cargo.sh build --release` produces the optimized binary.
- `cd tests/playwright && npm install && npx playwright install` then `npm run test:e2e` runs UI suites.

## Coding Style & Naming Conventions
- Rust 2024 edition; rely on `rustfmt` and `clippy` for formatting and linting.
- Naming: `snake_case` for files/functions, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Keep modules focused by domain and add `configure` entry points when wiring new routes.

## Compiler Warnings and Deprecations
- Never silence compiler warnings at the crate level (no `#![allow(..)]`, `#![cfg_attr(..)]`, or similar blanket suppression).
- Deprecated APIs are unacceptable. Remove or replace them immediately; do not hide them behind warning suppression.

## Testing Guidelines
- Tests must be deterministic and hermetic; avoid external network calls.
- Unit tests live alongside code in `#[cfg(test)]` blocks; integration tests live in `nop/tests/`.
- Name tests by behavior (for example, `rejects_invalid_csrf_header`).

## Commit Policy
- Assistants must not commit unless explicitly instructed by the user.
- Commit messages start with a capital letter and end with a full stop.
- Keep commit messages succinct and descriptive of the changes.

## Security & Configuration Tips
- Runtime configuration lives in `config.yaml` and `users.yaml`; seed examples are in `examples/`.
- Avoid committing secrets; prefer local runtime roots such as `runtime/` created by `scripts/watch.sh`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
