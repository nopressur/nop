# Tooling & Automation

This catalog highlights repo-provided tooling that speeds up development, testing, and releases. Each script lives in-tree so AI assistants and engineers can locate and invoke them confidently.

## Rust Build Utilities

- `scripts/crg.sh <crate>`
  - Explicit crate-targeting wrapper for `cargo`.
  - Works with any cargo subcommand (build, check, test, fmt, clippy, run, etc.).
  - Accepts full package names (`nop-rt-well-known`) or short names without the `nop-`
    prefix (`rt-well-known`); use `nop` for the root package.
- `scripts/run-full-tests.sh`
  - Full non-browser testing scope for the repository.
  - Runs Rust format, test, and clippy in dependency-first order for every local path crate and
    the root `nop` package.
  - Runs admin/login SPA checks and tests.
- `scripts/run-playwright.sh`
  - Runs the Playwright browser E2E/UX scope separately.

## Asset Utilities

- `scripts/update-bulma.sh`
  - Downloads the pinned Bulma CSS version from `scripts/bulma-version.txt` into `nop/builtin/bulma.min.css`.
  - `--ensure` only downloads if the CSS file is missing (used by the build script).
  - Uses `curl` when available, with `wget` as a fallback.
- `scripts/update-ace.sh`
  - Downloads the pinned Ace editor assets from `scripts/ace-version.txt` into `nop/builtin/` (core, modes, themes, extensions).
  - `--ensure` only downloads if the Ace assets are missing.
  - Uses `curl` when available, with `wget` as a fallback.

## Supporting Artifacts

- `docs/devops/build-and-release.md`
  - Companion reference describing how these scripts integrate into the release flow.

## Usage Guidelines

1. **Bootstrap**: install Rust tooling (`rustup`), ensure `scripts/crg.sh nop fmt`, `scripts/crg.sh nop clippy`, `scripts/crg.sh nop test`, and `scripts/run-full-tests.sh` succeed for the relevant scope.
2. **Manage credentials**: use `nop user` subcommands for local user hashes instead of online generators.
3. **Frontend builds**: `build.rs` rebuilds admin/login SPA assets automatically; run `npm run build`
   in `nop/ts/admin` or `nop/ts/login` only if you need to regenerate assets manually. Login
   builds write `login.js` + `login.css` into `nop/builtin/login-<hash>` and update
   `nop/builtin/login-spa-version.txt` so the templates reference the correct versioned assets.
4. **Ship**: use `scripts/crg.sh nop build --release` before packaging binaries or images.

Each tool prints actionable output and exits with non-zero status on failure, making them safe to wire into CI or scripted workflows.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
