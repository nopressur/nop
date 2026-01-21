# Tooling & Automation

This catalog highlights repo-provided tooling that speeds up development, testing, and releases. Each script lives in-tree so AI assistants and engineers can locate and invoke them confidently.

## Rust Build Utilities

- `scripts/cargo.sh`
  - Wrapper for `cargo` that ensures the patched Rust vendor crates are available first.
  - Works with any cargo subcommand (build, check, test, fmt, clippy, run, etc.).
  - Resolves the crate automatically (uses `nop/` when invoked from repo root).
- `scripts/update-rust-vendor.sh`
  - Downloads pinned crates from crates.io and applies local patches into `nop/target/vendor/`.
  - `--ensure` skips work when the vendor directory and marker are already valid.

## Versioning Utilities

- `scripts/bump-version.sh`
  - Updates the NoPressure package version in `nop/Cargo.toml`.
  - Bumps the `[package]` version field (patch by default, or `minor`/`major` on request).
  - Usage: `scripts/bump-version.sh`, `scripts/bump-version.sh minor`, `scripts/bump-version.sh major`

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

1. **Bootstrap**: install Rust tooling (`rustup`), ensure `scripts/cargo.sh fmt`, `scripts/cargo.sh clippy`, `scripts/cargo.sh test` succeed.
2. **Manage credentials**: use `nop user` subcommands for local user hashes instead of online generators.
3. **Frontend builds**: `build.rs` rebuilds admin/login SPA assets automatically; run `npm run build`
   in `nop/ts/admin` or `nop/ts/login` only if you need to regenerate assets manually. Login
   builds write `login.js` + `login.css` into `nop/builtin/login-<hash>` and update
   `nop/builtin/login-spa-version.txt` so the templates reference the correct versioned assets.
4. **Ship**: use `scripts/cargo.sh build --release` before packaging binaries or images.

Each tool prints actionable output and exits with non-zero status on failure, making them safe to wire into CI or scripted workflows.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
