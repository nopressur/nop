# Build & Release Engineering

This guide summarizes how NoPressure builds, watches, and ships the `nop` binary, tying each workflow to the underlying source files.

## Build Modes

- **Development (`scripts/cargo.sh run`)** – Actix serves admin and login assets from the filesystem. `build.rs`
  ensures the admin SPA is generated in `nop/builtin/admin` and the login SPA in a versioned
  directory such as `nop/builtin/login-<hash>` (runs `npm install` if needed, then `npm run build`).
  The script writes `builtin/login-spa-version.txt` plus a generated `login_spa_version.rs` so the
  Rust templates know which versioned login assets to reference. Debug builds still write an empty
  `builtin_files.rs`, so asset changes are reflected without recompiling the Rust binary.
  `build.rs` also builds the public site bundle from `nop/ts/site` into `nop/builtin/site.js`.
- **Release (`scripts/cargo.sh build --release`)** – `build.rs` (see `nop/build.rs`) walks `nop/builtin/`, gzip-compresses each asset, and generates `BUILTIN_FILES` (a `HashMap<&str, (&[u8], &str)>`). Release binaries embed these bytes, so no external asset directory is needed at runtime.
- Cargo reruns the build script when admin/login SPA sources or builtin assets change, ensuring the
  frontends and embedded assets stay in sync.

## Local Iteration

- `scripts/cargo.sh run -- -C ../runtime -F` – standard dev loop (runtime root at `../runtime`; `-F -C ../runtime` is equivalent).
- `scripts/cargo.sh check` – type-check without linking; use for quick feedback when editing APIs.
- Note: the server daemonizes by default when started without subcommands; pass `-F` to keep it in the foreground. If auto-bootstrap creates `config.yaml` or `users.yaml`, the server stays in the foreground for that run so credentials are visible.

## Release Builds

- `scripts/cargo.sh build --release` – builds the optimized binary with embedded assets. Output lands in `nop/target/release/nop`.

## Container Images

- `examples/docker/` – example full build pipeline inside Docker:
  - `Dockerfile` builds the Rust project, runs `scripts/cargo.sh build --release`, and copies the binary into a runtime image.
  - `docker-compose.yaml` mounts a host `data/` runtime root into `/data` and exposes the app on port `5466`.
  - `README.md` outlines build and run instructions (`docker-compose build && docker-compose up`).
- `examples/docker-slim/` – expects a prebuilt `nop` binary dropped into the directory. `Dockerfile` simply packages that binary with runtime dependencies; ideal for CI pipelines where the binary is built elsewhere.

## Supporting Utilities

- `scripts/cargo.sh` ensures patched Rust vendor crates are present (via `scripts/update-rust-vendor.sh`) before running any cargo command.
- `build.rs` watches `nop/ts/admin` and `nop/ts/login` sources and rebuilds the SPA assets when
  needed (`npm install` + `npm run build` as required). Login builds emit `login.js` + `login.css`
  into a versioned `nop/builtin/login-<hash>` directory and update `login-spa-version.txt`.
- `build.rs` watches `nop/ts/site` and rebuilds the public site bundle into `nop/builtin/site.js`.
- `build.rs` ensures `nop/builtin/bulma.min.css` exists; if it is missing, it runs
  `scripts/update-bulma.sh --ensure`.
- `build.rs` ensures the Ace editor assets (core, modes, themes, extensions) exist under
  `nop/builtin/`; if any are missing, it runs `scripts/update-ace.sh --ensure`.
- `nop user` subcommands provide user management for release manifests (including password hashing).
- `nop/BUILD.md` contains legacy build notes; this DevOps doc supersedes it for quick reference but remains a detailed companion.

## Operational Checklist

1. Ensure configuration files exist: copy `examples/config.yaml.example` and `examples/users.yaml.example` into the runtime root (or rely on auto-bootstrap defaults).
2. Run `scripts/cargo.sh fmt --all`, `scripts/cargo.sh clippy -- -D warnings`, and `scripts/cargo.sh test` locally before producing release artifacts.
3. Choose a delivery path:
   - Local binary: `scripts/cargo.sh build --release`, distribute `nop/target/release/nop`.
   - Container: `cd examples/docker && docker-compose build` (full build) or `cd examples/docker-slim && docker-compose build` (package prebuilt binary).
4. Persist or publish the resulting binaries/images through your deployment pipeline.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
