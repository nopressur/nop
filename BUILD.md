## Build and run

Prerequisites:
- Rust (cargo)
- Node.js (builds the admin UI during compilation)
- Linux: `libssl-dev` installed

Quick start (auto-bootstrap a clean data directory):

```bash
scripts/cargo.sh run -- -C /path/to/empty-directory -F
```

- Visit `https://localhost:7443` for the public site when using auto-generated config.
- The admin UI lives at `https://localhost:7443/admin` by default.
- The first run uses a self-signed certificate, so your browser will ask to proceed.
- `-C` and `-F` are order-insensitive when starting the server without subcommands (for example, `-F -C /path/to/empty-directory`).

Release build:

```bash
scripts/cargo.sh build --release
mkdir -p /path/to/empty-directory
cd /path/to/empty-directory
/path/to/nop/target/release/nop
```

This is the simplest way to run it: start the binary from a clean directory and auto-bootstrap will populate it. (You can also pass `-C <root>` from anywhere.) Note: the server daemonizes by default; add `-F` to keep it in the foreground.

Optional: preseed configuration and users instead of auto-bootstrap.

```bash
mkdir -p /path/to/data
cp examples/config.yaml.example /path/to/data/config.yaml
cp examples/users.yaml.example /path/to/data/users.yaml
```

## Auto-bootstrap behavior

When you point NoPressure at a clean data directory (via `-C <root>`), it can create a working site for you on first run. It never overwrites existing files.

What it does on a clean runtime root:
- Ensures the runtime root is a dedicated data directory and refuses to start if unexpected top-level files are present.
- Creates a minimal `config.yaml` with self-signed TLS enabled (HTTPS on 7443, HTTP well-known on 7080).
- Creates `users.yaml` with a default admin account when local auth is enabled; the password is printed once at startup, so keep the terminal output visible.
- Creates `content/`, `themes/`, and `state/` plus a default home page and theme.
- Stays in the foreground for the first run if it created credentials so you can capture them.

If you provide your own config (for example to use external auth), bootstrap respects it and only fills in what is missing.

## More documentation

- `docs/devops/build-and-release.md` for build and deployment details
- `docs/devops/configuration.md` for configuration options
- `docs/admin/auto-bootstrap.md` for the full bootstrap contract

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
