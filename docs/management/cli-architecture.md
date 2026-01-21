# CLI Architecture

Status: Developed

## Objectives

- Define the shared CLI parsing and routing behavior for all management domains.
- Support explicit aliases and unambiguous prefix inference for subcommands.
- Ensure CLI inputs resolve into typed management commands via the CLI helper module.

## Technical Details

### Parsing and Resolution Rules

- Subcommands support explicit aliases (for example, `user` → `u`).
- Subcommands support prefix inference when unambiguous (`u`, `us`, `use`, `user`).
- Domain and command matching is case-insensitive (inputs are normalized to lowercase before resolution).
- Ambiguous prefixes are rejected with a clear error message.
- Domain CLI modules register their commands and aliases through the shared CLI helper.
- `help` is a top-level command that prints CLI usage without loading runtime configuration.
- `-h` and `--help` display the same help output regardless of other arguments.

### CLI Helper Module

- Domain CLI modules own CLI parsing and interpretation for their commands.
- The CLI helper module accepts domain-decoded command structs and dispatches via connectors.
- It owns the alias registry and prefix inference logic.

### Testing

- End-to-end CLI tests live under `nop/tests/` and execute the built `nop` binary via `CARGO_BIN_EXE_nop`.
- Each test creates a temp runtime root, writes `config.yaml`/`users.yaml` as needed, and runs CLI commands with `-C <root>`.
- Tests cover happy paths and error paths, including size limit over/under cases for CLI requests.

### Related Documents

- `docs/management/architecture.md`
- `docs/management/connector-cli-bypass.md`
- `docs/admin/user-management.md`

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
