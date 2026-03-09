# CLI

Status: Developed

## Objectives

- Provide a CLI for operating a NoPressure runtime root via the management bus.
- Document domain/command syntax and examples for operators.
- Add file-management commands for storing, changing, streaming, and deleting content assets.

## Technical Details

The `nop` binary ships with a CLI for operating a NoPressure runtime root. CLI commands route
through the management bus and work whether the daemon is running or not.

### Quick Start

- `nop help`
- `nop -C <root> system ping`

### Runtime Root

- The runtime root defaults to the current working directory; override with `-C <root>`.
- Use a dedicated directory that contains only `config.yaml`, `users.yaml`, `content/`,
  `themes/`, `state/`, `logs/`, and `nop.pid` at the top level.
- If `config.yaml` or `users.yaml` are missing, bootstrap creates defaults on the first run.

### Running The Server

- `nop -C <root>` starts the server and daemonizes by default on Unix.
- `nop -F -C <root>` runs the server in the foreground.
- `-F` is rejected when subcommands are present.
- `-C` and `-F` are order-insensitive when no subcommands are provided.
- When bootstrap creates `config.yaml` or `users.yaml`, the server stays in the foreground
  for that run so credentials are visible.

### Command Structure

```
nop [options] <domain> <command> [args]
```

Options:
- `-C <root>`: set the runtime root (default: current directory).
- `-F`: run the server in the foreground (only when no CLI command is provided).
- `-h`, `--help`, or `help`: print the CLI help.

Resolution rules:
- Domains and commands are case-insensitive.
- Unambiguous prefixes are accepted (for example `us` for `user`).
- Aliases are supported (see domain sections below).

### Domains

#### system (alias: `sys`)

- `system ping` (alias: `p`)
- `system logging show`
- `system logging set --max-size-mb <mb> --max-files <count>`
- `system logging clear`

Notes:
- `system logging set` requires both `--max-size-mb` and `--max-files`, and both must be
  numeric.

#### user (alias: `u`)

- `user add <email> --name <display-name> [--roles <role> ...] [--password <password>]`
- `user change <email> [--name <display-name>] [--roles <role> ...] [--clear-roles]`
- `user delete <email>`
- `user password <email> [--password <password>]`
- `user list`
- `user show <email>`

Notes:
- If `--password` is omitted for `user add` or `user password`, the CLI prompts twice.
- Passwords longer than 1024 characters are rejected.

#### role (alias: `r`)

- `role add <role>`
- `role change <role> --new-role <role>`
- `role delete <role>`
- `role list`
- `role show <role>`

#### tag (alias: `t`)

- `tag add <id> --name <name> [--roles <role> ...] [--access <union|intersect>]`
- `tag change <id> [--new-id <id>] [--name <name>] [--roles <role> ...] [--clear-roles] [--access <union|intersect>] [--clear-access]`
- `tag delete <id>`
- `tag list`
- `tag show <id>`

Notes:
- `--access` accepts `union` or `intersect`.
- `--clear-roles` cannot be combined with `--roles`.
- `--clear-access` cannot be combined with `--access`.

#### search (alias: `s`)

- `search find [--tag <tag> ...] [--markdown-only] [--] <query words...>`
- `search invalidate <id>`
- `search reset`

Notes:
- `--tag` may be repeated to filter by multiple tags (all-of matching).
- `--markdown-only` restricts results to markdown content.
- `--` ends flag parsing so query terms may start with `-`.

#### content (alias: `c`)

- `content store [--alias <alias>] [--title <title>] [--tag <tag> ...] [--theme <theme>] [--nav-title <title>] [--nav-parent <id>] [--nav-order <order>] <file|->`
- `content change <id> [--alias <alias>] [--title <title>] [--tag <tag> ...] [--clear-tags] [--theme <theme>] [--nav-title <title>] [--nav-parent <id>] [--nav-order <order>] [<file|->]`
- `content stream <id> <file|->`
- `content delete <id>`

Notes:
- The `file` argument must be last. Use `-` to read from standard input or write to standard output.
- `content store` requires a file argument and fails if the filename has no extension.
- `content store` requires `--title` for markdown content.
- `content store` derives MIME on the server; no CLI flag is provided for it.
- When `content store` reads from standard input, it uses `cli-store-YYYY-MM-DD-HH-MM-SS.<ext>` as the generated filename (extension derived from the detected MIME type; `application/octet-stream` uses `.bin`).
- `--tag` may be repeated to apply multiple tags.
- `--clear-tags` cannot be combined with `--tag`.
- `--theme`, `--nav-title`, `--nav-parent`, and `--nav-order` apply to markdown content only.
- `content change` only updates metadata for non-markdown files; markdown body updates use the optional file/stdin input. Omit the file argument for metadata-only changes.
- `content change` file input must be a markdown file (`.md`/`.markdown`) and cannot be empty.
- `content stream` returns markdown content inline and streams binary content bytes via `content.read` with `stream_content` enabled.

### Examples

```
# Foreground server run
nop -F -C ./runtime

# Ping the daemon
nop -C ./runtime system ping

# Add a local user and set their password
nop -C ./runtime user add alice@example.com --name "Alice" --roles admin

# Update user roles
nop -C ./runtime user change alice@example.com --roles admin --roles editor

# Add a tag with access rules
nop -C ./runtime tag add news --name "News" --roles editor --access union

# Store a binary asset
nop -C ./runtime content store --alias images/logo.png --title "Logo" ./assets/logo.png

# Change markdown content from stdin
cat ./docs/intro.md | nop -C ./runtime content change <id> -

# Stream content to stdout
nop -C ./runtime content stream <id> -
```

### Troubleshooting

- Management socket issues, permission errors, and version mismatches are documented in
  `docs/management/troubleshooting.md`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
