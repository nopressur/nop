# Command Line

NoPressure includes a `nop` command for starting a runtime and managing content,
users, roles, tags, search, and logs from a terminal. Commands operate on a
runtime root: the directory that contains `config.yaml`, `users.yaml`, `content/`,
`themes/`, `state/`, and `logs/`.

```bash
nop -C ./runtime system ping
```

Use `-C <root>` to select the runtime root. If `-C` is omitted, the current
directory is used.

## Runtime Selection

| Option | Default | Range | Notes |
| --- | --- | --- | --- |
| Runtime root | Current directory | Any valid NoPressure runtime directory | Set with `-C <root>`. |
| First run bootstrap | Built in | Missing `config.yaml` or `users.yaml` | Missing files are created when the server starts. |
| Help | None | `nop help`, `nop -h`, `nop --help` | Prints domains, commands, aliases, and syntax. |
| Foreground mode | Off for normal server start | `-F` | Keeps the server attached to the terminal. Only valid when no management command is provided. |

When bootstrap creates `config.yaml` or `users.yaml`, the server remains in the
foreground for that run so the generated credentials are visible.

## Starting The Server

| Command | Purpose |
| --- | --- |
| `nop -C ./runtime` | Start the server using `./runtime`. On Unix this daemonizes by default. |
| `nop -F -C ./runtime` | Start the server in the foreground. |
| `nop -C ./runtime system ping` | Check that the selected runtime can answer management commands. |

Options are order-insensitive for server startup, so `nop -C ./runtime -F` and
`nop -F -C ./runtime` are equivalent. `-F` is not allowed with management
commands.

## Command Syntax

```bash
nop [options] <domain> <command> [args]
```

Domains and commands are case-insensitive. Unambiguous prefixes are accepted, so
`nop -C ./runtime sys p` is equivalent to `nop -C ./runtime system ping`.

| Domain | Alias | Used for |
| --- | --- | --- |
| `system` | `sys` | Ping, log rotation settings, and clearing logs. |
| `settings` | `cfg` | Website-level editable settings. |
| `user` | `u` | Local user accounts and passwords. |
| `role` | `r` | Role names. |
| `tag` | `t` | Content tags and tag access rules. |
| `content` | `c` | Uploading, changing, streaming, and deleting content. |
| `search` | `s` | Searching and search index maintenance. |

## System Commands

| Command | Purpose |
| --- | --- |
| `system ping` | Verify CLI connectivity and version compatibility. |
| `system logging show` | Show log rotation settings. |
| `system logging set --max-size-mb <mb> --max-files <count>` | Update log rotation settings. Both values are required. |
| `system logging clear` | Clear managed log files. |

Example:

```bash
nop -C ./runtime system logging set --max-size-mb 50 --max-files 5
```

## Settings Commands

Settings commands manage website-level settings persisted in `config.yaml`.

| Command | Purpose |
| --- | --- |
| `settings show` | Show the current Website Title. |
| `settings website-title set --title <title>` | Set or replace the Website Title. |
| `settings website-title clear` | Clear the Website Title. |

When Website Title is set, public browser titles render as `<page title> | <website title>`.

Example:

```bash
nop -C ./runtime settings website-title set --title "Example Site"
```

## User Commands

These commands manage local users in `users.yaml`. If the runtime is configured
for an external identity provider, user editing may not be available through the
local user store.

| Command | Purpose |
| --- | --- |
| `user add <email> --name <display-name> [--roles <role> ...] [--password <password>]` | Create a user. |
| `user change <email> [--name <display-name>] [--roles <role> ...] [--clear-roles]` | Update display name or role assignments. |
| `user delete <email>` | Delete a user. |
| `user password <email> [--password <password>]` | Set a user's password. |
| `user list` | List users. |
| `user show <email>` | Show one user. |

If `--password` is omitted for `user add` or `user password`, the command prompts
twice. Passwords longer than 1024 characters are rejected.

Examples:

```bash
nop -C ./runtime user add alice@example.com --name "Alice" --roles admin
nop -C ./runtime user change alice@example.com --roles admin --roles editor
nop -C ./runtime user password alice@example.com
```

## Role Commands

| Command | Purpose |
| --- | --- |
| `role add <role>` | Create a role. |
| `role change <role> --new-role <role>` | Rename a role. |
| `role delete <role>` | Delete a role. |
| `role list` | List roles. |
| `role show <role>` | Show one role. |

Example:

```bash
nop -C ./runtime role add editor
```

## Tag Commands

Tags can carry access rules. Content assigned to tags inherits the tag access
requirements.

| Command | Purpose |
| --- | --- |
| `tag add <id> --name <name> [--roles <role> ...] [--access <union\|intersect>]` | Create a tag. |
| `tag change <id> [--new-id <id>] [--name <name>] [--roles <role> ...] [--clear-roles] [--access <union\|intersect>] [--clear-access]` | Update a tag. |
| `tag delete <id>` | Delete a tag. |
| `tag list` | List tags. |
| `tag show <id>` | Show one tag. |

`--access` accepts `union` or `intersect`. `--clear-roles` cannot be combined
with `--roles`, and `--clear-access` cannot be combined with `--access`.

Example:

```bash
nop -C ./runtime tag add news --name "News" --roles editor --access union
```

## Content Commands

Content commands manage markdown pages and binary assets. The content ID returned
by `content store` is the stable identifier used by later commands.

| Command | Purpose |
| --- | --- |
| `content store [options] <file\|->` | Store a markdown page or binary asset. |
| `content change <id> [options] [<file\|->]` | Update metadata and, for markdown, optionally replace the body. |
| `content stream <id> <file\|->` | Write content to a file or standard output. |
| `content delete <id>` | Delete content. |

Common `content store` and `content change` options:

| Option | Applies to | Notes |
| --- | --- | --- |
| `--alias <alias>` | Markdown and assets | Public route or asset path. |
| `--title <title>` | Markdown and assets | Required when storing markdown. |
| `--tag <tag>` | Markdown and assets | May be repeated. |
| `--clear-tags` | `content change` only | Cannot be combined with `--tag`. |
| `--theme <theme>` | Markdown only | Theme name without `.theme`. |
| `--nav-title <title>` | Markdown only | Adds the page to the navbar. |
| `--nav-parent <id>` | Markdown only | Requires `--nav-title`. |
| `--nav-order <order>` | Markdown only | Requires `--nav-title`. |
| `--disable-navbar` | Markdown only | Omits the public navbar on that page. |
| `--enable-navbar` | `content change` only | Clears `--disable-navbar`. |
| `--disable-floating-nav` | Markdown only | Omits the floating document navigation panel and mobile heading links on that page. |
| `--enable-floating-nav` | `content change` only | Clears `--disable-floating-nav`. |

Use `-` as the file argument to read from standard input or write to standard
output. When `content store` reads from standard input, it creates a generated
filename based on the current date and the detected MIME type.

Examples:

```bash
nop -C ./runtime content store --alias docs/intro --title "Introduction" ./intro.md
nop -C ./runtime content store --alias images/logo.png --title "Logo" ./logo.png
cat ./updated.md | nop -C ./runtime content change <id> -
nop -C ./runtime content stream <id> ./copy.md
nop -C ./runtime content stream <id> -
```

## Search Commands

| Command | Purpose |
| --- | --- |
| `search find [--tag <tag> ...] [--markdown-only] [--] <query words...>` | Search public content. |
| `search invalidate <id>` | Re-index one content item. |
| `search reset` | Rebuild search state. |

`--tag` may be repeated. Use `--` before the query if the query begins with a
dash.

Examples:

```bash
nop -C ./runtime search find getting started
nop -C ./runtime search find --tag docs --markdown-only install
nop -C ./runtime search find -- -leading-dash
```

## Operating Notes

- Management commands use the runtime's management socket when the server is
  running. If the socket is unavailable, commands run through the local
  management path against the selected runtime root.
- A stale management socket is removed automatically when detected.
- Usage errors exit with code `2`; connector/runtime errors exit with code `1`.
- If a command reports a version mismatch, use a `nop` binary built from the same
  release as the running server.
- Socket, permission, and version troubleshooting details are in
  `docs/management/troubleshooting.md`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
