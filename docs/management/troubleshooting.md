# Management Troubleshooting

Status: Developed

## Common Issues

### Management socket already active

- Cause: another daemon is running or a stale socket exists at `<runtime-root>/state/sys/management.sock`.
- Steps:
  - Run `nop -C <root> system ping` to confirm a live daemon.
  - If the daemon is stopped and the ping fails, remove the stale socket and retry.

### Permission denied for management socket

- Cause: the CLI user does not match the daemon user (socket permissions are `0600`).
- Steps:
  - Run the CLI as the same OS user as the daemon.
  - Verify socket ownership and permissions with `ls -l <runtime-root>/state/sys/management.sock`.

### Version mismatch

- Cause: the CLI and daemon versions do not match exactly (major/minor/patch).
- Steps:
  - Use the same binary for both CLI and daemon.
  - Upgrade or rebuild so the versions match exactly.

### blocking pool saturated

- Cause: all blocking pool permits are in use (Argon2id work is bounded).
- Steps:
  - Retry the operation after a brief pause.
  - Check logs for repeated saturation warnings.

### Password salt/update rejects change_token

- Cause: the change token expired, was reused, or does not match the issued salt.
- Steps:
  - Call `users.password_salt` again to fetch a fresh token and salt pair.
  - Retry `users.password_set` or `users.password_update` with the new token.

### User management requires local authentication

- Cause: `users.auth_method` is set to `oidc`.
- Steps:
  - Switch to local auth in `config.yaml` or use OIDC flows instead of local user commands.

## Diagnostics

- Use `RUST_LOG=debug` for more verbose management logging.
- Confirm the runtime root and socket path are correct for the command you are running.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
