# Management Connector: CLI Bypass

Status: Developed

## Objectives

- Provide a direct in-process connector for CLI commands when no socket is available.
- Ensure CLI requests still go through the async management bus.
- Keep CLI behavior consistent with socket-driven execution.
- Provide a CLI helper module that bridges decoded user intent to management commands (socket or bypass).

## Technical Details

### Connector Behavior

- If `<runtime-root>/state/sys/management.sock` exists, the CLI uses the socket connector.
- If the socket does not exist, the CLI bypass connector submits requests directly to the bus.
- If the socket exists but is stale (no valid `Ping` response), the CLI deletes it and falls back to the bypass connector.
- If the socket exists but responds with an incompatible handshake (version mismatch), the CLI returns an error and does not fall back.
- Permission-denied errors from the socket connector return immediately without falling back.

### Bus Integration

- The CLI bypass connector initializes the management bus with the same handler registry as the daemon.
- The connector then awaits the async response from the bus and returns it to the CLI layer.

### CLI Helper Module

- Provide a shared CLI helper module inside the main binary (`nop/src/management/cli_helper.rs`) that:
  - Accepts domain-decoded command structs (no CLI parsing inside the helper).
  - Selects the connector path (socket vs bypass) based on socket presence.
  - Hides the connector details from domain-specific CLI code.
  - Normalizes success/error output for CLI users.
- Domain CLI modules (for example, user management) only define:
  - CLI syntax and argument parsing rules.
  - Conversion from parsed arguments into the domain request struct.
  - No direct knowledge of sockets or bus wiring.

### Related Documents

- `docs/management/architecture.md`
- `docs/management/cli-architecture.md`

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
