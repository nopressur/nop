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
- `system ping` never runs through the bypass connector: without a usable socket the CLI deletes a stale socket if present and fails, since ping verifies a live daemon.
- If the socket exists but responds with an incompatible handshake (version mismatch), the CLI returns an error and does not fall back.
- Permission-denied errors from the socket connector return immediately without falling back.

### Bus Integration

- The CLI bypass connector initializes the management bus with the same handler registry as the daemon.
- The connector then awaits the async response from the bus and returns it to the CLI layer.

### Runtime Lock

- A single lock file at `<runtime-root>/state/sys/runtime.lock` arbitrates
  daemon lifetime against CLI bypass: exactly one side holds it at a time.
- The daemon acquires the lock at startup (after the pid check, daemonize, and
  pid creation; before serving) and holds it until exit. It fails fast with
  `Cannot start` when another process holds the lock.
- Each CLI bypass invocation holds the lock for the duration of the bypass and
  waits up to 60 seconds for it, so concurrent offline commands queue instead
  of racing on shared state files. The CLI socket path never touches the lock.
- The lock complements the existing detections (pid file, socket probe); it
  does not replace them. The lock file itself must never be deleted while any
  side may be running.

### CLI Helper Module

- Provide a shared CLI helper module inside the management bus crate (`nop/crates/nop-management-bus/src/cli_helper.rs`) that:
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
