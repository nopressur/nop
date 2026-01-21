# Management Operations

Status: Developed

## Monitoring

- Management connectors emit log messages for accept failures, socket cleanup, and codec errors.
- Adjust logging with `RUST_LOG` (for example, `RUST_LOG=info` or `RUST_LOG=debug`).
- Use `nop -C <root> system ping` to confirm the daemon is responding.
- Verify socket presence at `<runtime-root>/state/sys/management.sock`.

## Capacity Notes

- The blocking pool is intentionally small (default 2 workers + 1 overflow) and fails fast with a Busy error when saturated.
- The socket handshake must complete within 5 seconds; idle connections are closed after 5 minutes.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
