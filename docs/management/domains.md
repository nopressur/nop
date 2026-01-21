# Adding Management Domains

Status: Developed

## Steps

1. Define domain/action IDs and request/response structs under `nop/src/management/<domain>/`.
2. Implement a domain command enum plus handlers that accept a `ManagementContext`.
3. Provide `RequestCodec` and `ResponseCodec` implementations with field limits and validation.
4. Register the domain and handlers in `nop/src/management/mod.rs` via `build_default_registry`.
5. Add CLI parsers under `nop/src/management/cli/` and register them in `nop/src/management/cli/mod.rs`.
6. Add unit tests for codecs/validation and socket/CLI integration tests where appropriate.
7. Update the management documentation to include IDs, limits, and behavioral notes.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
