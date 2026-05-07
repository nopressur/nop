# Adding Management Domains

Status: Developed

## Steps

1. Define domain/action IDs and request/response structs under `nop/crates/nop-management-contract/src/<domain>.rs` (re-exported by `nop-management-bus`).
2. Implement a domain command enum plus handlers that accept the domain context trait (for example `<Domain>Context`).
   Domain handler implementations live under `nop/crates/nop-management-<domain>/` and are re-exported by `nop-management-bus::<domain>`; `ManagementContext` implements the required context traits.
3. Provide `RequestCodec` and `ResponseCodec` implementations with field limits and validation.
4. Register the domain and handlers in `nop/crates/nop-management-bus/src/lib.rs` via `build_default_registry`.
5. Add CLI parsers under `nop/crates/nop-management-bus/src/cli/` and register them in `nop/crates/nop-management-bus/src/cli/mod.rs`.
6. If the use case spans multiple domains, add a workflow under `nop/crates/nop-management-workflows/src/` and keep the domain handler thin.
7. Add unit tests for codecs/validation and socket/CLI integration tests where appropriate.
8. Update the management documentation to include IDs, limits, and behavioral notes.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
