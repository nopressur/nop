# Management Architecture

Status: Developed

## Objectives

- Define the layered management architecture (core operations, async management bus, connectors).
- Keep core operations domain-focused and transport-agnostic.
- Ensure all management inputs route through the same async bus for consistent validation and error handling.
- Default all management message passing and parameters to binary encoding at transport boundaries.
- Provide abstract modules for defining core operations and registering command IDs/constants in a single aggregated registry.

## Technical Details

### Layer 1: Core Operations

- Core operations are the canonical implementations for management mutations.
- Each domain defines request/response structs with explicit fields (no loose maps).
- All core operations are async and return structured results and errors.
- Core operations are transport-agnostic and do not depend on sockets or CLI parsing.
- Core operations receive `ManagementContext` (version info, blocking pool, runtime root, validated config, runtime paths).
- Core operations must apply mutations to the live in-memory services and persist to disk; no daemon restart is required.
- Each domain exposes a registration hook that exports command IDs, request/response codecs, and handler wiring.
- Domain modules define action IDs, request/response size limits, and parameter formats.

### Layer 2: Async Management Bus

- The bus is the single entry point for all management requests.
- Requests are represented as a command enum with domain-specific variants.
- Dispatch is async and channel-backed using `mpsc` for requests and `oneshot` for replies.
- The bus is constructed from an aggregated registry of domain command IDs and handlers (`build_default_registry()`).
- The bus operates on typed command structs; connectors handle any encode/decode work.
- Bus replies use a shared success/error response type for consistent handling across connectors.

#### Command Enum and Bus Flow

- `ManagementCommand::{ System(SystemCommand), Users(UserCommand) }` carries domain-specific requests.
- `ManagementRequest { connection_id, workflow_id, command }` is the bus payload; connectors and
  internal callers must supply both IDs.
- `ManagementRequest` also carries optional actor metadata (for example, `actor_email`) injected by
  trusted connectors such as the authenticated admin WebSocket; this metadata is not part of any
  wire protocol and is never supplied by clients.
- `connection_id` is a required `u32` allocated sequentially for every new connector/session/request.
  It is internal metadata used for correlation and isolation, not part of any wire protocol.
- `workflow_id` is a required `u32` that must be monotonic per connection.
- `ManagementBus::start` spawns a background task that receives requests over `mpsc` and replies over `oneshot`.
- The registry maps `DomainActionKey { domain_id, action_id }` to handlers and codecs.

#### Concurrency and Blocking Work

- CPU-bound operations (for example, Argon2id hashing) must run in a small blocking pool.
- `BlockingPool::default_pool` uses two blocking workers with one overflow permit.
- When all permits are in use, blocking work fails fast with a Busy error rather than queueing.
- Password management actions (`users.password_set`, `users.password_validate`, `users.password_update`)
  always use the blocking pool for Argon2id hashing/verification.

### Layer 3: Connectors

- Connectors translate external inputs into `ManagementCommand` and submit them to the bus.
- Connectors do not implement business logic; they only validate transport-level constraints.
- Connectors implemented today:
  - Socket connector (`nop/src/management/socket`).
  - CLI bypass connector (`nop/src/management/cli_helper.rs`).
- Each connector has its own feature document:
  - `docs/management/connector-socket.md`
  - `docs/management/connector-cli-bypass.md`

#### Transport Encoding

- Connectors encode/decode protocol payloads at the boundary (socket today).
- Internal bus traffic uses typed structs only.
- Protocols require an exact app version match (major/minor/patch) and do not support cross-version negotiation.
- The socket connector wraps payloads in `RequestEnvelope`/`ResponseEnvelope` frames with a u32
  length prefix and the wire serialization defined in `docs/management/wire-serialization.md`.

### Error Handling

- Core operations return typed domain errors.
- The bus normalizes domain errors into a shared `ManagementError`.
- Connectors translate `ManagementError` into transport-specific errors and exit codes.
- When running inside the daemon, management errors are logged to the daemon logger.
- CLI helpers surface errors as a single-line message with a non-zero exit code.

### Command IDs and Registry

- A central registry in the management module owns domain ID assignments.
- Each domain module owns its action IDs and publishes its request/response size limits.
- Protocol encoders/decoders use published limits to validate payload sizes.
- A shared codec registry maps `DomainActionKey { domain_id, action_id }` to typed request/response encoders.

#### Domain ID Table

| Domain | ID (u32) | Owner | Notes |
| --- | --- | --- | --- |
| System | 0 | Core | Reserved for liveness and control |
| Users | 1 | User management | Initial user operations |
| Tags | 11 | Tag management | Tag CRUD/list/show |

#### System Action Table

| Action | ID (u32) | Payload | Response |
| --- | --- | --- | --- |
| Ping | 1 | `PingRequest { version_major, version_minor, version_patch }` (u16) | `PongResponse { message }` |
| Pong | 2 | `PongResponse { message }` | Response to Ping (success) |
| PongError | 3 | `PongErrorResponse { message }` | Response to Ping (error) |
| LoggingGet | 4 | `GetLoggingConfigRequest {}` | `LoggingConfigResponse { level, rotation_max_size_mb, rotation_max_files, run_mode, file_logging_active }` |
| LoggingGetOk | 5 | `LoggingConfigResponse { ... }` | Response to LoggingGet (success) |
| LoggingGetErr | 6 | `MessageResponse { message }` | Response to LoggingGet (error) |
| LoggingSet | 7 | `SetLoggingConfigRequest { rotation_max_size_mb, rotation_max_files }` | `LoggingConfigResponse { ... }` |
| LoggingSetOk | 8 | `LoggingConfigResponse { ... }` | Response to LoggingSet (success) |
| LoggingSetErr | 9 | `MessageResponse { message }` | Response to LoggingSet (error) |
| LoggingClear | 10 | `ClearLogsRequest {}` | `ClearLogsResponse { message, deleted_files, deleted_bytes }` |
| LoggingClearOk | 11 | `ClearLogsResponse { ... }` | Response to LoggingClear (success) |
| LoggingClearErr | 12 | `MessageResponse { message }` | Response to LoggingClear (error) |

#### Parameter Structures and Limits

- Each domain publishes:
  - Request/response struct definitions for every action.
  - Per-field max sizes (string lengths, list lengths).
  - Any required normalization rules (for example, lowercase roles).
- Connectors enforce size limits during decoding using the published per-field limits.
- Limits are expressed via `FieldLimits`/`FieldLimit` (`MaxChars`, `Range`, `MaxEntries`) in `nop/src/management/codec.rs`.

#### Protocol Helper Modules

- `nop/src/management/codec.rs` provides shared `encode_payload`/`decode_payload` helpers plus codecs for requests/responses.
- `nop/src/management/socket/protocol.rs` owns the binary frame encoding for socket envelopes.
- The CLI helper uses the shared response payload type (`MessageResponse`) to provide uniform output.

#### Success/Error Response Shape

- Responses always include:
  - `domain_id` (u32) and `action_id` (u32) for the response action.
- `workflow_id` (`u32`) for request correlation and multi-stage interactions.
- `connection_id` is request-only metadata and is not echoed in responses.
- The bus does not mutate `workflow_id`; it is echoed back to the connector for response routing.
- `workflow_id` value `0` is invalid; connectors must reject before dispatching to the bus.
- `workflow_id` values must remain strictly increasing per connection; connectors enforce this
  by tracking the last accepted value per connection.
- A response payload enum; currently `ResponsePayload::Message(MessageResponse { message })` (max 1024 characters).
  - Optional structured fields linked to the domain/action.
- Response actions are distinct IDs defined by the domain (for example, `AddOk` and `AddErr`).
- Define a shared `MessageResponse { message }` payload for actions that only need a message.

#### Codec Traits

- `RequestCodec` and `ResponseCodec` structs advertise:
  - Domain/action IDs via `DomainActionKey`.
  - Per-field limits via `FieldLimits`.
  - `encode`/`decode` using the wire serialization defined in
    `docs/management/wire-serialization.md`.
  - `validate` hooks for semantic validation.
- The registry aggregates these codecs for socket and CLI connector use.

### Related Documents

- `docs/management/connector-socket.md`
- `docs/management/wire-serialization.md`
- `docs/management/connector-cli-bypass.md`
- `docs/admin/user-management.md`
- `docs/management/cli-architecture.md`
- `docs/management/troubleshooting.md`
- `docs/management/operations.md`
- `docs/management/domains.md`

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
