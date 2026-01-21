# Management Connectors: Socket + WebSocket

Status: Developed

## Objectives

- Provide a local Unix domain socket connector for the management bus.
- Provide a WebSocket management connector for admin UI components.
- Restrict socket access to the daemon user; restrict WebSocket access to authenticated admins.
- Define a versioned binary protocol for management requests and responses.
- Reuse management bus domain codecs across both connectors.

## Technical Details

### Shared Protocol Overview

- Management requests and responses use the wire serialization defined in
  `docs/management/wire-serialization.md`.
- Domain/action IDs are encoded as `u32` values; `workflow_id` is a required `u32` for
  request correlation and multi-stage flows.
- Each connector allocates a sequential `connection_id` (`u32`) per accepted connection and
  attaches it to bus requests for correlation (not part of the wire protocol).
- Connectors enforce that `workflow_id` values are strictly increasing per connection by
  tracking the last accepted value.
- `workflow_id` value `0` is invalid and must be rejected.
- Connectors validate size limits and semantic rules using the registered domain codecs.
- The protocol is internal; clients must match the daemon app version (enforced by socket ping).

### ID-First Content Addressing

- Content domain operations must target content IDs for read/update/delete flows.
- Aliases remain optional metadata: create/update can set or clear aliases, but aliases are never
  required for addressing.
- Responses must always include content IDs so clients can route editor views by ID.

### Socket Connector

#### Socket Location and Lifecycle

- Socket path: `<runtime-root>/state/sys/management.sock`.
- Created after runtime paths are validated and before accepting management traffic.
- File permissions: `0600` and owned by the daemon user.
- Each accepted connection is assigned a new `connection_id` for bus correlation.
- On clean shutdown, remove the socket.
- Stale socket handling:
  - On startup, if the socket already exists, connect and send a system `Ping`.
  - If a valid response is received, fail fast (another daemon is running).
  - If there is no response or the handshake fails, treat the socket as stale, remove it, and create a new one.
- Handshake must complete within 5 seconds; idle connections are closed after 5 minutes.

#### Access Control

- Enforce both filesystem permissions and peer credential checks.
- For each accepted connection, verify effective UID matches the daemon UID.
- Platform approach:
  - Linux: `getsockopt(SO_PEERCRED)`
  - macOS/BSD: `getpeereid`

#### Binary Protocol

- Framing: `u32` little-endian length prefix followed by a serialized payload.
- Serialization: see `docs/management/wire-serialization.md`.
- Versioning is negotiated only during the initial `Ping` handshake.

##### Request Envelope

- `Request { domain, action, workflow_id, payload }`
- `domain` and `action` are enums encoded as `u32` values.
- `workflow_id` is a required `u32` used for request correlation and multi-stage workflows.
- `payload` is binary (`Vec<u8>`) encoded per the wire serialization spec.

##### Response Envelope

- `Response { domain, action, workflow_id, payload }`
- `domain` and `action` are enums encoded as `u32` values for the response action.
- `workflow_id` is a required `u32` echoed from the request.
- `payload` is binary (`Vec<u8>`) encoded per the wire serialization spec.
- Response payloads must include a `message` field (UTF-8, max 1024 characters).

##### System Domain

- Domain `0` is reserved for system commands.
- System `Ping` is used for stale socket detection and liveness checks.
- `Ping` action ID: `1`.
- `Ping` request payload: `PingRequest { version_major, version_minor, version_patch }` (u16).
- `Pong` response action ID: `2`.
- `PongError` response action ID: `3`.
- `Pong` response payload: `PongResponse { message }`.
- `PongError` response payload: `PongErrorResponse { message }`.
- `Ping` returns action `Pong` only for an exact version match (major/minor/patch); otherwise it returns `PongError` with a message indicating the mismatch.
- Rationale: the management CLI is shipped with a single binary that calls itself, so strict matching prevents accidental use of a different binary.

#### Connector-to-Bus Mapping

- The connector validates framing and protocol version, then maps to a `ManagementCommand`.
- All business validation and mutation is handled by core operations via the bus.
- Socket-level errors return a `PongError` response with a populated `message`.
- The server logs management errors when running inside the daemon.

#### Payload Limits

- Each domain publishes size limits for request/response fields.
- The socket connector validates these limits via the registered codecs and returns a `PongError` response on violations.

### WebSocket Connector

#### Scope and Placement

- The WebSocket connector is an admin-only management connector that bridges the admin UI to the management bus.
- Core domain logic remains in the management bus; this connector is transport-only.
- Domain and action definitions live under the management docs (see `docs/management/domains.md`).

#### Authentication and CSRF Tickets

- The WebSocket connection uses the same JWT auth cookie as the rest of the admin UI.
- CSRF token issuance is split into two flows:
  - Long-lived tokens (existing, 1 hour) for REST-style admin APIs.
  - Short-lived tickets (20 seconds) for WebSocket initiation.
- The ticket endpoint lives under the admin scope:
  - `POST <admin_path>/ws-ticket`
  - Requires an authenticated admin and the long-lived `X-CSRF-Token` header.
  - Returns a short-lived, single-use ticket bound to the JWT ID.
- Authenticated admin requests to the ticket endpoint are not rate limited; login/session rate limits
  remain scoped to authentication flows only.
- WebSocket authentication requires:
  - The JWT cookie.
  - A valid long-lived CSRF token.
  - A valid short-lived ticket.
- The WS ticket endpoint and WS auth frame validation use a shared helper so JWT/dev-mode
  resolution and CSRF + ticket checks stay consistent.

#### WebSocket Endpoint and Handshake

- Endpoint: `GET <admin_path>/ws`.
- First client frame must be an auth frame containing `{ ticket, csrf_token }`.
- The backend validates:
  - Admin role and JWT session.
  - Long-lived CSRF token for the JWT ID.
  - Short-lived ticket (unexpired, unused) for the JWT ID.
- On success, the server replies with `AuthOk`; on failure, the server replies with `AuthErr` and closes the connection.
- On success, the connector assigns a new `connection_id` for the lifetime of that WebSocket session.

#### Client Reconnect Behavior

- The admin SPA maintains a single WebSocket connection at a time.
- When the connection closes or errors, the client should request a new ticket and reconnect.
- When the connection is open, the client must not attempt a parallel reconnect.

#### WebSocket Frame Model

- Each WebSocket message carries exactly one protocol frame.
- WebSocket continuation frames are aggregated by the connector; protocol decoding only happens
  on fully reassembled messages.
- Protocol messages are capped at 63 KiB (`WS_MAX_MESSAGE_BYTES`).
- Binary payloads are encoded using the wire serialization spec in
  `docs/management/wire-serialization.md`.
- The WebSocket frame header includes:
  - `frame_type` (`Auth`, `Request`, `Response`, `StreamChunk`, `Ack`, `Error`).
  - `workflow_id`, `domain_id`, `action_id` for request/response frames.
  - `stream_id`, `seq`, `flags` for streaming frames.
- No length prefix is needed; the WebSocket frame boundary is the message boundary.

#### Backend WebSocket Coordinator

- The coordinator owns the WebSocket session and routes frames to the appropriate connector:
  - Auth frames are handled locally.
  - Request frames are decoded via the management registry and dispatched to the bus.
  - Response frames are routed back to the requesting client and/or frontend connector.
  - Stream frames are processed by the shared streaming helper.
- The coordinator enforces:
  - Protocol message size limits (63 KiB) and payload limits via `management::codec` field limits.
  - Admin-only access and CSRF ticket validation on connection setup.
  - Backpressure by gating outbound stream chunks on per-frame acknowledgements.

#### Content Identification (Management Bus)

- All admin content operations identify content by ID only; aliases are never accepted as
  identifiers on the management bus.
- Aliases are optional metadata used exclusively for public routing and user-friendly links.

#### Content CRUD (Management Bus)

Read request payload:

```
ContentReadRequest {
  id: String,
}
```

Update request payload:

```
ContentUpdateRequest {
  id: String,
  new_alias: Option<String>,
  title: Option<String>,
  tags: Option<Vec<String>>,
  nav_title: Option<String>,
  nav_parent_id: Option<String>,
  nav_order: Option<i32>,
  theme: Option<String>,
  content: Option<String>,
}
```

Delete request payload:

```
ContentDeleteRequest {
  id: String,
}
```

Upload request payload (alias optional metadata only):

```
ContentUploadRequest {
  alias: Option<String>,
  title: Option<String>,
  mime: String,
  tags: Vec<String>,
  nav_title: Option<String>,
  nav_parent_id: Option<String>,
  nav_order: Option<i32>,
  original_filename: Option<String>,
  theme: Option<String>,
  content: Vec<u8>,
}
```

#### Binary Upload Protocol

Binary uploads are split into a pre-validation step and a stream-backed upload step. All steps use
the management bus for validation and commit, while streaming bytes are handled by the WebSocket
coordinator and written to temp files.

##### Actions (Content Domain)

- `content_binary_prevalidate` (request id `7`)
  - Response: `content_binary_prevalidate_ok` (`701`) or `_err` (`702`)
- `content_binary_upload_init` (request id `8`)
  - Response: `content_binary_upload_init_ok` (`801`) or `_err` (`802`)
- `content_binary_upload_commit` (request id `9`)
  - Response: `content_binary_upload_commit_ok` (`901`) or `_err` (`902`)

##### Pre-validation Request/Response

Request payload:

```
BinaryPrevalidateRequest {
  filename: String,
  mime: String,
  size_bytes: u64,
}
```

Response payload:

```
BinaryPrevalidateResponse {
  accepted: bool,
  message: String,
}
```

Validation rules:
- `size_bytes` must be <= `upload.max_file_size_mb` (0 = unlimited).
- `filename` must pass `security::validate_new_file_name`.
- `mime` must be non-empty; allowed types are enforced via `upload.allowed_extensions`
  by matching the filename extension case-insensitively.

##### Upload Init Request/Response

Request payload:

```
BinaryUploadInitRequest {
  alias: Option<String>,
  tags: Vec<String>,
  filename: String,
  mime: String,
  size_bytes: u64,
}
```

Response payload:

```
BinaryUploadInitResponse {
  upload_id: u32,
  stream_id: u32,
  max_bytes: u64,
  chunk_bytes: u32,
}
```

Validation rules:
- `alias` must pass canonicalization and must not exist.
- `tags` must pass tag validation.
- `filename`, `mime`, and `size_bytes` must pass the same checks as pre-validation.
- On success, the coordinator allocates a temp file at the final blob path plus `.upload` (or `.tmp`)
  and stores stream state keyed by `upload_id`.

##### Stream Chunking

- The client streams file bytes using `StreamChunk` frames with the `stream_id` from init.
- `chunk_bytes` is derived from `WS_MAX_MESSAGE_BYTES` minus the StreamChunk header overhead so
  the encoded frame fits within the message limit.
- The coordinator appends bytes to the temp file and enforces `max_bytes`.
- Each chunk is acknowledged with `Ack { stream_id, seq }`; the client should wait for the ack
  before sending the next chunk.

##### Commit Request/Response

Request payload:

```
BinaryUploadCommitRequest {
  upload_id: u32,
}
```

Response payload:

```
BinaryUploadCommitResponse {
  id: String,
  alias: String,
  mime: String,
  is_markdown: bool,
}
```

Commit behavior:
- The coordinator finalizes the temp file into the content blob path and invokes the management bus
  to write the sidecar and update the cache.
- If streaming failed or exceeded limits, the commit returns an error and the temp file is removed.

##### Cleanup and Recovery

- Temp files must be removed when the WebSocket disconnects, times out, or closes without a commit.
- If the management bus rejects a commit, the temp file is removed immediately.
- On startup, the server scans for `.upload`/`.tmp` files in content storage and deletes them before
  accepting new uploads.

#### Markdown Streaming

Markdown create/update must support stream-backed uploads for large content while preserving
existing validation rules.

##### Actions (Content Domain)

- `content_upload_stream_init` (request id `10`)
  - Response: `content_upload_stream_init_ok` (`1001`) or `_err` (`1002`)
- `content_upload_stream_commit` (request id `11`)
  - Response: `content_upload_stream_commit_ok` (`1101`) or `_err` (`1102`)
- `content_update_stream_init` (request id `12`)
  - Response: `content_update_stream_init_ok` (`1201`) or `_err` (`1202`)
- `content_update_stream_commit` (request id `13`)
  - Response: `content_update_stream_commit_ok` (`1301`) or `_err` (`1302`)

##### Stream Init Payloads

Create:

```
ContentUploadStreamInitRequest {
  alias: Option<String>,
  title: Option<String>,
  tags: Vec<String>,
  nav_title: Option<String>,
  nav_parent_id: Option<String>,
  nav_order: Option<i32>,
  theme: Option<String>,
  size_bytes: u64,
}
```

Update:

```
ContentUpdateStreamInitRequest {
  id: String,
  new_alias: Option<String>,
  title: Option<String>,
  tags: Option<Vec<String>>,
  nav_title: Option<String>,
  nav_parent_id: Option<String>,
  nav_order: Option<i32>,
  theme: Option<String>,
  size_bytes: u64,
}
```

Responses include `upload_id`, `stream_id`, `max_bytes`, and `chunk_bytes` as above.

##### Stream Commit Payloads

Create:

```
ContentUploadStreamCommitRequest { upload_id: u32 }
```

Update:

```
ContentUpdateStreamCommitRequest { upload_id: u32 }
```

Commit rules:
- The streamed bytes must be valid UTF-8 and are stored as Markdown content.
- Size enforcement uses `upload.max_file_size_mb` (0 = unlimited) with no hard-coded caps.

#### Connector Translation and Validation

- The WebSocket connector uses the management registry to translate between frames and
  `ManagementCommand` variants.
- Requests are validated with the same codecs and limits as the socket connector:
  - Field length limits, list sizes, and semantic validations.
  - Invalid payloads return `Response` frames with error actions and messages.
- The connector never performs business logic; it only validates and dispatches.

#### Shared Streaming Helper (Chunking + Compression)

- A shared helper is available to any framed connector (WebSocket, socket) to:
  - Compress large payloads when the content is not already compressed.
  - Split the payload into fixed-size chunks that fit within the max protocol message size.
  - Attach per-chunk metadata: `stream_id`, `seq`, `is_final`, `is_compressed`.
- Compression rules:
  - Skip compression for already-compressed media (video/audio/image formats).
  - Apply compression for text or structured payloads when it reduces size.
- Backpressure:
  - Every `StreamChunk` requires an `Ack { stream_id, seq }` before the next chunk for that stream.
  - Non-stream frames may be interleaved between chunks to allow mixed traffic.
  - Missing or stale acknowledgements terminate the stream with an error frame.

#### Frontend Coordinator (Svelte SPA)

- The SPA owns the WebSocket connection and dispatching:
  - Handles ticket fetch + auth handshake.
  - Sends request frames and resolves promises by `workflow_id`.
  - Routes incoming frames to registered connectors.
  - Manages chunk reassembly and ack responses for streaming payloads.
- Domain services (users, tags, pages, themes, uploads) rely on shared transport helpers in:
  - `nop/ts/admin/src/transport/wsClient.ts`
  - `nop/ts/admin/src/transport/ws-coordinator.ts`
  - `nop/ts/admin/src/transport/ws-streaming.ts`
- These modules bundle into `nop/builtin/admin/admin-spa.js`.

#### TypeScript Protocol Structures

- TypeScript definitions mirror the management bus request/response structs:
  - Domain and action IDs.
  - Request/response payload structures.
  - Binary encoding helpers that match the wire serialization layout.
- WebSocket frames are encoded with a numeric `frame_type` (`u32`) matching the Rust enum
  variant order.
- The frontend uses these structures to construct frames without ad-hoc JSON conversions.
- Protocol codecs live under `nop/ts/admin/src/protocol/` and are bundled into the SPA build.
- System logging settings use the System domain codecs in `nop/ts/admin/src/protocol/system.ts`.

#### Testing Scope

- Unit tests for ticket issuance and expiration behavior.
- Integration tests for WebSocket auth handshake success/failure.
- Protocol tests for request/response encoding and codec validation failures.
- Streaming tests covering compression skip logic, chunk ordering, acks, and interleaving.

### Related Documents

- `docs/management/architecture.md`
- `docs/management/domains.md`
- `docs/management/operations.md`
- `docs/management/wire-serialization.md`
- `docs/infrastructure/csrf-protection.md`
- `docs/admin/user-management.md`
- `docs/admin/ui.md`

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
