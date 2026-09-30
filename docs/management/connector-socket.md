# Management Connectors: Socket + WebSocket

Status: Developed

## Objectives

- Provide a local Unix domain socket connector for the management bus.
- Provide a WebSocket management connector for admin UI components.
- Restrict socket access to the daemon user; restrict WebSocket access to authenticated admins.
- Define a versioned binary protocol for management requests and responses.
- Reuse management bus domain codecs across both connectors.
- Add generic backend-to-frontend blob streaming for admin WebSocket responses without adding
  content-type-specific frame variants.

## Technical Details

### Shared Protocol Overview

- Management requests and responses use the wire serialization defined in
  `docs/management/wire-serialization.md`.
- Connector stream extensions for content and blob transfers are specified in this document; domain
  payload semantics remain in `docs/management/wire-serialization.md`.
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
- `StreamChunk` and `Ack` frames are bidirectional. The same frame types carry UI-to-backend upload
  bytes and backend-to-frontend response blob bytes.
- No length prefix is needed; the WebSocket frame boundary is the message boundary.

#### Backend WebSocket Coordinator

- The coordinator owns the WebSocket session and routes frames to the appropriate connector:
  - Auth frames are handled locally.
  - Request frames are decoded via the management registry and dispatched to the bus.
  - Response frames are routed back to the requesting client and/or frontend connector.
  - Incoming stream frames are appended to upload streams through the upload registry.
  - Outgoing stream frames are produced from a response stream plan after the response frame is sent.
- The coordinator enforces:
  - Protocol message size limits (63 KiB) and payload limits via `nop_management_contract::codec` field limits.
  - Admin-only access and CSRF ticket validation on connection setup.
  - Backpressure by gating outbound stream chunks on per-frame acknowledgements.

#### Backend-to-Frontend Blob Streaming

The WebSocket connector must support generic streamed response blobs from the backend to the admin
frontend. This is a transport capability, not a Markdown-specific or content-type-specific protocol.

Response selection:

- The WebSocket connector must never send an encoded `Response` frame larger than
  `WS_MAX_MESSAGE_BYTES`.
- If the connector's final encoded-frame guard encounters an oversized response, it must send a
  workflow-scoped system error response when that error response fits and keep the session open. If
  even the error response cannot be sent, it closes the WebSocket session. Large Markdown reads must
  be handled by the streamed path before this emergency guard is reached. When the guard sends this
  fallback error for a response that had prepared stream metadata, the coordinator must not register
  or emit the prepared stream because the client was not given a valid stream contract.
- Content-domain read handlers own the inline-versus-streamed decision for `content.read` when
  `stream_content = true`, because the oversized inline payload must be omitted before connector
  encoding. They use the shared `WS_MAX_RESPONSE_PAYLOAD_BYTES` budget and encode the candidate
  content-read payload before choosing the inline path; the WebSocket connector remains the final
  enforcement guard.
- Domain handlers and connector helpers may use the normal response payload inline when the shared
  budget indicates the encoded WebSocket `Response` frame will fit within `WS_MAX_MESSAGE_BYTES`.
- When a response would exceed `WS_MAX_MESSAGE_BYTES`, the response payload must omit the large data
  field and include stream metadata using the domain's existing optional stream fields.
- For content reads, this means `ContentReadResponse.content = None` with `stream_id`,
  `chunk_bytes`, and `size_bytes` set.
- The connector must send the `Response` frame first. The client uses that frame to discover the
  stream and then receives raw bytes as `StreamChunk` frames over the same connection.

Stream production:

- Shared Rust transport limits live in `nop_management_contract::ws_limits`:
  `WS_MAX_MESSAGE_BYTES`, `WS_RESPONSE_FRAME_OVERHEAD_BYTES`,
  `WS_MAX_RESPONSE_PAYLOAD_BYTES`, `WS_STREAM_CHUNK_OVERHEAD_BYTES`, and
  `WS_MAX_STREAM_CHUNK_BYTES`.
- Shared outbound content stream planning lives in
  `nop_management_bus::content_stream`. `ContentStreamPlan` carries `content_id`,
  `stream_id`, `chunk_bytes`, and `size_bytes`; `assign_content_stream_id(response, stream_id)`
  detects streamed `content.read` responses and writes the connector-owned stream ID before the
  response is encoded; `open_content_blob_stream(context, plan)` resolves the latest content blob
  and returns an incremental producer.
- Shared outbound blob production lives in `nop_management_bus::ws::BlobStreamProducer`. It opens
  the source path after validating the advertised byte length, reads with one bounded
  `chunk_bytes` buffer at a time, emits one final empty chunk for empty blobs, and has no total
  stream-size cap. `validate_outbound_chunk_bytes` enforces the per-frame chunk limit before a
  producer is created.
- If a content blob changes between the read response and stream opening, the producer rejects the
  stream with a source-size mismatch and the connector terminates the stream/session instead of
  sending bytes that no longer match the response metadata.
- `stream_id` is unique within the connector connection for the lifetime of the stream.
  Content-domain handlers do not own this ID; connectors assign it before the response is encoded.
  Upload stream IDs are allocated from the low positive range (`1..=0x7fffffff`). Outbound
  backend-to-frontend WebSocket response stream IDs are allocated by `OutboundBlobStreams` from
  `0x80000000..=0xffffffff`, making the two WebSocket directions collision-free. The socket
  connector assigns the request workflow ID as its local stream ID because socket connections have
  no upload stream ID namespace.
- In the admin WebSocket connector, `OutboundBlobStreams` owns the outbound stream ID allocator and
  per-stream state. Each active stream stores a `BlobStreamProducer`, the one pending ack sequence,
  and whether the final chunk has been sent; it removes the stream after the final ack.
- `chunk_bytes` must be positive and small enough that the encoded `StreamChunk` frame fits within
  `WS_MAX_MESSAGE_BYTES`.
- The connector reads the source blob as bytes and emits `StreamChunk { stream_id, seq, flags,
  payload }` in ascending `seq` order.
- The final chunk sets `STREAM_FLAG_FINAL`. Empty blobs are represented by one final chunk with an
  empty payload; shared helpers must support this case explicitly.
- Backend-to-frontend blob streams are uncompressed. `STREAM_FLAG_COMPRESSED` is never set for this
  path, and `size_bytes` is the exact uncompressed/raw source byte length.
- Every outbound `StreamChunk` requires a matching `Ack { stream_id, seq }` before the next chunk is
  sent.
- A stale ack, wrong stream ID, source read error, disconnect, or timeout terminates the stream by
  closing the WebSocket connection. The frontend streamed-response helper rejects the active
  streamed operation and the normal reconnect path handles later work on a fresh connection.
- The admin WebSocket connector enforces an outbound ack timeout while a response stream has a
  pending unacknowledged chunk. In production the timeout is 30 seconds; tests use a short timeout.

Frontend consumption:

- The admin SPA transport layer exposes a simple streamed-response helper instead of making domain
  services manage raw frame state. `AdminWsClient.requestWithStream(...)` returns the decoded
  `ResponseFrame` plus assembled `Uint8Array` bytes when stream metadata is present.
- The transport registers the expected stream immediately when it decodes a response with stream
  metadata. The request promise is not resolved to the domain service until the final chunk has been
  received, acknowledged, and validated against `size_bytes`.
- WebSocket close/error handling rejects registered streamed-response promises as well as ordinary
  pending requests and pending acks.
- The frontend streamed-response timeout is an idle timeout. It is armed when stream metadata is
  registered and re-armed after each accepted non-final chunk, so it does not impose a total
  duration or size cap on large transfers.
- Incoming `StreamChunk` frames without a registered stream are protocol errors; the client logs or
  rejects them instead of acknowledging and discarding them.
- Domain services decide how to interpret bytes. Markdown source bytes are UTF-8 decoded by the
  content service; binary bytes can remain a `Uint8Array`.
- Existing inline response handling remains valid for responses without stream metadata.

#### Content Identification (Management Bus)

- All admin content operations identify content by ID only; aliases are never accepted as
  identifiers on the management bus.
- Aliases are optional metadata used exclusively for public routing and user-friendly links.

#### Content CRUD (Management Bus)

##### Actions (Content Domain)

- `content_list` (request id `1`)
  - Response: `content_list_ok` (`101`) or `_err` (`102`)
- `content_read` (request id `2`)
  - Response: `content_read_ok` (`201`) or `_err` (`202`)
- `content_update` (request id `3`)
  - Response: `content_update_ok` (`301`) or `_err` (`302`)
- `content_delete` (request id `4`)
  - Response: `content_delete_ok` (`401`) or `_err` (`402`)
- `content_upload` (request id `5`)
  - Response: `content_upload_ok` (`501`) or `_err` (`502`)
- `content_nav_index` (request id `6`)
  - Response: `content_nav_index_ok` (`601`) or `_err` (`602`)
- `content_alias_status` (request id `14`)
  - Response: `content_alias_status_ok` (`1401`) or `_err` (`1402`)

Read request payload:

```
ContentReadRequest {
  id: String,
  stream_content: Option<bool>,
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
  disable_navbar: Option<bool>,
  disable_floating_nav: Option<bool>,
  content_width: Option<ContentWidthMode>,
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
  disable_navbar: bool,
  disable_floating_nav: bool,
  content_width: ContentWidthMode,
  content: Vec<u8>,
}
```

Content read response payload:

```
ContentReadResponse {
  id: String,
  alias: String,
  title: Option<String>,
  mime: String,
  tags: Vec<String>,
  nav_title: Option<String>,
  nav_parent_id: Option<String>,
  nav_order: Option<i32>,
  original_filename: Option<String>,
  theme: Option<String>,
  disable_navbar: bool,
  disable_floating_nav: bool,
  content_width: ContentWidthMode,
  content: Option<String>,
  stream_id: Option<u32>,
  chunk_bytes: Option<u32>,
  size_bytes: Option<u64>,
}
```
Notes:
- `stream_content` defaults to `false` when omitted.
- When `stream_content` is false or omitted, content reads keep their inline behavior for content
  types with inline response fields only while the response can fit the shared inline budget. A
  large Markdown source read without `stream_content = true` returns a content-read error instructing
  the caller to request streaming content.
- When `stream_content` is true, content reads may still return inline content when the encoded
  response fits the connector frame limit.
- When `stream_content` is true and inline content would exceed the WebSocket message limit, or no
  inline representation is available for the content type, the response includes `stream_id`,
  `chunk_bytes`, and `size_bytes`, followed by `StreamChunk` frames over the same connection.
- This streamed response path is generic: Markdown source, binary content, and future large blob
  payloads use the same `StreamChunk`/`Ack` frames.

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
  title: Option<String>,
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
  disable_navbar: bool,
  disable_floating_nav: bool,
  content_width: ContentWidthMode,
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
  disable_navbar: Option<bool>,
  disable_floating_nav: Option<bool>,
  content_width: Option<ContentWidthMode>,
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

#### Shared Streaming Helpers

- File and blob transfers must use incremental streaming. Connectors must not materialize complete
  file-sized payloads or complete stream chunk lists in memory.
- Backend-to-frontend blob streaming uses `BlobStreamProducer`, which reads the source file one
  bounded `chunk_bytes` buffer at a time and returns a single `StreamChunkFrame` per call.
- UI-to-backend upload streaming uses `UploadRegistry`, which writes incoming chunks directly to a
  temp file and validates size, chunk limit, UTF-8 requirements for Markdown streams, and final-byte
  count.
- Compression is not part of the active WebSocket blob-stream protocol. `STREAM_FLAG_COMPRESSED`
  is rejected for uploads and is never set for backend-to-frontend blob streams. Any future
  compressed streaming must first define frontend decompression behavior and raw-versus-compressed
  `size_bytes` semantics.
- Backpressure:
  - Every `StreamChunk` requires an `Ack { stream_id, seq }` before the next chunk for that stream.
  - Non-stream frames may be interleaved between chunks to allow mixed traffic.
  - Missing or stale acknowledgements terminate the stream through the connector-specific failure
    channel; backend-to-frontend WebSocket blob streams close the WebSocket connection.

#### Frontend Coordinator (Svelte SPA)

- The SPA owns the WebSocket connection and dispatching:
  - Handles ticket fetch + auth handshake.
  - Sends request frames and resolves promises by `workflow_id`.
  - Routes incoming frames to registered connectors.
  - Manages chunk reassembly and ack responses for streaming payloads.
- Domain services (users, tags, pages, themes, uploads) rely on shared transport helpers in:
  - `nop/ts/admin/src/transport/wsClient.ts`
  - `nop/ts/admin/src/transport/ws-coordinator.ts`
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
- Website Title settings use the Settings domain codecs in `nop/ts/admin/src/protocol/settings.ts`;
  the domain/action IDs and payloads are defined in `docs/admin/settings.md`.

#### Testing Scope

- Unit tests for ticket issuance and expiration behavior.
- Integration tests for WebSocket auth handshake success/failure.
- Protocol tests for request/response encoding and codec validation failures.
- Streaming tests covering compression skip logic, chunk ordering, acks, interleaving, inbound
  uploads, outbound backend-to-frontend blob streams, and large Markdown reads that cross the
  WebSocket frame-size boundary.

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
