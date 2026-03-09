# Search Infrastructure (Tantivy)

Status: Developed

## Objectives

- Provide infrastructure-level search using Tantivy as an embedded on-disk index.
- Keep files and ROL sidecars as the system of record, with search treated as a projection.
- Enforce RBAC in the search query path so unauthorized documents are never returned.
- Define a schema and runtime integration that can be consumed by management, admin, and content flows.
- Keep indexing deterministic for insert, update, and delete operations.

## Technical Details

### Architecture

- Search consists of four infrastructure services:
  - `ingestion`: transforms content + sidecar metadata into index documents.
  - `indexing`: owns Tantivy write access and applies upsert/delete commits.
  - `query`: executes user search requests using the current reader view.
  - `reindex`: performs full source-driven rebuilds by enumerating markdown content + sidecars.
- Text extraction is an ingestion concern; Tantivy only indexes the normalized fields it receives.
- Current release scope is markdown-only ingestion; non-markdown ingestion is deferred to later releases.
- Role resolution is an ingestion concern: roles are derived from content tags using the IAM roles
  module (`union`/`intersect` precedence), because roles are not stored directly in ROL sidecars.
- Derived role tokens are normalized to lowercase via the IAM roles module before indexing.
- The index is persisted on disk and can be reused across restarts.
- Full reindex is mandatory when no usable index exists and must also be available as an explicit forced operation.

### Index Schema

The initial schema fields:

- `id`: stable document identifier; indexed for term delete/update and stored for result payloads.
- `alias`: searchable identifier; stored for result payloads.
- `title`: searchable title; stored for result payloads.
- `tags`: multi-valued tag terms; stored and indexed for admin-focused tag-aware search.
- `body`: extracted plain text for full-text search; indexed and not stored.
- `roles`: multi-valued RBAC tokens used for query-time authorization filtering, computed at ingest
  time from tags using IAM roles module resolution rules and normalized to lowercase.

```rust
use tantivy::schema::*;

let mut sb = Schema::builder();
let id = sb.add_text_field("id", STRING | STORED);
let alias = sb.add_text_field("alias", TEXT | STORED);
let title = sb.add_text_field("title", TEXT | STORED);
let tags = sb.add_text_field("tags", STRING | STORED);
let body = sb.add_text_field("body", TEXT);
let roles = sb.add_text_field("roles", STRING);
let schema = sb.build();
```

### Storage and Lifecycle

- Search state is stored under `state/sys/search/`.
- Tantivy index files live under `state/sys/search/index/`.
- Failed ingestion IDs are persisted at `state/sys/search/failed-ids.yaml`.
- Startup behavior:
  - open an existing index when present;
  - when index is missing, create a new index and run full markdown enumeration + indexing before serving requests;
  - when forced reindex is requested, drop/recreate index contents and run full markdown enumeration + indexing before serving requests.
- If existing index open/read fails (corrupt or unreadable index), startup must hard-stop immediately
  and surface the error to the operator.
- Exactly one active writer is allowed for a given index directory.
- Query paths use `IndexReader` and per-request `Searcher`.
- Reader visibility should use explicit reload after commit for deterministic management/admin behavior.

### Configuration

Search introduces a dedicated top-level configuration section:

```yaml
search:
  max_memory_mb: 128
  worker_count: 1
```

- `search.max_memory_mb` defines the maximum memory budget (MiB) used by the Tantivy search
  subsystem for write/index operations.
- `search.worker_count` defines the number of partitioned ingestion workers.
- `max_memory_mb` must be a positive integer greater than `0`.
- `worker_count` must be a positive integer greater than `0` and defaults to `1`.
- `worker_count` has a hard maximum of `16`.
- If configured above `16`, effective worker count is clamped to `16` and a startup warning is logged.
- The subsystem converts this setting to bytes when creating Tantivy writer resources.

### Actix Integration Pattern

- Shared state holds `Index` and `IndexReader`.
- Ingestion jobs are enqueued to partitioned workers using
  `partition = content_id_u64 % effective_worker_count`.
- Partitioning guarantees jobs for the same `id` always execute on the same worker and are processed in FIFO order for that `id`.
- Tantivy write/commit operations remain serialized through a single writer stage.
- Write commands are modeled as:
  - `Upsert { id, document }`
  - `Delete { id }`
  - `CommitAndReload`
- Request handlers must enqueue write commands asynchronously and must not perform Tantivy commit/reload on the request thread.
- Search indexing runs on the dedicated worker thread so content persistence/cache invalidation/release tracking remain fast and non-blocking.
- On successful commit, the worker triggers reader reload to make changes query-visible.

### Startup Instantiation

Search service startup is instantiated in `nop/src/main.rs` before `HttpServer::new`, after core
runtime/bootstrap services are available.
Index health/open checks for existing indexes must run in the pre-daemon startup path so failures
abort before daemon forking.

Required startup sequence:

1. Resolve search config from validated config (`search.max_memory_mb`, `search.worker_count`) in
   `nop/src/config.rs`, computing `effective_worker_count = min(worker_count, 16)` and logging a
   startup warning when clamping occurs.
2. Resolve search runtime paths from canonical runtime root (`state/sys/search/`,
   `state/sys/search/index/`, `state/sys/search/failed-ids.yaml`) using runtime path helpers in
   `nop/src/runtime_paths.rs`.
3. Ensure search directories exist before service construction.
4. Create failed-ID store and load snapshot from `state/sys/search/failed-ids.yaml`.
5. Resolve startup reindex mode:
   - `MissingIndex` when no usable index exists;
   - `Forced` when an explicit force-reindex request is provided to the startup path.
6. Run startup integrity check using `Open + Reader Warm`:
   - open/create Tantivy index at `state/sys/search/index/`;
   - construct `IndexReader` and acquire initial `Searcher` to warm reader state;
   - if open/read/warm fails for an existing index, abort startup immediately (hard stop).
   - no schema fingerprint/version compatibility check is performed in this release.
7. Create the search service (`nop/src/search/`) with:
   - partitioned ingestion workers from `effective_worker_count`;
   - Tantivy writer memory budget from `search.max_memory_mb`;
   - single serialized write/commit stage.
8. If startup reindex mode is `MissingIndex` or `Forced`, execute full markdown reindex before
   route registration:
   - enumerate markdown documents + sidecars from canonical content storage;
   - build deterministic upsert jobs (`id`, metadata, derived roles, normalized body);
   - commit and reload reader after rebuild completion.
9. Inject the resulting search service handle into management shared context
   (`nop/src/management/core.rs`) so content mutation handlers can enqueue async upsert/delete work.
10. Expose query capability through `SearchService` module methods only; public/admin/management
    integration paths call this module API in their own phases.

Failure behavior:

- Invalid search config, failed directory creation, failed failed-ID store load, or failed Tantivy
  index open/create are fatal startup errors.
- Existing-index open/read failure must abort startup before daemonization/fork (operators must
  delete or repair the index).
- Missing-index startup rebuild is best-effort: per-document failures are logged and tracked, but do
  not abort startup.
- Forced reindex failures are surfaced to the caller and logged; they do not terminate the running
  server.
- Request handling and route registration must not begin unless search startup succeeds.

### Full Reindex Semantics

- Full reindex is source-authoritative: index state is rebuilt from persisted markdown blobs and
  sidecars, not from existing index content.
- Reindex input scope for current release is markdown only; non-markdown content is skipped.
- Schema migration/version detection is out of scope; schema evolution is handled explicitly in
  dedicated follow-up work when schema changes are introduced.
- Reindex command contract:
  - `ReindexAllMarkdown { reason: MissingIndex | Forced }`
- Reindex execution contract:
  1. initialize/clear target index state for rebuild
  2. delete `state/sys/search/failed-ids.yaml` and reset failed-ID in-memory cache to empty
  3. enumerate markdown files and sidecars
  4. derive roles from tags using existing union/intersect rules
  5. upsert all eligible markdown documents
  6. commit and reload reader once rebuild completes
- Reindex is best-effort at the per-document level: failures are logged and tracked in the failed-ID
  store without aborting the rebuild.

### Failure Tracking

- Search ingestion does not retry failed jobs in this release.
- Failed jobs are logged and their `id` is recorded in a persisted YAML failed-ID list.
- Failed reindex load attempts (sidecar read/parse failures, alias/title validation failures, blob
  read failures, or reserved alias violations) are recorded in the failed-ID list.
- Failed-ID storage:
  - in-memory cache for fast reads;
  - queue-based writer for serialized disk writes;
  - synchronous read access against the in-memory snapshot.
- The failed-ID list is intended to be surfaced in admin content views; UI behavior is defined separately.

### Logging Policy

Search logging must stay low-noise by default.

- `info` level is reserved for lifecycle events only:
  - search service startup summary;
  - missing-index full rebuild start/completion;
  - forced full rebuild start/completion.
- `warn` level is required for indexing failures:
  - upsert/delete/commit/reload/reindex failures with actionable context (`id`, reason, stage).
  - startup config normalization when `search.worker_count > 16` and effective count is clamped to `16`.
- `debug` level is for main document-level state transitions:
  - document added/updated in index;
  - document removed from index.
- `trace` level is for execution detail:
  - worker partition/worker id, content id, version/path source, queue transitions, and stage timings.

Required constraints:

- Do not use `info` for per-document add/remove actions.
- File-level detail belongs to `trace`, not `info`.

### Query and RBAC Enforcement

The search module must provide two query capabilities via `SearchService` methods:

1. `query_public` capability for public-facing consumers:
   - build content query with the public profile;
   - add RBAC role filters (user roles + `__public__`) to the Tantivy query unless the caller is
     admin, in which case RBAC filtering is skipped;
   - execute a relevance-ranked search using the content query;
   - return raw hits so the public API can apply final access validation using the in-memory page
     cache (do not trust search index roles as the sole gate).
2. `query_admin` capability for admin/management consumers:
   - build content query with the admin profile;
   - execute without RBAC filtering (full-access query capability).

Query profiles:

- Admin query profile:
  - includes `title`, `alias`, `body`, and `tags`.
  - used by management/admin search flows where operators need tag-aware lookup and full-access retrieval.
- Public query profile:
  - includes `title`, `alias`, and `body`.
  - explicitly excludes `tags` from matching behavior.

Required behavior:

- Query capability is provided by module API only (`SearchService`) and is not tied to a specific transport.
- Public access control must be validated against the in-memory cache after query execution (in the
  public API handler); search index role tokens are a pre-filter, not the sole gate.
- Admin query capability is explicitly non-RBAC and returns all matching indexed documents.
- Query parsing is plain-text only; operators/syntax parsing is out of scope in this phase.
- Public API query input validation must enforce `len(trim(q))` in the inclusive range `3..=256`.
- Public query capability enforces a hard-coded maximum result size of `16` (no caller-provided limit).
- Admin query capability enforces a hard-coded maximum result size of `128`.
- Query results are ranked by Tantivy relevance first, then the final returned set is sorted
  alphabetically by `title` after access filtering.
- Result payload mapping uses stored fields only (`id`, `alias`, `title`, `tags`).
- Full content access is resolved from source files only after authorization.

### Public Query Validation and Error Leakage Control

- Validation boundary:
  - public endpoint (`GET /api/search`) validates query length before invoking `SearchService::query_public`.
  - backend validation is authoritative; frontend validation is complementary UX behavior.
- Input bounds:
  - minimum query length: `3` characters after trim;
  - maximum query length: `256` characters after trim.
- Invalid input handling:
  - return `400 Bad Request` for out-of-bounds query lengths.
- Internal error handling:
  - return `500 Internal Server Error` for execution failures;
  - client-facing error payload must be generic and must not include internal parser/service details;
  - detailed error cause is logged server-side.

### Admin RBAC Bypass, Role Normalization, and Reindex Failure Semantics

- Admin RBAC bypass:
  - public query callers with the `admin` role must receive full-access search results.
  - public query RBAC filtering must be skipped for admin callers to align with public access rules.
- Role normalization: role tokens in search must be normalized via the IAM roles module (lowercase
  ASCII identifiers).
- Role comparisons in search must use canonical IAM-normalized role IDs; search must not implement
  its own normalization or validation.
- Reindex failure semantics:
  - missing-index startup rebuild uses best-effort per-document semantics and does not abort startup.
  - existing-index open failures remain fatal at startup and require operator intervention.
  - forced reindex failures are returned to the caller without terminating the server.

### Resource and Size Controls

- Configure writer memory budget conservatively and tune with measured ingestion throughput.
- Keep stored fields minimal to control index growth and reduce accidental data exposure.
- Do not store full extracted bodies unless explicitly required by a later approved requirement.

### Cross-Domain Integration Contract

- Management and admin operations that mutate content must emit search index mutations through the indexing service contract.
- Content pipeline publishes the canonical metadata and extracted text inputs used by ingestion.
- Search infrastructure remains domain-neutral; domain-specific permissions are expressed only through `roles` tokens.
- Public/admin/management integrations must call shared query methods on `SearchService`; query behavior differences are selected via module query capability, not duplicated per transport.
- Forced reindex is exposed first as an internal search API endpoint; management-bus command wiring is
  defined in later integration work.

### Testing Scope

- Schema construction tests for required fields and options.
- Index lifecycle tests:
  - open existing index
  - create missing index
  - existing-index `Open + Reader Warm` succeeds before route registration
  - existing-index warm failure hard-stops startup
  - missing-index startup triggers full markdown rebuild
  - forced full reindex rebuilds from source files
  - existing-index startup serves index without rebuild when force is not requested
- Config normalization tests:
  - `worker_count > 16` is clamped to `16`
  - startup emits warning when clamp is applied
- Write path tests for upsert/delete/commit/reload semantics.
- Query tests for module query capabilities:
  - content matching for both query profiles
  - admin full-access, tag-inclusive matching
  - public RBAC-filtered, tag-excluded matching
  - public query limit fixed to `16`
  - plain-text parsing rejects/ignores operator syntax behavior
  - title-alphabetic ordering behavior
  - stored-field-only result mapping
- Public API tests:
  - invalid query lengths (`<3`, `>256`, blank/missing after trim) return `400`.
  - internal query failures return `500` with generic client-visible message.
- Admin search wiring is implemented; coverage currently remains in search unit/integration tests,
  CLI integration tests for search commands, and `/api/search` tests. Dedicated management-bus
  integration coverage for admin UI search flows remains pending.

For ingestion-specific behavior, see `docs/infrastructure/search-ingest.md`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
