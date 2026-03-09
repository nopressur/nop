# Search Ingestion Pipeline

Status: Developed

## Objectives

- Define how new and updated content is ingested into the Tantivy search index.
- Standardize extraction, normalization, and mapping from source files + ROL sidecars.
- Keep ingestion idempotent and safe for repeated/duplicate events across management/admin/content mutation flows.
- Ensure RBAC metadata is propagated into indexed documents without drift.
- Scope the current release to markdown-only search upsert integration.
- Require ingest-time conversion of markdown body content to plain text before Tantivy indexing.

## Technical Details

### Current Release Scope

- Search upsert is currently limited to markdown pages only.
- Eligibility is enforced by the higher-level content mutation flow: only markdown page writes (`mime == text/markdown`) trigger search upsert.
- Non-markdown content is out of scope for this release and must not trigger search upsert.
- Future releases may add extractor-based ingestion for additional document types, but that work is explicitly out of scope for now.

### Ingestion Inputs

Each markdown ingestion event resolves two canonical inputs:

- markdown body bytes/string supplied by the save/update flow.
- ROL sidecar metadata, including `id`, `alias`, `title`, and `tags`.

The source file remains authoritative. The search index stores only the projection required for search.
Roles are not stored in ROL sidecars and must be derived during ingestion.

Full-reindex events use the same canonical inputs, resolved by enumerating persisted markdown blobs
and sidecars from content storage.

### Integration Point in the Save Pipeline

- Search upsert is emitted only after the markdown blob and its sidecar have both been persisted successfully.
- The integration point is in the existing content mutation handlers in `nop/src/management/content/mod.rs`:
  - `handle_upload` (inline create)
  - `handle_update` (inline update)
  - `handle_upload_stream_commit` (streamed create)
  - `handle_update_stream_commit` (streamed update)
- Required ordering for create/update:
  1. persist markdown blob
  2. persist sidecar
  3. enqueue search upsert to the search worker thread (non-blocking), using in-memory body when available
  4. continue with cache invalidation/release tracking on the request path
- If blob or sidecar persistence fails, search upsert must not run.
- Search indexing must not execute inline on the request thread.
- Cache invalidation and release tracking must keep current latency characteristics and must not wait
  for search indexing commit completion.

### Post-Save Data Structures and Reuse Strategy

The current save/update paths already accumulate most upsert inputs in memory:

- Sidecar metadata:
  - `ContentSidecar` (alias, title, mime, tags, nav/theme fields) is built/updated in handlers.
- Inline markdown body:
  - `ContentUploadRequest.content: Vec<u8>`
  - `ContentUpdateRequest.content: Option<String>`
- Streamed markdown metadata:
  - `UploadKind::MarkdownCreate(MarkdownUploadMeta { content_id, version, sidecar })`
  - `UploadKind::MarkdownUpdate(MarkdownUpdateMeta { content_id, base_version, sidecar, ... })`

Current gap for streamed markdown:

- `UploadRecord` persists bytes to a temp file and tracks UTF-8 validity, but does not retain the full markdown body in memory.

Required reuse rule:

- If markdown body is already present in memory in the mutation handler, build the upsert payload from that in-memory data.
- Inline create/update should reuse the existing payload body and `ContentSidecar`.
- Streamed create/update keeps the existing upload/save flow unchanged; when markdown body is not available in memory at commit time, the search worker loads blob/sidecar from disk.
- Upsert assembly should reuse existing owned buffers/strings from the mutation context and avoid additional full-body copies.
- Disk fallback reads for streamed commits are accepted for this release to avoid disruption to current streaming implementation.

### Extraction and Normalization

- Markdown body is provided by the save/update flow and must be valid UTF-8.
- Ingestion parses markdown with `pulldown_cmark` and extracts text-bearing content only
  (strikethrough, tables, footnotes, and task lists are enabled).
- Markdown structural syntax (headings, emphasis markers, link/image syntax, fences, and list markup) is not indexed.
- Visible text content is preserved for indexing, including:
  - link labels (for example `[Docs](https://example.com)` contributes `Docs`);
  - image alt text (for example `![Hero Alt](/hero.png)` contributes `Hero Alt`);
  - code spans/blocks and footnote reference text.
- Link destinations and image URLs are not indexed unless they appear as visible text content.
- Raw HTML fragments inside markdown are sanitized and stripped to plain text before indexing.
- HTML sanitization strips tags, attributes, comments, and unsafe content (for example script/style).
- Block boundaries are normalized to prevent word concatenation, including:
  - paragraphs, headings, block quotes;
  - list items (ordered, unordered, task lists);
  - code blocks and HTML blocks;
  - table rows and cells.
- Line endings and whitespace are normalized deterministically before indexing.
- Tantivy receives plain-text normalized fields only.
- Binary/document extraction for non-markdown formats is deferred to future releases.

### Index Document Mapping

The ingestion output must map into the search schema:

- `id` <- canonical content identifier (stable across updates).
- `alias` <- sidecar alias.
- `title` <- sidecar title.
- `tags` <- sidecar tags (multi-valued).
- `roles` <- RBAC role tokens derived from tags via the IAM roles module (union/intersect rules)
  and normalized to lowercase.
- `body` <- plain text extracted from markdown body supplied by the mutation flow when available in memory, otherwise loaded by the worker from persisted markdown blob.
  - markdown and HTML markup are stripped;
  - visible textual content (including link labels and image alt text) is indexed;
  - link/image destination URLs are excluded unless present as visible text.

Document identity is always keyed by `id` for deterministic updates and deletes.

### Mutation Semantics

Ingestion emits indexing commands to partitioned ingestion workers:

- markdown create/update (in-memory body available) -> `UpsertMarkdownInMemory { id, alias, title, tags, roles, body }`
- markdown create/update (body not available in memory) -> `UpsertMarkdownFromDisk { id, version }`
- delete (markdown-indexed content only) -> `Delete { id }`
- full rebuild -> `ReindexAllMarkdown { reason: MissingIndex | Forced }`

Upsert contract requirements:

- In-memory path: caller supplies all indexed fields and full markdown `body`.
- Disk fallback path: caller supplies `id` + persisted `version`; worker loads markdown blob and sidecar from disk.
- `roles` are derived from tags using existing union/intersect precedence.
- Command emission is gated by markdown eligibility only.
- Delete command emission is also gated by markdown eligibility; non-markdown content is not indexed
  in this release and must not produce search delete commands.
- Upsert dispatch is asynchronous: management/admin/content mutation handlers enqueue work and return
  without waiting for Tantivy commit/reload.
- Upsert execution runs on dedicated worker threads (not the request thread).
- `ReindexAllMarkdown` is a controlled rebuild operation:
  - startup `MissingIndex` reindex is mandatory before request serving starts;
  - `Forced` reindex is explicitly requested and rebuilds from source files.

### Worker Partitioning and Ordering

- `search.worker_count` controls ingestion worker partitions and defaults to `1`.
- Effective worker count is capped at `16`: `effective_worker_count = min(worker_count, 16)`.
- If configured `worker_count` is above `16`, startup logs a warning and uses `16`.
- Worker selection uses numeric partitioning by ID:
  `partition = content_id_u64 % effective_worker_count`.
- This guarantees jobs for the same `id` are always handled by the same worker and cannot execute concurrently on different workers.
- Per-partition processing is FIFO.
- Tantivy write/commit remains serialized in a single writer stage behind the worker pool.
- Current release behavior has no retry or requeue mechanism for failed jobs.

Upsert semantics are implemented as:

1. delete by `id` term
2. add new document
3. commit
4. reload reader

This ensures a single visible version per document identifier.

### Trigger Sources

Search ingestion is fed by mutation sources that already change content state:

- content pipeline write operations.
- management bus operations.
- admin operations that mutate content/metadata.

Each markdown mutation path must emit exactly one logical search upsert request per content change.
Non-markdown mutations are intentionally skipped in this release.

Full-reindex trigger sources:

- startup bootstrap when index is missing;
- explicit forced rebuild trigger from an internal search API endpoint.
- management-bus command wiring for forced rebuild is defined in later integration work.

### Idempotency and Recovery

- Repeating the same upsert for a given `id` is safe and leaves one current indexed version.
- Repeating delete for missing `id` is a no-op success.
- Startup with missing index performs full markdown reindex before serving requests.
- Forced full reindex replaces existing index contents with a new source-derived snapshot.
- Full rebuild starts with failed-ID reset by deleting `state/sys/search/failed-ids.yaml` and
  reinitializing the in-memory failed-ID cache as empty.
- Failed ingestion jobs are logged and recorded in the failed-ID store; automatic retries are out of scope for this release.

### Failed-ID Persistence

- Failed search ingestion IDs are persisted to a YAML file as a simple list of content IDs.
- Search subsystem storage root is `state/sys/search/`.
- Tantivy index directory is `state/sys/search/index/`.
- Canonical file path: `state/sys/search/failed-ids.yaml`.
- YAML format:

```yaml
- "0123456789abcdef"
- "fedcba9876543210"
```

- Store behavior:
  - full in-memory cache of failed IDs for fast reads;
  - queue-based single writer for serialized persistence;
  - synchronous reader API served from in-memory snapshot.
- On startup, the store loads the YAML file into memory before workers start.
- A successful upsert or delete for an ID should remove that ID from the failed-ID list.
- Full rebuild deletes the failed-ID file and starts a fresh empty failed-ID set before reindexing.
- Admin content list integration will consume this store in a later step; UI behavior is intentionally unspecified in this document.

### RBAC Integrity

- `roles` are computed from tag metadata and tag definitions at ingest time; they are not read from ROL sidecar role fields.
- Role derivation uses the IAM roles module to apply the canonical tag-to-role behavior:
  - any explicit `intersect` tag forces intersect across the full tag set;
  - otherwise any explicit `union` tag applies union;
  - otherwise default to intersect.
- Search ingestion reuses the same IAM role-resolution implementation used by the public cache path
  so tag role outcomes stay identical across serving and search.
- Ingestion must preserve the same resolved role outcomes used by the public RBAC pipeline.
- RBAC is enforced at query time, but ingestion must still preserve accurate role tokens.

### Tag Integrity

- `tags` values are copied from canonical sidecar metadata at ingest time.
- Tags are normalized consistently (trimmed, stable casing policy) before indexing.
- Tags are always stored in the index to support the admin tag-inclusive query profile.
- Public query profile excludes tags from matching even though tags are present in the index.

### Observability

Logging policy by level:

- `info`:
  - startup lifecycle and rebuild lifecycle only (`MissingIndex` rebuild, `Forced` rebuild).
  - no document-level file actions at `info`.
- `warn`:
  - indexing failures (upsert/delete/commit/reload/reindex) with context required for diagnosis.
  - startup worker-count clamp warning when configured `worker_count > 16`.
- `debug`:
  - main document-level indexing transitions (`add/update`, `remove`) without verbose worker internals.
- `trace`:
  - detailed execution context including worker/partition, content id, version/path source, queue transitions, and stage timings.

Metrics/telemetry should capture:

- ingest attempts by source (content, management, admin).
- markdown upsert attempts, skips (non-markdown), and failures.
- async enqueue outcomes (queued, dropped/rejected, queue full).
- queue depth and worker lag for search upsert jobs.
- failed-ID store writes/loads and current failed-ID count.
- indexing command outcomes (upsert/delete/commit/reload/reindex).
- terminal failures (no retry in this release).

### Testing Scope

- Unit tests for field mapping and normalization.
- Unit tests for markdown/body sanitization that verify markdown markup is removed from indexed body text.
- Unit tests for HTML stripping in markdown body, including inline HTML and block HTML fragments.
- Unit tests that verify deterministic whitespace and newline normalization after markup stripping.
- Markdown-only gating tests (`is_markdown` true/false) for all create/update mutation paths.
- Order-of-operations tests proving upsert runs only after blob + sidecar persistence succeeds.
- Payload completeness tests ensuring upsert receives `id`, `alias`, `title`, `tags`, derived `roles`, and full markdown `body`.
- Fallback tests ensuring streamed markdown commits can enqueue disk-backed upsert jobs when body is not available in memory.
- Integration tests for upsert and delete mutation flows from each trigger source.
- Integration tests asserting markdown heading/emphasis/link syntax and HTML tags are not searchable as literal tokens in Tantivy.
- Non-blocking behavior tests ensuring content save/update response is not delayed by slow search
  commits.
- Threading tests ensuring upsert execution happens on the dedicated search worker thread, not the
  request handling thread.
- Partitioning tests ensuring same `id` always maps to the same worker and is processed serially.
- No-retry failure tests ensuring failed jobs are logged and persisted in `failed-ids.yaml`.
- Logging-level tests ensuring:
  - `info` logs appear for startup/rebuild lifecycle only;
  - per-document add/remove does not emit `info`;
  - indexing failures emit `warn`;
  - worker-count clamp (`worker_count > 16`) emits `warn` and uses effective count `16`;
  - document add/remove emits `debug`;
  - worker/file execution details are emitted at `trace`.
- RBAC mapping tests ensuring tag-derived role resolution is indexed correctly.
- Tag mapping tests ensuring sidecar tags are normalized and indexed as expected.
- Streamed markdown tests ensuring existing streaming behavior remains unchanged and worker disk-read fallback builds correct index documents.
- Seeded-markdown startup tests that pre-create multiple markdown + sidecar files and verify:
  - missing-index startup performs full rebuild and indexed queries return the seeded documents;
  - a subsequent startup with existing index can serve query results without rebuild when force is not requested.
- Forced-rebuild tests that verify the index is regenerated from current markdown files when force is requested.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
