# Search Management Domain

Status: Developed

## Objectives

- Provide a management bus domain for admin UI and CLI search operations.
- Replace admin content list search with search-index-backed querying.
- Support targeted search invalidation for a single document.
- Support full search reset (drop + rebuild) operations.
- Keep the domain contract canonical for admin UI and CLI integrations.

## Technical Details

### Scope and Ownership

- This document is the canonical contract for the search management domain.
- Search infrastructure behavior remains defined in `docs/infrastructure/search.md` and `docs/infrastructure/search-ingest.md`.
- Public search UX and API remain defined in `docs/content/search-ux.md`.

### Domain ID and Action IDs

- Domain ID: `21`.
- Request actions: `Find`=1, `Invalidate`=2, `Reset`=3.
- Response actions: `FindOk`=101, `FindErr`=102, `InvalidateOk`=201, `InvalidateErr`=202,
  `ResetOk`=301, `ResetErr`=302.

### Request/Response Shapes

- `SearchFindRequest { query, tags?, markdown_only }`
- `SearchFindResponse { hits: Vec<SearchListItem> }`
- `SearchListItem` mirrors the content list summary fields:
  - `id`, `alias`, `title`, `mime`, `tags`, `nav_title`, `nav_parent_id`, `nav_order`,
    `original_filename`, `is_markdown`.
- `SearchInvalidateRequest { id }`
- `SearchResetRequest {}`

### Query Rules

- Query input is trimmed before validation.
- Query length bounds are `3..=256` characters; out-of-range queries return `FindErr`.
- Query text is passed to `SearchService::query_admin` without RBAC filtering.
- The management domain must not change the internal search indexing or ingestion behavior.
- Tag filtering: when `tags` are provided, results must include every selected tag (all-of
  matching, additional tags allowed), matching the existing content list tag filter behavior. Tag
  constraints are passed into the Tantivy query so tag filtering happens at search time.
- Markdown filtering: when `markdown_only` is true, results include only markdown content.
- Parsing and validation occur before any search execution.

### Result Assembly (Title Priority + Relevance)

Search results are assembled in two phases and merged:

1. **Title-priority phase**:
   - Enumerate content from the in-memory cache.
   - Apply `markdown_only` and tag filters.
   - Match case-insensitive substring against the title (same rule as the current content list query).
   - Preserve the full list-item fields for display.
   - Order matches by title + ID.
2. **Relevance phase**:
   - Execute `SearchService::query_admin` with the same query and tag filters.
   - Query fields include title, alias, and body; tag constraints are enforced in the Tantivy query.
   - Filter results by `markdown_only` (tag filtering is already enforced by the query).
   - Preserve relevance order from Tantivy; when relevance scores are equal, use title + ID as a tiebreak.
3. **Merge**:
   - Deduplicate by content ID.
   - Append relevance results after title-priority results.
   - Cap the final list to the response limit.

### Invalidate Semantics

- Invalidate targets a single content ID.
- The command must reject missing or invalid IDs during request parsing/validation.
- The invalidate operation reindexes the document from canonical persisted markdown sources.
- Invalidation must fail for non-markdown content IDs.

### Reset Semantics

- Reset performs a full search rebuild using `ReindexAllMarkdown` with reason `Forced`.
- Reset clears the failed-ID store prior to rebuilding.
- Reset executes through the search worker pipeline and returns the completion result to the caller.

### Admin UI Integration

- Admin content list search routes through `search.find` instead of `content.list` query filtering.
- Search results must be mapped to content list rows without losing required metadata for list rendering.
- Admin UI results use the same `128`-hit cap as the search domain.
- The admin UI applies the selected column sort to the returned results.
- System settings gains a `Search Reset` section with a reset action that triggers `search.reset`.

### CLI Integration

- Domain: `search` with standard prefix matching and alias handling per the shared CLI rules.
- Commands: `search find [--tag <tag> ...] [--markdown-only] [--] <query words...>`,
  `search invalidate <id>`, `search reset`.
- `search find` accepts the remaining arguments as the raw query without quoting.
- `--tag` may be repeated to supply tag filters.
- `--markdown-only` restricts results to markdown content.
- `--` ends flag parsing so queries can start with `-` without being treated as flags.
- `search invalidate <id>` invalidates a single content ID.
- `search reset` triggers a full reset/reindex.
- CLI output for `find` prints `id`, `alias`, then `title`, separated by single spaces.
- When `alias` is empty, print `-` in its place.
- CLI output does not display tags.
- CLI output uses the title-priority + relevance ordering returned by the domain.

### Field Limits and Validation

- `id` follows the same validation as content IDs in the content management domain.
- `query` length limits must be enforced in codecs and in-domain validation.
- Response hit counts are capped at `128` per request.
