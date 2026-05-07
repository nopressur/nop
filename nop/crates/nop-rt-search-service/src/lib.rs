// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod failed_ids;
#[cfg(test)]
mod test_support;

use failed_ids::FailedIdStore;
use log::{debug, info, trace, warn};
use nop_config::{SEARCH_MAX_WORKER_COUNT, SearchConfig};
use nop_content_store::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, content_id_hex, normalize_optional_alias,
    read_sidecar, sidecar_path,
};
use nop_content_store::reserved_paths::ReservedPaths;
use nop_roles::{
    ADMIN_ROLE, ResolvedRoleSet, TagRoleRecord, normalize_role, resolve_roles_for_tags,
};
use nop_rt_paths::RuntimePaths;
use pulldown_cmark::{Event, Options, Parser, TagEnd};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, Query, QueryParser, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, STORED, STRING, Schema, TEXT,
    TantivyDocument as TantivyOwnedDocument, Value,
};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term, doc};

const SEARCH_ROLE_PUBLIC: &str = "__public__";
const SEARCH_ROLE_DENY: &str = "__deny__";
const SEARCH_PUBLIC_QUERY_LIMIT: usize = 16;
const SEARCH_ADMIN_QUERY_LIMIT: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReindexReason {
    MissingIndex,
    Forced,
}

impl fmt::Display for ReindexReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReindexReason::MissingIndex => write!(f, "missing-index"),
            ReindexReason::Forced => write!(f, "forced"),
        }
    }
}

#[derive(Clone)]
pub struct SearchService {
    partition_count: usize,
    partitions: Vec<mpsc::Sender<PartitionCommand>>,
    writer_tx: mpsc::Sender<WriterCommand>,
    failed_ids: Arc<FailedIdStore>,
    reader: IndexReader,
    fields: SearchSchemaFields,
}

#[derive(Debug, Clone)]
pub struct UpsertMarkdownInMemoryRequest {
    pub id: ContentId,
    pub version: ContentVersion,
    pub alias: String,
    pub title: String,
    pub tags: Vec<String>,
    pub body: String,
}

#[derive(Debug, Clone, Copy)]
pub struct UpsertMarkdownFromDiskRequest {
    pub id: ContentId,
    pub version: ContentVersion,
}

#[derive(Debug, Clone)]
pub struct QueryPublicRequest {
    pub query: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct QueryAdminRequest {
    pub query: String,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryHit {
    pub id: String,
    pub alias: String,
    pub title: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct ScoredHit {
    score: f32,
    hit: QueryHit,
}

pub struct SearchStartup {
    pub service: Arc<SearchService>,
    pub startup_reindex_reason: Option<ReindexReason>,
}

#[derive(Debug, Clone)]
struct SearchSchemaFields {
    id: Field,
    alias: Field,
    title: Field,
    tags: Field,
    body: Field,
    roles: Field,
}

#[derive(Debug)]
struct SearchDocument {
    version: ContentVersion,
    id_hex: String,
    alias: String,
    title: String,
    tags: Vec<String>,
    body: String,
    roles: Vec<String>,
}

#[derive(Debug)]
enum PartitionCommand {
    UpsertInMemory(UpsertMarkdownInMemoryRequest),
    UpsertFromDisk(UpsertMarkdownFromDiskRequest),
    DeleteMarkdown(ContentId),
}

#[derive(Debug)]
enum WriterCommand {
    Upsert {
        worker_id: usize,
        document: SearchDocument,
        reply: mpsc::Sender<Result<(), String>>,
    },
    Delete {
        worker_id: usize,
        id: ContentId,
        reply: mpsc::Sender<Result<(), String>>,
    },
    ReindexAllMarkdown {
        reason: ReindexReason,
        reply: mpsc::Sender<Result<(), String>>,
    },
}

#[derive(Debug)]
enum ResolvedSearchRoles {
    Public,
    Deny,
    Restricted(Vec<String>),
}

struct ReindexResources<'a> {
    content_dir: &'a Path,
    state_sys_dir: &'a Path,
    failed_ids: &'a FailedIdStore,
    reserved_paths: &'a ReservedPaths,
}

pub fn initialize(
    runtime_paths: &RuntimePaths,
    search: &SearchConfig,
    reserved_paths: ReservedPaths,
    force_reindex_on_startup: bool,
) -> Result<SearchStartup, String> {
    let schema = build_schema();
    let fields = schema_fields(&schema)?;
    let index_exists = index_metadata_exists(&runtime_paths.state_search_index_dir);
    let index = if index_exists {
        Index::open_in_dir(&runtime_paths.state_search_index_dir).map_err(|err| {
            format!(
                "Failed to open existing search index {}: {}",
                runtime_paths.state_search_index_dir.display(),
                err
            )
        })?
    } else {
        Index::create_in_dir(&runtime_paths.state_search_index_dir, schema.clone()).map_err(
            |err| {
                format!(
                    "Failed to create search index {}: {}",
                    runtime_paths.state_search_index_dir.display(),
                    err
                )
            },
        )?
    };

    let reader = index
        .reader_builder()
        .reload_policy(ReloadPolicy::Manual)
        .try_into()
        .map_err(|err| format!("Failed to create search index reader: {}", err))?;
    let _ = reader.searcher();

    let failed_ids = Arc::new(FailedIdStore::new(
        runtime_paths.state_search_failed_ids_file.clone(),
    )?);

    let writer_memory_bytes = search
        .max_memory_mb
        .checked_mul(1024)
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| "Search max_memory_mb overflows byte conversion".to_string())?;
    let writer_memory_bytes = usize::try_from(writer_memory_bytes)
        .map_err(|_| "Search writer memory budget does not fit in usize".to_string())?;
    let writer = index.writer(writer_memory_bytes).map_err(|err| {
        format!(
            "Failed to initialize search writer (max_memory_mb={}): {}",
            search.max_memory_mb, err
        )
    })?;

    let effective_worker_count = search.worker_count.clamp(1, SEARCH_MAX_WORKER_COUNT);
    let writer_tx = spawn_writer_thread(
        writer,
        reader.clone(),
        fields.clone(),
        runtime_paths.content_dir.clone(),
        runtime_paths.state_sys_dir.clone(),
        failed_ids.clone(),
        reserved_paths.clone(),
    )?;
    let partitions = spawn_partition_threads(
        effective_worker_count,
        runtime_paths.content_dir.clone(),
        runtime_paths.state_sys_dir.clone(),
        reserved_paths,
        failed_ids.clone(),
        writer_tx.clone(),
    )?;

    let service = Arc::new(SearchService {
        partition_count: effective_worker_count,
        partitions,
        writer_tx,
        failed_ids,
        reader,
        fields,
    });

    info!(
        "Search service startup: workers={}, index_dir={}, failed_ids_file={}",
        service.partition_count,
        runtime_paths.state_search_index_dir.display(),
        runtime_paths.state_search_failed_ids_file.display()
    );

    let startup_reindex_reason = if force_reindex_on_startup {
        Some(ReindexReason::Forced)
    } else if !index_exists {
        Some(ReindexReason::MissingIndex)
    } else {
        None
    };

    if let Some(reason) = startup_reindex_reason {
        info!("Search reindex start (reason={})", reason);
        service.reindex_all_markdown(reason)?;
        info!("Search reindex completed (reason={})", reason);
    }

    Ok(SearchStartup {
        service,
        startup_reindex_reason,
    })
}

impl SearchService {
    pub fn partition_count(&self) -> usize {
        self.partition_count
    }

    pub fn enqueue_upsert_markdown_in_memory(
        &self,
        request: UpsertMarkdownInMemoryRequest,
    ) -> Result<(), String> {
        let partition = partition_for_id(request.id, self.partition_count);
        trace!(
            "Search enqueue upsert-in-memory id={} version={} partition={}",
            content_id_hex(request.id),
            request.version.0,
            partition
        );
        self.partitions[partition]
            .send(PartitionCommand::UpsertInMemory(request))
            .map_err(|err| format!("Search partition queue unavailable: {}", err))
    }

    pub fn enqueue_upsert_markdown_from_disk(
        &self,
        request: UpsertMarkdownFromDiskRequest,
    ) -> Result<(), String> {
        let partition = partition_for_id(request.id, self.partition_count);
        trace!(
            "Search enqueue upsert-from-disk id={} version={} partition={}",
            content_id_hex(request.id),
            request.version.0,
            partition
        );
        self.partitions[partition]
            .send(PartitionCommand::UpsertFromDisk(request))
            .map_err(|err| format!("Search partition queue unavailable: {}", err))
    }

    pub fn enqueue_delete_markdown(&self, id: ContentId) -> Result<(), String> {
        let partition = partition_for_id(id, self.partition_count);
        trace!(
            "Search enqueue delete id={} partition={}",
            content_id_hex(id),
            partition
        );
        self.partitions[partition]
            .send(PartitionCommand::DeleteMarkdown(id))
            .map_err(|err| format!("Search partition queue unavailable: {}", err))
    }

    pub fn query_public(&self, request: QueryPublicRequest) -> Result<Vec<QueryHit>, String> {
        let raw = request.query.trim();
        if raw.is_empty() {
            return Ok(Vec::new());
        }

        let index = self.reader.searcher().index().clone();
        let content_query = build_plain_text_query(
            &index,
            vec![self.fields.title, self.fields.alias, self.fields.body],
            raw,
        )?;
        let mut role_terms = HashSet::new();
        let mut is_admin = false;
        for role in request.roles {
            match normalize_role(&role) {
                Ok(normalized) => {
                    if normalized == ADMIN_ROLE {
                        is_admin = true;
                    }
                    role_terms.insert(normalized);
                }
                Err(err) => {
                    warn!("Skipping invalid role '{}' for search query: {}", role, err);
                }
            }
        }

        let query = if is_admin {
            content_query
        } else {
            role_terms.insert(SEARCH_ROLE_PUBLIC.to_string());
            let mut role_queries: Vec<(Occur, Box<dyn Query>)> =
                Vec::with_capacity(role_terms.len());
            for role in role_terms {
                let term = Term::from_field_text(self.fields.roles, &role);
                role_queries.push((
                    Occur::Should,
                    Box::new(TermQuery::new(term, IndexRecordOption::Basic)),
                ));
            }

            let mut subqueries = Vec::with_capacity(role_queries.len() + 1);
            subqueries.push((Occur::Must, content_query));
            subqueries.push((Occur::Must, Box::new(BooleanQuery::new(role_queries))));
            Box::new(BooleanQuery::new(subqueries))
        };
        self.execute_query(query.as_ref(), SEARCH_PUBLIC_QUERY_LIMIT)
    }

    pub fn query_admin(&self, request: QueryAdminRequest) -> Result<Vec<QueryHit>, String> {
        let raw = request.query.trim();
        if raw.is_empty() {
            return Ok(Vec::new());
        }

        let index = self.reader.searcher().index().clone();
        let content_query = build_plain_text_query(
            &index,
            vec![
                self.fields.title,
                self.fields.alias,
                self.fields.body,
                self.fields.tags,
            ],
            raw,
        )?;
        let query = if let Some(tags) = request.tags.as_ref() {
            let normalized_tags = normalize_tags(tags);
            if normalized_tags.is_empty() {
                content_query
            } else {
                let mut subqueries: Vec<(Occur, Box<dyn Query>)> =
                    Vec::with_capacity(normalized_tags.len() + 1);
                subqueries.push((Occur::Must, content_query));
                for tag in normalized_tags {
                    let term = Term::from_field_text(self.fields.tags, &tag);
                    subqueries.push((
                        Occur::Must,
                        Box::new(TermQuery::new(term, IndexRecordOption::Basic)),
                    ));
                }
                Box::new(BooleanQuery::new(subqueries))
            }
        } else {
            content_query
        };
        let mut hits = self.execute_query_with_scores(query.as_ref(), SEARCH_ADMIN_QUERY_LIMIT)?;
        hits.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.hit.title.cmp(&right.hit.title))
                .then_with(|| left.hit.id.cmp(&right.hit.id))
        });
        Ok(hits.into_iter().map(|entry| entry.hit).collect())
    }

    fn execute_query(&self, query: &dyn Query, limit: usize) -> Result<Vec<QueryHit>, String> {
        let scored_hits = self.execute_query_with_scores(query, limit)?;
        Ok(scored_hits.into_iter().map(|entry| entry.hit).collect())
    }

    fn execute_query_with_scores(
        &self,
        query: &dyn Query,
        limit: usize,
    ) -> Result<Vec<ScoredHit>, String> {
        let searcher = self.reader.searcher();
        let top_docs = searcher
            .search(query, &TopDocs::with_limit(limit).order_by_score())
            .map_err(|err| format!("Search query execution failed: {}", err))?;
        if top_docs.is_empty() {
            return Ok(Vec::new());
        }

        let mut hits = Vec::with_capacity(top_docs.len());
        for (score, address) in top_docs {
            let document = searcher
                .doc::<TantivyOwnedDocument>(address)
                .map_err(|err| format!("Search doc fetch failed: {}", err))?;
            let id = extract_first_string(&document, self.fields.id);
            if id.is_empty() {
                continue;
            }
            let alias = extract_first_string(&document, self.fields.alias);
            let title = extract_first_string(&document, self.fields.title);
            let tags = extract_all_strings(&document, self.fields.tags);
            hits.push(ScoredHit {
                score,
                hit: QueryHit {
                    id,
                    alias,
                    title,
                    tags,
                },
            });
        }
        Ok(hits)
    }

    pub fn reindex_all_markdown(&self, reason: ReindexReason) -> Result<(), String> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.writer_tx
            .send(WriterCommand::ReindexAllMarkdown {
                reason,
                reply: reply_tx,
            })
            .map_err(|err| format!("Search writer unavailable for reindex: {}", err))?;
        reply_rx
            .recv()
            .map_err(|err| format!("Search writer dropped reindex response: {}", err))?
    }

    pub fn internal_force_reindex_endpoint(&self) -> Result<(), String> {
        self.reindex_all_markdown(ReindexReason::Forced)
    }

    pub fn failed_ids_snapshot(&self) -> Vec<String> {
        self.failed_ids.snapshot()
    }

    pub fn failed_ids_file_path(&self) -> PathBuf {
        self.failed_ids.file_path().clone()
    }

    pub fn warm_searcher(&self) {
        let _ = self.reader.searcher();
    }

    pub fn warm_query_paths(&self) {
        let _ = self.query_public(QueryPublicRequest {
            query: String::new(),
            roles: Vec::new(),
        });
        let _ = self.query_admin(QueryAdminRequest {
            query: String::new(),
            tags: None,
        });
    }
}

pub(crate) fn partition_for_id(id: ContentId, partition_count: usize) -> usize {
    (id.0 % partition_count as u64) as usize
}

fn spawn_partition_threads(
    partition_count: usize,
    content_dir: PathBuf,
    state_sys_dir: PathBuf,
    reserved_paths: ReservedPaths,
    failed_ids: Arc<FailedIdStore>,
    writer_tx: mpsc::Sender<WriterCommand>,
) -> Result<Vec<mpsc::Sender<PartitionCommand>>, String> {
    let mut senders = Vec::with_capacity(partition_count);
    for worker_id in 0..partition_count {
        let (partition_tx, partition_rx) = mpsc::channel::<PartitionCommand>();
        let worker_content_dir = content_dir.clone();
        let worker_state_sys_dir = state_sys_dir.clone();
        let worker_reserved_paths = reserved_paths.clone();
        let worker_failed_ids = failed_ids.clone();
        let worker_writer_tx = writer_tx.clone();
        let thread_name = format!("search-ingest-{}", worker_id);
        let builder = std::thread::Builder::new().name(thread_name);
        builder
            .spawn(move || {
                while let Ok(command) = partition_rx.recv() {
                    match command {
                        PartitionCommand::UpsertInMemory(request) => {
                            handle_upsert_in_memory(
                                worker_id,
                                request,
                                &worker_state_sys_dir,
                                &worker_failed_ids,
                                &worker_writer_tx,
                            );
                        }
                        PartitionCommand::UpsertFromDisk(request) => {
                            handle_upsert_from_disk(
                                worker_id,
                                request,
                                &worker_content_dir,
                                &worker_state_sys_dir,
                                &worker_reserved_paths,
                                &worker_failed_ids,
                                &worker_writer_tx,
                            );
                        }
                        PartitionCommand::DeleteMarkdown(id) => {
                            handle_delete(worker_id, id, &worker_failed_ids, &worker_writer_tx);
                        }
                    }
                }
            })
            .map_err(|err| {
                format!(
                    "Failed to start search ingest worker {}: {}",
                    worker_id, err
                )
            })?;
        senders.push(partition_tx);
    }
    Ok(senders)
}

fn handle_upsert_in_memory(
    worker_id: usize,
    request: UpsertMarkdownInMemoryRequest,
    state_sys_dir: &Path,
    failed_ids: &FailedIdStore,
    writer_tx: &mpsc::Sender<WriterCommand>,
) {
    let id_hex = content_id_hex(request.id);
    trace!(
        "Search worker={} upsert-in-memory id={} version={}",
        worker_id, id_hex, request.version.0
    );

    let normalized_tags = normalize_tags(&request.tags);
    let roles = resolve_search_roles(&normalized_tags, state_sys_dir);
    let document = SearchDocument {
        version: request.version,
        id_hex: id_hex.clone(),
        alias: normalize_alias_value(&request.alias),
        title: request.title.trim().to_string(),
        tags: normalized_tags,
        body: normalize_markdown_body(&request.body),
        roles: encode_roles(&roles),
    };
    match request_writer_upsert(worker_id, document, writer_tx) {
        Ok(()) => failed_ids.clear_failed(&id_hex),
        Err(err) => {
            warn!(
                "Search indexing failed for upsert id={} (worker={}, source=in-memory): {}",
                id_hex, worker_id, err
            );
            failed_ids.mark_failed(&id_hex);
        }
    }
}

fn handle_upsert_from_disk(
    worker_id: usize,
    request: UpsertMarkdownFromDiskRequest,
    content_dir: &Path,
    state_sys_dir: &Path,
    reserved_paths: &ReservedPaths,
    failed_ids: &FailedIdStore,
    writer_tx: &mpsc::Sender<WriterCommand>,
) {
    let id_hex = content_id_hex(request.id);
    trace!(
        "Search worker={} upsert-from-disk id={} version={}",
        worker_id, id_hex, request.version.0
    );
    match load_markdown_document_from_disk(
        request.id,
        request.version,
        content_dir,
        state_sys_dir,
        reserved_paths,
    ) {
        Ok(Some(document)) => match request_writer_upsert(worker_id, document, writer_tx) {
            Ok(()) => failed_ids.clear_failed(&id_hex),
            Err(err) => {
                warn!(
                    "Search indexing failed for upsert id={} (worker={}, source=disk): {}",
                    id_hex, worker_id, err
                );
                failed_ids.mark_failed(&id_hex);
            }
        },
        Ok(None) => {
            warn!(
                "Search load skipped non-markdown upsert-from-disk id={} (worker={})",
                id_hex, worker_id
            );
            failed_ids.mark_failed(&id_hex);
        }
        Err(err) => {
            warn!(
                "Search load failed for upsert-from-disk id={} (worker={}): {}",
                id_hex, worker_id, err
            );
            failed_ids.mark_failed(&id_hex);
        }
    }
}

fn handle_delete(
    worker_id: usize,
    id: ContentId,
    failed_ids: &FailedIdStore,
    writer_tx: &mpsc::Sender<WriterCommand>,
) {
    let id_hex = content_id_hex(id);
    trace!("Search worker={} delete id={}", worker_id, id_hex);
    match request_writer_delete(worker_id, id, writer_tx) {
        Ok(()) => failed_ids.clear_failed(&id_hex),
        Err(err) => {
            warn!(
                "Search indexing failed for delete id={} (worker={}): {}",
                id_hex, worker_id, err
            );
            failed_ids.mark_failed(&id_hex);
        }
    }
}

fn request_writer_upsert(
    worker_id: usize,
    document: SearchDocument,
    writer_tx: &mpsc::Sender<WriterCommand>,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = mpsc::channel();
    writer_tx
        .send(WriterCommand::Upsert {
            worker_id,
            document,
            reply: reply_tx,
        })
        .map_err(|err| format!("Search writer unavailable: {}", err))?;
    reply_rx
        .recv()
        .map_err(|err| format!("Search writer dropped upsert response: {}", err))?
}

fn request_writer_delete(
    worker_id: usize,
    id: ContentId,
    writer_tx: &mpsc::Sender<WriterCommand>,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = mpsc::channel();
    writer_tx
        .send(WriterCommand::Delete {
            worker_id,
            id,
            reply: reply_tx,
        })
        .map_err(|err| format!("Search writer unavailable: {}", err))?;
    reply_rx
        .recv()
        .map_err(|err| format!("Search writer dropped delete response: {}", err))?
}

fn spawn_writer_thread(
    mut writer: IndexWriter,
    reader: IndexReader,
    fields: SearchSchemaFields,
    content_dir: PathBuf,
    state_sys_dir: PathBuf,
    failed_ids: Arc<FailedIdStore>,
    reserved_paths: ReservedPaths,
) -> Result<mpsc::Sender<WriterCommand>, String> {
    let (writer_tx, writer_rx) = mpsc::channel::<WriterCommand>();
    let builder = std::thread::Builder::new().name("search-writer".to_string());
    builder
        .spawn(move || {
            while let Ok(command) = writer_rx.recv() {
                match command {
                    WriterCommand::Upsert {
                        worker_id,
                        document,
                        reply,
                    } => {
                        let result = writer_apply_upsert(&mut writer, &reader, &fields, &document);
                        if result.is_ok() {
                            debug!(
                                "Search indexed document id={} (worker={}, version={})",
                                document.id_hex, worker_id, document.version.0
                            );
                        }
                        let _ = reply.send(result);
                    }
                    WriterCommand::Delete {
                        worker_id,
                        id,
                        reply,
                    } => {
                        let id_hex = content_id_hex(id);
                        let result = writer_apply_delete(&mut writer, &reader, &fields, id);
                        if result.is_ok() {
                            debug!(
                                "Search removed document id={} (worker={})",
                                id_hex, worker_id
                            );
                        }
                        let _ = reply.send(result);
                    }
                    WriterCommand::ReindexAllMarkdown { reason, reply } => {
                        let resources = ReindexResources {
                            content_dir: &content_dir,
                            state_sys_dir: &state_sys_dir,
                            failed_ids: &failed_ids,
                            reserved_paths: &reserved_paths,
                        };
                        let result = writer_reindex_all_markdown(
                            &mut writer,
                            &reader,
                            &fields,
                            resources,
                            reason,
                        );
                        let _ = reply.send(result);
                    }
                }
            }
        })
        .map_err(|err| format!("Failed to start search writer thread: {}", err))?;
    Ok(writer_tx)
}

fn writer_apply_upsert(
    writer: &mut IndexWriter,
    reader: &IndexReader,
    fields: &SearchSchemaFields,
    document: &SearchDocument,
) -> Result<(), String> {
    let term = Term::from_field_text(fields.id, &document.id_hex);
    writer.delete_term(term);
    let mut tantivy_document = doc!(
        fields.id => document.id_hex.clone(),
        fields.alias => document.alias.clone(),
        fields.title => document.title.clone(),
        fields.body => document.body.clone(),
    );
    for tag in &document.tags {
        tantivy_document.add_text(fields.tags, tag);
    }
    for role in &document.roles {
        tantivy_document.add_text(fields.roles, role);
    }
    writer
        .add_document(tantivy_document)
        .map_err(|err| format!("Add document failed: {}", err))?;
    writer
        .commit()
        .map_err(|err| format!("Commit failed: {}", err))?;
    reader
        .reload()
        .map_err(|err| format!("Reader reload failed: {}", err))?;
    Ok(())
}

fn writer_apply_delete(
    writer: &mut IndexWriter,
    reader: &IndexReader,
    fields: &SearchSchemaFields,
    id: ContentId,
) -> Result<(), String> {
    let id_hex = content_id_hex(id);
    writer.delete_term(Term::from_field_text(fields.id, &id_hex));
    writer
        .commit()
        .map_err(|err| format!("Commit failed: {}", err))?;
    reader
        .reload()
        .map_err(|err| format!("Reader reload failed: {}", err))?;
    Ok(())
}

fn writer_reindex_all_markdown(
    writer: &mut IndexWriter,
    reader: &IndexReader,
    fields: &SearchSchemaFields,
    resources: ReindexResources<'_>,
    reason: ReindexReason,
) -> Result<(), String> {
    info!("Search full reindex start (reason={})", reason);
    resources.failed_ids.clear_all_and_delete_file();
    writer
        .delete_all_documents()
        .map_err(|err| format!("Reindex delete_all_documents failed: {}", err))?;

    let documents = enumerate_latest_markdown_documents(
        resources.content_dir,
        resources.state_sys_dir,
        resources.reserved_paths,
        resources.failed_ids,
    )?;
    for document in documents {
        let mut tantivy_document: TantivyOwnedDocument = doc!(
            fields.id => document.id_hex.clone(),
            fields.alias => document.alias.clone(),
            fields.title => document.title.clone(),
            fields.body => document.body.clone(),
        );
        for tag in &document.tags {
            tantivy_document.add_text(fields.tags, tag);
        }
        for role in &document.roles {
            tantivy_document.add_text(fields.roles, role);
        }
        if let Err(err) = writer.add_document(tantivy_document) {
            warn!(
                "Search reindex add failed id={} version={}: {}",
                document.id_hex, document.version.0, err
            );
            resources.failed_ids.mark_failed(&document.id_hex);
        }
    }

    writer
        .commit()
        .map_err(|err| format!("Reindex commit failed: {}", err))?;
    reader
        .reload()
        .map_err(|err| format!("Reindex reader reload failed: {}", err))?;
    info!("Search full reindex completed (reason={})", reason);
    Ok(())
}

fn enumerate_latest_markdown_documents(
    content_dir: &Path,
    state_sys_dir: &Path,
    reserved_paths: &ReservedPaths,
    failed_ids: &FailedIdStore,
) -> Result<Vec<SearchDocument>, String> {
    let mut latest: HashMap<ContentId, (ContentVersion, PathBuf)> = HashMap::new();
    let mut stack = vec![content_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|err| {
            format!(
                "Failed to read content directory {}: {}",
                dir.display(),
                err
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("Failed to read content entry: {}", err))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("Failed to inspect content entry: {}", err))?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if !name.ends_with(".ron") {
                continue;
            }
            let Some((id, version)) = parse_sidecar_filename(name) else {
                continue;
            };
            match latest.get(&id) {
                Some((existing, _)) if existing.0 >= version.0 => {}
                _ => {
                    latest.insert(id, (version, path));
                }
            }
        }
    }

    let mut documents = Vec::new();
    for (id, (version, _sidecar_path)) in latest {
        match load_markdown_document_from_disk(
            id,
            version,
            content_dir,
            state_sys_dir,
            reserved_paths,
        ) {
            Ok(Some(document)) => documents.push(document),
            Ok(None) => {}
            Err(err) => {
                warn!(
                    "Search reindex skipped id={} version={} due to load failure: {}",
                    content_id_hex(id),
                    version.0,
                    err
                );
                failed_ids.mark_failed(&content_id_hex(id));
            }
        }
    }
    Ok(documents)
}

fn load_markdown_document_from_disk(
    id: ContentId,
    version: ContentVersion,
    content_dir: &Path,
    state_sys_dir: &Path,
    reserved_paths: &ReservedPaths,
) -> Result<Option<SearchDocument>, String> {
    let sidecar_path = sidecar_path(content_dir, id, version);
    let sidecar = read_sidecar(&sidecar_path)
        .map_err(|err| format!("Failed to read sidecar {}: {}", sidecar_path.display(), err))?;
    if sidecar.mime.trim() != "text/markdown" {
        return Ok(None);
    }
    build_document_from_sidecar(
        id,
        version,
        sidecar,
        content_dir,
        state_sys_dir,
        reserved_paths,
    )
    .map(Some)
}

fn build_document_from_sidecar(
    id: ContentId,
    version: ContentVersion,
    sidecar: ContentSidecar,
    content_dir: &Path,
    state_sys_dir: &Path,
    reserved_paths: &ReservedPaths,
) -> Result<SearchDocument, String> {
    let alias = normalize_optional_alias(&sidecar.alias)
        .map_err(|err| {
            format!(
                "Invalid alias for id={} version={}: {}",
                content_id_hex(id),
                version.0,
                err
            )
        })?
        .unwrap_or_default();
    if !alias.is_empty() && reserved_paths.alias_is_reserved(&alias) {
        return Err(format!(
            "Alias '{}' is reserved for id={} version={}",
            alias,
            content_id_hex(id),
            version.0
        ));
    }
    let title = sidecar.title.unwrap_or_default().trim().to_string();
    if title.is_empty() {
        return Err(format!(
            "Missing markdown title for id={} version={}",
            content_id_hex(id),
            version.0
        ));
    }
    let blob = blob_path(content_dir, id, version);
    let body = std::fs::read_to_string(&blob)
        .map_err(|err| format!("Failed to read markdown blob {}: {}", blob.display(), err))?;
    let tags = normalize_tags(&sidecar.tags);
    let roles = resolve_search_roles(&tags, state_sys_dir);
    Ok(SearchDocument {
        version,
        id_hex: content_id_hex(id),
        alias,
        title,
        tags,
        body: normalize_markdown_body(&body),
        roles: encode_roles(&roles),
    })
}

fn normalize_alias_value(alias: &str) -> String {
    normalize_optional_alias(alias)
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn normalize_markdown_body(raw: &str) -> String {
    let markdown = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut extracted = String::with_capacity(markdown.len());
    let push_separator = |output: &mut String| {
        if output.chars().last().is_some_and(|ch| !ch.is_whitespace()) {
            output.push(' ');
        }
    };

    for event in Parser::new_ext(&markdown, markdown_extraction_options()) {
        match event {
            Event::Text(text) | Event::Code(text) | Event::FootnoteReference(text) => {
                extracted.push_str(text.as_ref());
            }
            Event::Html(html) | Event::InlineHtml(html) => {
                extracted.push_str(&strip_html_to_text(html.as_ref()));
            }
            Event::SoftBreak | Event::HardBreak => extracted.push('\n'),
            Event::End(tag_end) => {
                if matches!(
                    tag_end,
                    TagEnd::Paragraph
                        | TagEnd::Heading(_)
                        | TagEnd::BlockQuote(_)
                        | TagEnd::CodeBlock
                        | TagEnd::HtmlBlock
                        | TagEnd::List(_)
                        | TagEnd::Item
                        | TagEnd::FootnoteDefinition
                        | TagEnd::DefinitionList
                        | TagEnd::DefinitionListTitle
                        | TagEnd::DefinitionListDefinition
                        | TagEnd::Table
                        | TagEnd::TableHead
                        | TagEnd::TableRow
                        | TagEnd::TableCell
                        | TagEnd::MetadataBlock(_)
                ) {
                    push_separator(&mut extracted);
                }
            }
            _ => {}
        }
    }

    normalize_index_whitespace(&extracted)
}

fn markdown_extraction_options() -> Options {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_TASKLISTS);
    options
}

fn strip_html_to_text(raw_html: &str) -> String {
    let sanitized = ammonia::clean(raw_html);
    let mut output = String::with_capacity(sanitized.len());
    let mut in_tag = false;

    for ch in sanitized.chars() {
        match ch {
            '<' => {
                in_tag = true;
                if output.chars().last().is_some_and(|c| !c.is_whitespace()) {
                    output.push(' ');
                }
            }
            '>' => in_tag = false,
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }

    output
}

fn normalize_index_whitespace(raw: &str) -> String {
    let mut normalized = String::with_capacity(raw.len());
    let mut previous_was_whitespace = true;
    for ch in raw.chars() {
        if ch.is_whitespace() {
            if !previous_was_whitespace {
                normalized.push(' ');
            }
            previous_was_whitespace = true;
        } else {
            normalized.push(ch);
            previous_was_whitespace = false;
        }
    }
    normalized.trim().to_string()
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut unique = HashSet::new();
    let mut normalized = Vec::new();
    for tag in tags {
        let value = tag.trim().to_ascii_lowercase();
        if value.is_empty() || !unique.insert(value.clone()) {
            continue;
        }
        normalized.push(value);
    }
    normalized.sort();
    normalized
}

fn resolve_search_roles(tags: &[String], state_sys_dir: &Path) -> ResolvedSearchRoles {
    let tag_map = load_tag_map(state_sys_dir);
    match resolve_roles_for_tags(tags, &tag_map) {
        ResolvedRoleSet::Public => ResolvedSearchRoles::Public,
        ResolvedRoleSet::Deny => ResolvedSearchRoles::Deny,
        ResolvedRoleSet::Restricted(roles) => ResolvedSearchRoles::Restricted(roles),
    }
}

fn load_tag_map(state_sys_dir: &Path) -> BTreeMap<String, TagRoleRecord> {
    let file_path = state_sys_dir.join("tags.yaml");
    let content = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return BTreeMap::new(),
        Err(err) => {
            warn!(
                "Failed to load tag map for search role derivation from {}: {}",
                file_path.display(),
                err
            );
            return BTreeMap::new();
        }
    };
    if content.trim().is_empty() {
        return BTreeMap::new();
    }
    match serde_yaml::from_str::<BTreeMap<String, TagRoleRecord>>(&content) {
        Ok(map) => map,
        Err(err) => {
            warn!(
                "Failed to parse search tag map from {}: {}",
                file_path.display(),
                err
            );
            BTreeMap::new()
        }
    }
}

fn encode_roles(resolved: &ResolvedSearchRoles) -> Vec<String> {
    match resolved {
        ResolvedSearchRoles::Public => vec![SEARCH_ROLE_PUBLIC.to_string()],
        ResolvedSearchRoles::Deny => vec![SEARCH_ROLE_DENY.to_string()],
        ResolvedSearchRoles::Restricted(roles) => roles.clone(),
    }
}

fn build_plain_text_query(
    index: &Index,
    default_fields: Vec<Field>,
    raw_query: &str,
) -> Result<Box<dyn Query>, String> {
    let normalized = normalize_plain_text_query(raw_query);
    let parser = QueryParser::for_index(index, default_fields);
    parser
        .parse_query(&normalized)
        .map_err(|err| format!("Search query parse failed: {}", err))
}

fn normalize_plain_text_query(raw_query: &str) -> String {
    let lower = raw_query.trim().to_ascii_lowercase();
    escape_query_special_chars(&lower)
}

fn escape_query_special_chars(raw_query: &str) -> String {
    let mut escaped = String::with_capacity(raw_query.len());
    for ch in raw_query.chars() {
        if matches!(
            ch,
            '\\' | '+'
                | '-'
                | '='
                | '&'
                | '|'
                | '!'
                | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | '^'
                | '"'
                | '~'
                | '*'
                | '?'
                | ':'
                | '/'
                | '<'
                | '>'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn extract_first_string(document: &TantivyOwnedDocument, field: Field) -> String {
    document
        .get_first(field)
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn extract_all_strings(document: &TantivyOwnedDocument, field: Field) -> Vec<String> {
    let mut values: Vec<String> = document
        .get_all(field)
        .filter_map(|value| value.as_str().map(|raw| raw.trim().to_string()))
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

fn build_schema() -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_text_field("id", STRING | STORED);
    schema_builder.add_text_field("alias", TEXT | STORED);
    schema_builder.add_text_field("title", TEXT | STORED);
    schema_builder.add_text_field("tags", STRING | STORED);
    schema_builder.add_text_field("body", TEXT);
    schema_builder.add_text_field("roles", STRING);
    schema_builder.build()
}

fn schema_fields(schema: &Schema) -> Result<SearchSchemaFields, String> {
    let field = |name: &str| {
        schema
            .get_field(name)
            .map_err(|_| format!("Search schema missing field '{}'", name))
    };
    Ok(SearchSchemaFields {
        id: field("id")?,
        alias: field("alias")?,
        title: field("title")?,
        tags: field("tags")?,
        body: field("body")?,
        roles: field("roles")?,
    })
}

fn index_metadata_exists(index_dir: &Path) -> bool {
    index_dir.join("meta.json").exists()
}

fn parse_sidecar_filename(file_name: &str) -> Option<(ContentId, ContentVersion)> {
    let trimmed = file_name.strip_suffix(".ron")?;
    let mut parts = trimmed.split('.');
    let id_hex = parts.next()?;
    let version_raw = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if id_hex.len() != 16 || !id_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let id = u64::from_str_radix(id_hex, 16).ok()?;
    let version = version_raw.parse::<u32>().ok()?;
    Some((ContentId(id), ContentVersion(version)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestFixtureRoot;
    use nop_content_store::flat_storage::{ContentSidecar, write_sidecar_atomic};
    use std::sync::Arc;

    fn write_markdown(
        runtime_paths: &RuntimePaths,
        id: ContentId,
        version: ContentVersion,
        sidecar: ContentSidecar,
        body: &str,
    ) {
        let blob = blob_path(&runtime_paths.content_dir, id, version);
        if let Some(parent) = blob.parent() {
            std::fs::create_dir_all(parent).expect("create shard");
        }
        std::fs::write(&blob, body).expect("write body");
        let sidecar_path = sidecar_path(&runtime_paths.content_dir, id, version);
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
    }

    fn query_public_with_retry(
        service: &Arc<SearchService>,
        query: &str,
        expected_len: usize,
    ) -> Vec<QueryHit> {
        for _ in 0..40 {
            let hits = service
                .query_public(QueryPublicRequest {
                    query: query.to_string(),
                    roles: Vec::new(),
                })
                .expect("query");
            if hits.len() == expected_len {
                return hits;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        service
            .query_public(QueryPublicRequest {
                query: query.to_string(),
                roles: Vec::new(),
            })
            .expect("query final")
    }

    #[test]
    fn partition_mapping_is_stable() {
        assert_eq!(partition_for_id(ContentId(0), 4), 0);
        assert_eq!(partition_for_id(ContentId(1), 4), 1);
        assert_eq!(partition_for_id(ContentId(2), 4), 2);
        assert_eq!(partition_for_id(ContentId(3), 4), 3);
        assert_eq!(partition_for_id(ContentId(4), 4), 0);
    }

    #[test]
    fn role_resolution_honors_union_and_intersect_precedence() {
        let fixture = TestFixtureRoot::new_unique("search-role-resolution").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");
        let tags_yaml = r#"tag-a:
  name: tag-a
  roles:
    - alpha
  access_rule: union
tag-b:
  name: tag-b
  roles:
    - beta
tag-c:
  name: tag-c
  roles:
    - beta
  access_rule: intersect
"#;
        std::fs::write(runtime_paths.state_sys_dir.join("tags.yaml"), tags_yaml).expect("tags");

        let union = resolve_search_roles(
            &["tag-a".to_string(), "tag-b".to_string()],
            &runtime_paths.state_sys_dir,
        );
        assert_eq!(
            encode_roles(&union),
            vec!["alpha".to_string(), "beta".to_string()]
        );

        let intersect = resolve_search_roles(
            &["tag-a".to_string(), "tag-c".to_string()],
            &runtime_paths.state_sys_dir,
        );
        assert_eq!(encode_roles(&intersect), vec![SEARCH_ROLE_DENY.to_string()]);
    }

    #[test]
    fn role_resolution_normalizes_role_casing() {
        let fixture = TestFixtureRoot::new_unique("search-role-casing").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");
        let tags_yaml = r#"casey:
  name: casey
  roles:
    - TeamLead
"#;
        std::fs::write(runtime_paths.state_sys_dir.join("tags.yaml"), tags_yaml).expect("tags");

        let resolved = resolve_search_roles(&["casey".to_string()], &runtime_paths.state_sys_dir);
        assert_eq!(encode_roles(&resolved), vec!["teamlead".to_string()]);
    }

    #[test]
    fn startup_missing_index_runs_reindex_and_builds_index() {
        let fixture = TestFixtureRoot::new_unique("search-startup-reindex").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");
        write_markdown(
            &runtime_paths,
            ContentId(1),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/intro".to_string(),
                title: Some("Intro".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["docs".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "# Intro\nhello",
        );

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");
        assert_eq!(
            startup.startup_reindex_reason,
            Some(ReindexReason::MissingIndex)
        );
        assert!(
            runtime_paths
                .state_search_index_dir
                .join("meta.json")
                .exists()
        );
        assert!(startup.service.failed_ids_snapshot().is_empty());
    }

    #[test]
    fn forced_reindex_clears_failed_ids_file() {
        let fixture = TestFixtureRoot::new_unique("search-forced-reindex").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");
        std::fs::write(
            &runtime_paths.state_search_failed_ids_file,
            "- \"0000000000000001\"\n",
        )
        .expect("seed failed ids");
        write_markdown(
            &runtime_paths,
            ContentId(1),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/intro".to_string(),
                title: Some("Intro".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec![],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "# Intro",
        );

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");
        startup
            .service
            .reindex_all_markdown(ReindexReason::Forced)
            .expect("forced reindex");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!runtime_paths.state_search_failed_ids_file.exists());
    }

    #[test]
    fn failed_disk_upsert_marks_failed_id_without_retry() {
        let fixture = TestFixtureRoot::new_unique("search-failed-upsert").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");
        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        let id = ContentId(0x000000000000000a);
        startup
            .service
            .enqueue_upsert_markdown_from_disk(UpsertMarkdownFromDiskRequest {
                id,
                version: ContentVersion(1),
            })
            .expect("enqueue");

        std::thread::sleep(std::time::Duration::from_millis(100));
        let first = startup.service.failed_ids_snapshot();
        assert_eq!(first, vec![content_id_hex(id)]);

        startup
            .service
            .enqueue_upsert_markdown_from_disk(UpsertMarkdownFromDiskRequest {
                id,
                version: ContentVersion(1),
            })
            .expect("enqueue second");
        std::thread::sleep(std::time::Duration::from_millis(100));
        let second = startup.service.failed_ids_snapshot();
        assert_eq!(second, vec![content_id_hex(id)]);
    }

    #[test]
    fn reindex_records_failed_ids_for_load_errors() {
        let fixture = TestFixtureRoot::new_unique("search-reindex-load-failure").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        let id = ContentId(0x55);
        let version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, id, version);
        if let Some(parent) = blob.parent() {
            std::fs::create_dir_all(parent).expect("create shard");
        }
        std::fs::write(&blob, "body").expect("write body");
        let sidecar_path = sidecar_path(&runtime_paths.content_dir, id, version);
        let sidecar_yaml = "alias: docs/broken\nmime: text/markdown\ntags: []\n";
        std::fs::write(&sidecar_path, sidecar_yaml).expect("write sidecar");

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        assert!(
            startup
                .service
                .failed_ids_snapshot()
                .contains(&content_id_hex(id))
        );
    }

    #[test]
    fn query_public_excludes_tag_matching_without_access_filtering() {
        let fixture = TestFixtureRoot::new_unique("search-query-public-rbac").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        std::fs::write(
            runtime_paths.state_sys_dir.join("tags.yaml"),
            r#"secret:
  name: secret
  roles:
    - editor
  access_rule: intersect
"#,
        )
        .expect("write tags");

        write_markdown(
            &runtime_paths,
            ContentId(1),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/public".to_string(),
                title: Some("Public Page".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec![],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "shared content",
        );
        write_markdown(
            &runtime_paths,
            ContentId(2),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/restricted".to_string(),
                title: Some("Restricted Page".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["secret".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "shared content",
        );

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        let anonymous_hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "shared".to_string(),
                roles: Vec::new(),
            })
            .expect("query anonymous");
        assert_eq!(anonymous_hits.len(), 1);

        let tag_only = startup
            .service
            .query_public(QueryPublicRequest {
                query: "secret".to_string(),
                roles: Vec::new(),
            })
            .expect("query tag-only");
        assert!(tag_only.is_empty());
    }

    #[test]
    fn query_admin_includes_tags_and_bypasses_rbac() {
        let fixture = TestFixtureRoot::new_unique("search-query-admin-access").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        std::fs::write(
            runtime_paths.state_sys_dir.join("tags.yaml"),
            r#"secret:
  name: secret
  roles:
    - editor
  access_rule: intersect
"#,
        )
        .expect("write tags");

        write_markdown(
            &runtime_paths,
            ContentId(10),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/public".to_string(),
                title: Some("Alpha Public".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec![],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "shared body",
        );
        write_markdown(
            &runtime_paths,
            ContentId(11),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/restricted".to_string(),
                title: Some("Beta Restricted".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["secret".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "shared body",
        );

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        let tag_hits = startup
            .service
            .query_admin(QueryAdminRequest {
                query: "secret".to_string(),
                tags: None,
            })
            .expect("admin tag query");
        assert_eq!(tag_hits.len(), 1);
        assert_eq!(tag_hits[0].id, content_id_hex(ContentId(11)));
        assert_eq!(tag_hits[0].tags, vec!["secret".to_string()]);

        let shared_hits = startup
            .service
            .query_admin(QueryAdminRequest {
                query: "shared".to_string(),
                tags: None,
            })
            .expect("admin shared query");
        assert_eq!(shared_hits.len(), 2);
        let mut titles: Vec<&str> = shared_hits.iter().map(|hit| hit.title.as_str()).collect();
        titles.sort();
        assert_eq!(titles, vec!["Alpha Public", "Beta Restricted"]);
    }

    #[test]
    fn query_admin_applies_tag_filters() {
        let fixture = TestFixtureRoot::new_unique("search-query-admin-tags").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        std::fs::write(
            runtime_paths.state_sys_dir.join("tags.yaml"),
            r#"secret:
  name: secret
  roles:
    - editor
  access_rule: intersect
"#,
        )
        .expect("write tags");

        write_markdown(
            &runtime_paths,
            ContentId(20),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/public".to_string(),
                title: Some("Gamma Public".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec![],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "shared body",
        );
        write_markdown(
            &runtime_paths,
            ContentId(21),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/restricted".to_string(),
                title: Some("Delta Restricted".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["secret".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "shared body",
        );

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        let tag_hits = startup
            .service
            .query_admin(QueryAdminRequest {
                query: "shared".to_string(),
                tags: Some(vec!["secret".to_string()]),
            })
            .expect("admin tag filter query");
        assert_eq!(tag_hits.len(), 1);
        assert_eq!(tag_hits[0].title, "Delta Restricted");
    }

    #[test]
    fn query_public_limit_is_bounded() {
        let fixture = TestFixtureRoot::new_unique("search-query-limit-order").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        for idx in 0u64..20u64 {
            write_markdown(
                &runtime_paths,
                ContentId(100 + idx),
                ContentVersion(1),
                ContentSidecar {
                    alias: format!("docs/page-{:02}", idx),
                    title: Some(format!("Doc {:02}", idx)),
                    mime: "text/markdown".to_string(),
                    tags: vec![],
                    nav_title: None,
                    nav_parent_id: None,
                    nav_order: None,
                    original_filename: None,
                    theme: None,
                },
                "common body",
            );
        }

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        let hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "common".to_string(),
                roles: Vec::new(),
            })
            .expect("query");
        assert_eq!(hits.len(), SEARCH_PUBLIC_QUERY_LIMIT);
    }

    #[test]
    fn query_public_prefers_relevance_over_insertion_order() {
        let fixture = TestFixtureRoot::new_unique("search-query-relevance").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        for idx in 0u64..16u64 {
            write_markdown(
                &runtime_paths,
                ContentId(300 + idx),
                ContentVersion(1),
                ContentSidecar {
                    alias: format!("docs/rel-{:02}", idx),
                    title: Some(format!("Rel {:02}", idx)),
                    mime: "text/markdown".to_string(),
                    tags: vec![],
                    nav_title: None,
                    nav_parent_id: None,
                    nav_order: None,
                    original_filename: None,
                    theme: None,
                },
                "common",
            );
        }
        write_markdown(
            &runtime_paths,
            ContentId(999),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/rel-most".to_string(),
                title: Some("Most Relevant".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec![],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "common common common",
        );

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        let hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "common".to_string(),
                roles: Vec::new(),
            })
            .expect("query");
        assert_eq!(hits.len(), SEARCH_PUBLIC_QUERY_LIMIT);
        assert!(hits.iter().any(|hit| hit.title == "Most Relevant"));
    }

    #[test]
    fn markdown_body_normalization_strips_markup_and_keeps_visible_text() {
        let markdown = r#"
# Heading
Visible [Link Label](https://zzlinktoken.example/path)
![Accessible Alt Token](/images/zzimagetoken.png)
<p>Inline <a href="https://zzhtmltoken.example">HTML Label</a></p>
"#;

        let normalized = normalize_markdown_body(markdown);
        assert!(normalized.contains("Heading"));
        assert!(normalized.contains("Link Label"));
        assert!(normalized.contains("Accessible Alt Token"));
        assert!(normalized.contains("HTML Label"));

        assert!(!normalized.contains("https://zzlinktoken.example"));
        assert!(!normalized.contains("zzlinktoken.example"));
        assert!(!normalized.contains("zzimagetoken.png"));
        assert!(!normalized.contains("zzhtmltoken.example"));
        assert!(!normalized.contains("<a"));
        assert!(!normalized.contains("# Heading"));
    }

    #[test]
    fn markdown_body_normalization_keeps_table_cells_separated() {
        let markdown = r#"
| Nimbus | Orion | Orion Quartz |
|-----------|----------|---------------|
"#;

        let normalized = normalize_markdown_body(markdown);
        assert!(normalized.contains("Nimbus Orion"));
        assert!(normalized.contains("Orion Quartz"));
        assert!(!normalized.contains("|"));
    }

    #[test]
    fn markdown_body_normalization_includes_code_blocks() {
        let markdown = r#"
```
Nimbus
Orion Quartz
```
"#;

        let normalized = normalize_markdown_body(markdown);
        assert!(normalized.contains("Nimbus"));
        assert!(normalized.contains("Orion Quartz"));
        assert!(!normalized.contains("```"));
    }

    #[test]
    fn markdown_body_normalization_strips_html_tags_and_attributes() {
        let markdown = r#"<p data-kind="note">Nimbus <strong>Orion</strong></p>"#;

        let normalized = normalize_markdown_body(markdown);
        assert!(normalized.contains("Nimbus"));
        assert!(normalized.contains("Orion"));
        assert!(!normalized.contains("<strong"));
        assert!(!normalized.contains("data-kind"));
    }

    #[test]
    fn markdown_body_normalization_keeps_block_boundaries_separated() {
        let markdown = r#"
# Nimbus
Paragraph text.
- Orion
- Orion Quartz

> Coverage
"#;

        let normalized = normalize_markdown_body(markdown);
        assert_eq!(
            normalized,
            "Nimbus Paragraph text. Orion Orion Quartz Coverage"
        );
    }

    #[test]
    fn markdown_body_normalization_retains_task_list_text() {
        let markdown = r#"
- [ ] Nimbus
- [x] Orion Quartz
"#;

        let normalized = normalize_markdown_body(markdown);
        assert_eq!(normalized, "Nimbus Orion Quartz");
    }

    #[test]
    fn markdown_body_normalization_retains_inline_markup_text() {
        let markdown = "Nimbus **Orion** _Quartz_ ~~Plan~~ `Code`";

        let normalized = normalize_markdown_body(markdown);
        assert_eq!(normalized, "Nimbus Orion Quartz Plan Code");
    }

    #[test]
    fn markdown_body_normalization_strips_html_comments_and_unsafe_tags() {
        let markdown = r#"
<!-- nimbus comment -->
<script>alert("nimbus")</script>
<style>body { color: red; }</style>
<p data-kind="note">Nimbus <strong>Orion</strong></p>
"#;

        let normalized = normalize_markdown_body(markdown);
        assert!(normalized.contains("Nimbus"));
        assert!(normalized.contains("Orion"));
        assert!(!normalized.contains("comment"));
        assert!(!normalized.contains("alert"));
        assert!(!normalized.contains("color"));
        assert!(!normalized.contains("data-kind"));
        assert!(!normalized.contains("note"));
    }

    #[test]
    fn in_memory_upsert_indexes_visible_markdown_text_not_link_or_image_urls() {
        let fixture =
            TestFixtureRoot::new_unique("search-in-memory-visible-text-only").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        startup
            .service
            .enqueue_upsert_markdown_in_memory(UpsertMarkdownInMemoryRequest {
                id: ContentId(0x33),
                version: ContentVersion(1),
                alias: "docs/visible-only".to_string(),
                title: "Visible Only".to_string(),
                tags: vec![],
                body: "Visible [Link Label](https://zzlinktoken.example/path) and ![Accessible Alt Token](/images/zzimagetoken.png).".to_string(),
            })
            .expect("enqueue in-memory upsert");

        let visible_hits = query_public_with_retry(&startup.service, "accessible", 1);
        assert_eq!(visible_hits.len(), 1);
        assert_eq!(visible_hits[0].id, content_id_hex(ContentId(0x33)));

        let link_url_hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "zzlinktoken".to_string(),
                roles: Vec::new(),
            })
            .expect("query link url token");
        assert!(link_url_hits.is_empty());

        let image_url_hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "zzimagetoken".to_string(),
                roles: Vec::new(),
            })
            .expect("query image url token");
        assert!(image_url_hits.is_empty());
    }

    #[test]
    fn reindex_from_disk_indexes_visible_markdown_text_not_link_or_image_urls() {
        let fixture =
            TestFixtureRoot::new_unique("search-disk-visible-text-only").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        write_markdown(
            &runtime_paths,
            ContentId(0x44),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/from-disk".to_string(),
                title: Some("From Disk".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec![],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "Visible [Disk Link Label](https://zzdisklinktoken.example/path) and ![Disk Alt Token](/assets/zzdiskimagetoken.png).",
        );

        let startup = initialize(
            &runtime_paths,
            &SearchConfig {
                max_memory_mb: 128,
                worker_count: 1,
            },
            ReservedPaths::default(),
            false,
        )
        .expect("search startup");

        let visible_hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "disk alt".to_string(),
                roles: Vec::new(),
            })
            .expect("query visible text");
        assert_eq!(visible_hits.len(), 1);
        assert_eq!(visible_hits[0].id, content_id_hex(ContentId(0x44)));

        let link_url_hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "zzdisklinktoken".to_string(),
                roles: Vec::new(),
            })
            .expect("query link url token");
        assert!(link_url_hits.is_empty());

        let image_url_hits = startup
            .service
            .query_public(QueryPublicRequest {
                query: "zzdiskimagetoken".to_string(),
                roles: Vec::new(),
            })
            .expect("query image url token");
        assert!(image_url_hits.is_empty());
    }

    #[test]
    fn plain_text_query_normalization_escapes_operator_syntax() {
        assert_eq!(normalize_plain_text_query("A OR B"), "a or b");
        assert_eq!(normalize_plain_text_query("one+two"), "one\\+two");
        assert_eq!(normalize_plain_text_query("foo:bar"), "foo\\:bar");
        assert_eq!(normalize_plain_text_query("a/b"), "a\\/b");
    }
}
