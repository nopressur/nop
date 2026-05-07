// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use async_trait::async_trait;
use nop_config::ValidatedConfig;
use nop_content_store::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, content_id_hex, generate_content_id,
    normalize_optional_alias, parse_content_id_hex, read_sidecar, sidecar_path, validate_sidecar,
    write_sidecar_atomic,
};
use nop_content_store::reserved_paths::ReservedPaths;
pub use nop_management_contract::content::{
    BinaryPrevalidateRequest, BinaryPrevalidateResponse, BinaryUploadCommitRequest,
    BinaryUploadInitRequest, CONTENT_ACTION_BINARY_PREVALIDATE,
    CONTENT_ACTION_BINARY_PREVALIDATE_ERR, CONTENT_ACTION_BINARY_PREVALIDATE_OK,
    CONTENT_ACTION_BINARY_UPLOAD_COMMIT, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
    CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK, CONTENT_ACTION_BINARY_UPLOAD_INIT,
    CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
    CONTENT_ACTION_DELETE, CONTENT_ACTION_DELETE_ERR, CONTENT_ACTION_DELETE_OK,
    CONTENT_ACTION_LIST, CONTENT_ACTION_LIST_ERR, CONTENT_ACTION_LIST_OK, CONTENT_ACTION_NAV_INDEX,
    CONTENT_ACTION_NAV_INDEX_ERR, CONTENT_ACTION_NAV_INDEX_OK, CONTENT_ACTION_READ,
    CONTENT_ACTION_READ_ERR, CONTENT_ACTION_READ_OK, CONTENT_ACTION_UPDATE,
    CONTENT_ACTION_UPDATE_ERR, CONTENT_ACTION_UPDATE_OK, CONTENT_ACTION_UPDATE_STREAM_COMMIT,
    CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR, CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
    CONTENT_ACTION_UPDATE_STREAM_INIT, CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
    CONTENT_ACTION_UPDATE_STREAM_INIT_OK, CONTENT_ACTION_UPLOAD, CONTENT_ACTION_UPLOAD_ERR,
    CONTENT_ACTION_UPLOAD_OK, CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
    CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR, CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
    CONTENT_ACTION_UPLOAD_STREAM_INIT, CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
    CONTENT_ACTION_UPLOAD_STREAM_INIT_OK, CONTENT_DOMAIN_ID, ContentCommand, ContentDeleteRequest,
    ContentListRequest, ContentListResponse, ContentNavIndexEntry, ContentNavIndexRequest,
    ContentNavIndexResponse, ContentReadRequest, ContentReadResponse, ContentSortDirection,
    ContentSortField, ContentSummary, ContentUpdateRequest, ContentUpdateStreamCommitRequest,
    ContentUpdateStreamInitRequest, ContentUploadRequest, ContentUploadResponse,
    ContentUploadStreamCommitRequest, ContentUploadStreamInitRequest, UploadStreamInitResponse,
};
use nop_management_contract::{
    CodecError, DomainActionKey, FieldLimit, FieldLimits, FieldValues, ManagementCommand,
    ManagementErrorKind, ManagementRequest, ManagementResponse, MessageResponse, RequestCodec,
    ResponseCodec, ResponsePayload, codec, validate_field_limits,
};
use nop_management_errors::DomainResult;
use nop_management_workflows::capabilities::{
    ConfigAccess, PageCacheAccess, ReleaseTrackerAccess, SearchServiceAccess,
};
use nop_management_workflows::content as content_workflows;
use nop_rt_page_cache::{CachedObject, PageMetaCache};
use nop_security_paths::validate_new_file_path;
use std::cmp::{Ordering, min};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ALIAS_CHARS: usize = 512;
const MAX_TITLE_CHARS: usize = 256;
const MAX_TAG_COUNT: usize = 256;
const MAX_TAG_CHARS: usize = 128;
const MAX_THEME_CHARS: usize = 128;
const MAX_MIME_CHARS: usize = 128;
const MAX_ORIGINAL_FILENAME_CHARS: usize = 512;
const MAX_QUERY_CHARS: usize = 256;
const MAX_PAGE_SIZE: u32 = 200;
const MAX_ID_CHARS: usize = 16;
const MAX_NAV_PARENT_CHARS: usize = 16;
const MAX_NAV_INDEX_ITEMS: usize = 2048;
const HOME_ALIAS: &str = "index";
// Keep in sync with management WS protocol limits.
const WS_MAX_MESSAGE_BYTES: usize = 63 * 1024;
const WS_STREAM_CHUNK_OVERHEAD_BYTES: usize = 17;
const WS_MAX_STREAM_CHUNK_BYTES: usize = WS_MAX_MESSAGE_BYTES - WS_STREAM_CHUNK_OVERHEAD_BYTES;
const DEFAULT_STREAM_CHUNK_BYTES: u32 = WS_MAX_STREAM_CHUNK_BYTES as u32;

#[derive(Debug, Clone)]
pub enum UploadKind {
    Binary(BinaryUploadMeta),
    MarkdownCreate(MarkdownUploadMeta),
    MarkdownUpdate(MarkdownUpdateMeta),
}

#[derive(Debug, Clone)]
pub struct UploadBeginConfig {
    pub connection_id: u32,
    pub kind: UploadKind,
    pub temp_path: PathBuf,
    pub expected_bytes: u64,
    pub max_bytes: u64,
    pub chunk_bytes: u32,
    pub validate_utf8: bool,
}

impl UploadBeginConfig {
    pub fn builder(
        connection_id: u32,
        kind: UploadKind,
        temp_path: PathBuf,
        expected_bytes: u64,
        max_bytes: u64,
        chunk_bytes: u32,
    ) -> UploadBeginConfigBuilder {
        UploadBeginConfigBuilder {
            connection_id,
            kind,
            temp_path,
            expected_bytes,
            max_bytes,
            chunk_bytes,
            validate_utf8: false,
        }
    }
}

#[derive(Debug)]
pub struct UploadBeginConfigBuilder {
    connection_id: u32,
    kind: UploadKind,
    temp_path: PathBuf,
    expected_bytes: u64,
    max_bytes: u64,
    chunk_bytes: u32,
    validate_utf8: bool,
}

impl UploadBeginConfigBuilder {
    pub fn validate_utf8(mut self, validate_utf8: bool) -> Self {
        self.validate_utf8 = validate_utf8;
        self
    }

    pub fn build(self) -> UploadBeginConfig {
        UploadBeginConfig {
            connection_id: self.connection_id,
            kind: self.kind,
            temp_path: self.temp_path,
            expected_bytes: self.expected_bytes,
            max_bytes: self.max_bytes,
            chunk_bytes: self.chunk_bytes,
            validate_utf8: self.validate_utf8,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BinaryUploadMeta {
    pub content_id: u64,
    pub version: u32,
    pub alias: String,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub filename: String,
    pub mime: String,
}

#[derive(Debug, Clone)]
pub struct MarkdownUploadMeta {
    pub content_id: u64,
    pub version: u32,
    pub sidecar: ContentSidecar,
}

#[derive(Debug, Clone)]
pub struct MarkdownUpdateMeta {
    pub content_id: u64,
    pub base_version: u32,
    pub sidecar: ContentSidecar,
    pub clear_children: bool,
    pub nav_changed: bool,
}

#[derive(Debug)]
pub struct UploadInit {
    pub upload_id: u32,
    pub stream_id: u32,
    pub max_bytes: u64,
    pub chunk_bytes: u32,
}

#[derive(Debug)]
pub struct UploadRecord {
    pub kind: UploadKind,
    pub stream_id: u32,
    pub chunk_bytes: u32,
    pub temp_path: PathBuf,
    pub bytes_written: u64,
    pub expected_bytes: u64,
    pub max_bytes: u64,
    pub complete: bool,
    pub connection_id: u32,
}

#[async_trait]
pub trait UploadRegistryAccess {
    async fn begin_upload(&self, config: UploadBeginConfig) -> Result<UploadInit, String>;
    async fn take_upload(&self, upload_id: u32) -> Result<UploadRecord, String>;
}

pub trait ContentContext:
    ConfigAccess + PageCacheAccess + SearchServiceAccess + ReleaseTrackerAccess + UploadRegistryAccess
{
}

impl<T> ContentContext for T where
    T: ConfigAccess
        + PageCacheAccess
        + SearchServiceAccess
        + ReleaseTrackerAccess
        + UploadRegistryAccess
{
}

pub fn content_summary_from_object(object: &CachedObject) -> ContentSummary {
    ContentSummary {
        id: content_id_hex(object.key.id),
        alias: object.alias.clone(),
        title: object.title.clone(),
        mime: object.mime.clone(),
        tags: object.tags.clone(),
        nav_title: object.nav_title.clone(),
        nav_parent_id: object.nav_parent_id.clone(),
        nav_order: object.nav_order,
        original_filename: object.original_filename.clone(),
        is_markdown: object.is_markdown,
    }
}

pub async fn handle_content_request<C>(
    request: ManagementRequest,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: ContentContext,
{
    let response = match request.command {
        ManagementCommand::Content(ContentCommand::List(payload)) => {
            handle_list(payload, request.workflow_id, context).await
        }
        ManagementCommand::Content(ContentCommand::Read(payload)) => {
            handle_read(payload, request.workflow_id, context).await
        }
        ManagementCommand::Content(ContentCommand::Update(payload)) => {
            handle_update(payload, request.workflow_id, context).await
        }
        ManagementCommand::Content(ContentCommand::Delete(payload)) => {
            handle_delete(payload, request.workflow_id, context).await
        }
        ManagementCommand::Content(ContentCommand::Upload(payload)) => {
            handle_upload(payload, request.workflow_id, context).await
        }
        ManagementCommand::Content(ContentCommand::NavIndex(payload)) => {
            handle_nav_index(payload, request.workflow_id, context).await
        }
        ManagementCommand::Content(ContentCommand::BinaryPrevalidate(payload)) => {
            handle_binary_prevalidate(payload, request.workflow_id, context).await
        }
        ManagementCommand::Content(ContentCommand::BinaryUploadInit(payload)) => {
            handle_binary_upload_init(payload, request.workflow_id, request.connection_id, context)
                .await
        }
        ManagementCommand::Content(ContentCommand::BinaryUploadCommit(payload)) => {
            handle_binary_upload_commit(
                payload,
                request.workflow_id,
                request.connection_id,
                context,
            )
            .await
        }
        ManagementCommand::Content(ContentCommand::UploadStreamInit(payload)) => {
            handle_upload_stream_init(payload, request.workflow_id, request.connection_id, context)
                .await
        }
        ManagementCommand::Content(ContentCommand::UploadStreamCommit(payload)) => {
            handle_upload_stream_commit(
                payload,
                request.workflow_id,
                request.connection_id,
                context,
            )
            .await
        }
        ManagementCommand::Content(ContentCommand::UpdateStreamInit(payload)) => {
            handle_update_stream_init(payload, request.workflow_id, request.connection_id, context)
                .await
        }
        ManagementCommand::Content(ContentCommand::UpdateStreamCommit(payload)) => {
            handle_update_stream_commit(
                payload,
                request.workflow_id,
                request.connection_id,
                context,
            )
            .await
        }
        _ => response_err(
            CONTENT_ACTION_LIST_ERR,
            request.workflow_id,
            "Invalid content command",
        ),
    };

    Ok(response)
}

async fn handle_list<C>(
    payload: ContentListRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    if let Err(err) = validate_content_list(&payload) {
        return response_err(CONTENT_ACTION_LIST_ERR, workflow_id, &err);
    }

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_LIST_ERR, workflow_id, &err),
    };

    let mut items: Vec<_> = cache.list_objects();
    if payload.markdown_only {
        items.retain(|object| object.is_markdown);
    }

    if let Some(tags) = payload.tags.as_ref() {
        let tags: Vec<String> = tags.iter().map(|tag| tag.to_ascii_lowercase()).collect();
        items.retain(|object| {
            tags.iter()
                .all(|tag| object.tags.iter().any(|item| item == tag))
        });
    }

    if let Some(query) = payload.query.as_ref() {
        let needle = query.to_ascii_lowercase();
        items.retain(|object| {
            object
                .title
                .as_ref()
                .map(|title| title.to_ascii_lowercase().contains(&needle))
                .unwrap_or(false)
        });
    }

    sort_content_items(&mut items, payload.sort_field, payload.sort_direction);

    let total = items.len() as u32;
    let page_size = payload.page_size;
    let page = payload.page.max(1);
    let start = ((page - 1) * page_size) as usize;
    let end = min(start + page_size as usize, items.len());
    let page_items = if start < items.len() {
        items[start..end].to_vec()
    } else {
        Vec::new()
    };

    let response_items = page_items
        .into_iter()
        .map(|object| content_summary_from_object(&object))
        .collect();

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_LIST_OK,
        workflow_id,
        payload: ResponsePayload::ContentList(ContentListResponse {
            total,
            page,
            page_size,
            items: response_items,
        }),
    }
}

fn sort_content_items(
    items: &mut [CachedObject],
    field: ContentSortField,
    direction: ContentSortDirection,
) {
    items.sort_by(|left, right| {
        let ordering = match field {
            ContentSortField::Title => {
                compare_optional_str(left.title.as_deref(), right.title.as_deref(), direction)
            }
            ContentSortField::Alias => compare_optional_str(
                Some(left.alias.as_str()),
                Some(right.alias.as_str()),
                direction,
            ),
            ContentSortField::Tags => {
                let left_tags = tags_sort_value(&left.tags);
                let right_tags = tags_sort_value(&right.tags);
                compare_optional_str(left_tags.as_deref(), right_tags.as_deref(), direction)
            }
            ContentSortField::Mime => compare_optional_str(
                Some(left.mime.as_str()),
                Some(right.mime.as_str()),
                direction,
            ),
            ContentSortField::NavTitle => compare_optional_str(
                left.nav_title.as_deref(),
                right.nav_title.as_deref(),
                direction,
            ),
        };

        ordering.then_with(|| left.key.id.0.cmp(&right.key.id.0))
    });
}

fn tags_sort_value(tags: &[String]) -> Option<String> {
    if tags.is_empty() {
        return None;
    }
    Some(tags.join(", "))
}

fn compare_optional_str(
    left: Option<&str>,
    right: Option<&str>,
    direction: ContentSortDirection,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => match direction {
            ContentSortDirection::Asc => left.cmp(right),
            ContentSortDirection::Desc => right.cmp(left),
        },
    }
}

async fn handle_read<C>(
    payload: ContentReadRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    let stream_requested = payload.stream_content.unwrap_or(false);
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_READ_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_READ_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => return response_err(CONTENT_ACTION_READ_ERR, workflow_id, "Content not found"),
    };

    let sidecar_path = sidecar_path(
        &context.runtime_paths().content_dir,
        object.key.id,
        object.key.version,
    );
    let sidecar = match read_sidecar(&sidecar_path) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_READ_ERR,
                workflow_id,
                &format!("Failed to read sidecar: {}", err),
            );
        }
    };

    let nav_title = normalize_nav_title_value(&sidecar.nav_title);
    let nav_parent_id = normalize_nav_parent_value(&sidecar.nav_parent_id, nav_title.is_some());
    let nav_order = normalize_nav_order_value(&sidecar.nav_order, nav_title.is_some());

    let mut stream_id = None;
    let mut chunk_bytes = None;
    let mut size_bytes = None;
    let content = if object.is_markdown {
        let blob_path = blob_path(
            &context.runtime_paths().content_dir,
            object.key.id,
            object.key.version,
        );
        match fs::read_to_string(&blob_path) {
            Ok(content) => Some(content),
            Err(err) => {
                return response_err(
                    CONTENT_ACTION_READ_ERR,
                    workflow_id,
                    &format!("Failed to read content: {}", err),
                );
            }
        }
    } else {
        if stream_requested {
            let blob_path = blob_path(
                &context.runtime_paths().content_dir,
                object.key.id,
                object.key.version,
            );
            let metadata = match fs::metadata(&blob_path) {
                Ok(metadata) => metadata,
                Err(err) => {
                    return response_err(
                        CONTENT_ACTION_READ_ERR,
                        workflow_id,
                        &format!("Failed to read content metadata: {}", err),
                    );
                }
            };
            stream_id = Some(workflow_id);
            chunk_bytes = Some(DEFAULT_STREAM_CHUNK_BYTES);
            size_bytes = Some(metadata.len());
        }
        None
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_READ_OK,
        workflow_id,
        payload: ResponsePayload::ContentRead(ContentReadResponse {
            id: content_id_hex(object.key.id),
            alias: sidecar.alias,
            title: sidecar.title,
            mime: sidecar.mime,
            tags: sidecar.tags,
            nav_title,
            nav_parent_id,
            nav_order,
            original_filename: sidecar.original_filename,
            theme: sidecar.theme,
            content,
            stream_id,
            chunk_bytes,
            size_bytes,
        }),
    }
}

async fn handle_update<C>(
    payload: ContentUpdateRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    let reserved_paths = ReservedPaths::from_config(context.config());
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, "Content not found"),
    };

    let current_sidecar_path = sidecar_path(
        &context.runtime_paths().content_dir,
        object.key.id,
        object.key.version,
    );
    let mut sidecar = match read_sidecar(&current_sidecar_path) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to read sidecar: {}", err),
            );
        }
    };

    let mut alias_changed = false;
    if let Some(new_alias) = payload.new_alias {
        let canonical = match canonicalize_optional_with_reserved_paths(&new_alias, &reserved_paths)
        {
            Ok(alias) => alias,
            Err(err) => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err),
        };
        if object.alias == HOME_ALIAS && canonical.as_deref() != Some(HOME_ALIAS) {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Index alias cannot be changed",
            );
        }
        if let Some(canonical) = canonical.as_ref()
            && canonical != &object.alias
            && let Some(existing) = cache.get_by_alias(canonical)
            && existing.key.id != object.key.id
        {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Alias already in use",
            );
        }
        let canonical_alias = canonical.unwrap_or_default();
        alias_changed = canonical_alias != object.alias;
        sidecar.alias = canonical_alias;
    }

    if let Some(title) = payload.title {
        let trimmed = title.trim();
        if trimmed.is_empty() {
            sidecar.title = None;
        } else {
            sidecar.title = Some(trimmed.to_string());
        }
    }

    if let Some(tags) = payload.tags {
        if let Err(err) = validate_tags(&tags) {
            return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err);
        }
        sidecar.tags = tags;
    }

    let current_nav_title = normalize_nav_title_value(&sidecar.nav_title);
    let current_nav_parent_id =
        normalize_nav_parent_value(&sidecar.nav_parent_id, current_nav_title.is_some());
    let current_nav_order =
        normalize_nav_order_value(&sidecar.nav_order, current_nav_title.is_some());
    let mut nav_title = current_nav_title.clone();
    let mut nav_parent_id = current_nav_parent_id.clone();
    let mut nav_order = current_nav_order;

    let mut nav_title_updated = false;
    let mut nav_parent_updated = false;
    let mut nav_order_updated = false;

    if let Some(value) = payload.nav_title {
        nav_title_updated = true;
        nav_title = normalize_nav_title_input(&value);
        if nav_title.is_none() {
            nav_parent_id = None;
            nav_order = None;
        }
    }

    if let Some(value) = payload.nav_parent_id {
        nav_parent_updated = true;
        nav_parent_id = normalize_nav_parent_input(&value);
    }

    if let Some(value) = payload.nav_order {
        nav_order_updated = true;
        nav_order = Some(value);
    }

    let nav_modified = nav_title_updated || nav_parent_updated || nav_order_updated;
    let clear_children = nav_modified && current_nav_title.is_some() && nav_title.is_none();
    if nav_modified && nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPDATE_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_modified
        && nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, Some(object.key.id))
    {
        return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err);
    }

    if nav_modified {
        sidecar.nav_title = nav_title.clone();
        sidecar.nav_parent_id = nav_parent_id.clone();
        sidecar.nav_order = nav_order;
    }
    let nav_entry_after = nav_title.is_some();
    let nav_changed = (nav_modified
        && (nav_title != current_nav_title
            || nav_parent_id != current_nav_parent_id
            || nav_order != current_nav_order))
        || (alias_changed && nav_entry_after);

    if let Some(theme) = payload.theme {
        let trimmed = theme.trim();
        if trimmed.is_empty() {
            sidecar.theme = None;
        } else {
            sidecar.theme = Some(trimmed.to_string());
        }
    }

    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }

    let mut search_upsert_in_memory: Option<(ContentVersion, String)> = None;
    let mut search_upsert_from_disk: Option<ContentVersion> = None;
    if let Some(content_text) = payload.content {
        if !object.is_markdown {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Only markdown content can be edited",
            );
        }
        if content_text.is_empty() {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Content cannot be empty",
            );
        }
        if let Err(err) = resolve_upload_limit(content_text.len() as u64, context.config()) {
            return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err);
        }

        let next_version = match object.key.version.0.checked_add(1) {
            Some(version) => ContentVersion(version),
            None => {
                return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, "Version overflow");
            }
        };
        let blob = blob_path(
            &context.runtime_paths().content_dir,
            object.key.id,
            next_version,
        );
        if let Some(parent) = blob.parent()
            && let Err(err) = fs::create_dir_all(parent)
        {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to create shard dir: {}", err),
            );
        }
        if let Err(err) = fs::write(&blob, content_text.as_bytes()) {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to write content: {}", err),
            );
        }
        let new_sidecar_path = sidecar_path(
            &context.runtime_paths().content_dir,
            object.key.id,
            next_version,
        );
        if let Err(err) = write_sidecar_atomic(&new_sidecar_path, &sidecar) {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to write sidecar: {}", err),
            );
        }
        search_upsert_in_memory = Some((next_version, content_text));
    } else if let Err(err) = write_sidecar_atomic(&current_sidecar_path, &sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_ERR,
            workflow_id,
            &format!("Failed to update sidecar: {}", err),
        );
    } else if object.is_markdown {
        search_upsert_from_disk = Some(object.key.version);
    }

    let mut child_nav_changed = false;
    if clear_children {
        match clear_child_nav_titles(&cache, &context.runtime_paths().content_dir, object.key.id) {
            Ok(changed) => child_nav_changed = changed,
            Err(err) => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err),
        }
    }

    if let Some((version, body)) = search_upsert_in_memory {
        content_workflows::enqueue_markdown_upsert_in_memory(
            context,
            object.key.id,
            version,
            &sidecar,
            body,
            "content.update.in_memory",
        );
    } else if let Some(version) = search_upsert_from_disk {
        content_workflows::enqueue_markdown_upsert_from_disk(
            context,
            object.key.id,
            version,
            sidecar.mime.trim() == "text/markdown",
            "content.update.from_disk",
        );
    }

    content_workflows::invalidate_cache(context).await;
    if nav_changed || child_nav_changed {
        content_workflows::bump_release_tracker_for_nav_change(context, content_id);
    }
    response_ok(
        CONTENT_ACTION_UPDATE_OK,
        workflow_id,
        "Content updated successfully",
    )
}

async fn handle_delete<C>(
    payload: ContentDeleteRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_DELETE_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_DELETE_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => return response_err(CONTENT_ACTION_DELETE_ERR, workflow_id, "Content not found"),
    };
    let nav_has_entry =
        object.nav_title.is_some() || object.nav_parent_id.is_some() || object.nav_order.is_some();

    if let Err(err) = delete_all_versions(&context.runtime_paths().content_dir, object.key.id) {
        return response_err(
            CONTENT_ACTION_DELETE_ERR,
            workflow_id,
            &format!("Failed to delete content: {}", err),
        );
    }

    content_workflows::enqueue_markdown_delete(
        context,
        object.key.id,
        object.is_markdown,
        "content.delete",
    );

    content_workflows::invalidate_cache(context).await;
    if nav_has_entry {
        content_workflows::bump_release_tracker_for_nav_change(context, content_id);
    }
    response_ok(
        CONTENT_ACTION_DELETE_OK,
        workflow_id,
        "Content deleted successfully",
    )
}

async fn handle_upload<C>(
    payload: ContentUploadRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    if let Err(err) = validate_content_upload(&payload) {
        return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err);
    }
    if let Err(err) = resolve_upload_limit(payload.content.len() as u64, context.config()) {
        return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err);
    }

    let reserved_paths = ReservedPaths::from_config(context.config());
    let alias = match payload.alias.as_deref() {
        Some(value) => match canonicalize_optional_with_reserved_paths(value, &reserved_paths) {
            Ok(alias) => alias,
            Err(err) => return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err),
        },
        None => None,
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err),
    };

    if let Some(alias) = alias.as_ref()
        && cache.get_by_alias(alias).is_some()
    {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            "Alias already exists",
        );
    }

    let content_id = match generate_content_id() {
        Ok(id) => id,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_ERR,
                workflow_id,
                &format!("Failed to generate ID: {}", err),
            );
        }
    };
    let version = ContentVersion(1);
    let mime = if payload.mime.trim().eq_ignore_ascii_case("text/markdown") {
        "text/markdown".to_string()
    } else {
        let filename = payload
            .original_filename
            .as_deref()
            .or(alias.as_deref())
            .unwrap_or("upload");
        detect_mime_type(Path::new(filename), &payload.content)
    };
    let markdown_body = if mime == "text/markdown" {
        match std::str::from_utf8(&payload.content) {
            Ok(content) => Some(content.to_string()),
            Err(_) => {
                return response_err(
                    CONTENT_ACTION_UPLOAD_ERR,
                    workflow_id,
                    "Markdown content must be valid UTF-8",
                );
            }
        }
    } else {
        None
    };

    let nav_title = normalize_nav_title_value(&payload.nav_title);
    let mut nav_parent_id = normalize_nav_parent_value(&payload.nav_parent_id, nav_title.is_some());
    let mut nav_order = normalize_nav_order_value(&payload.nav_order, nav_title.is_some());
    if nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, None)
    {
        return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err);
    }

    if nav_title.is_none() {
        nav_parent_id = None;
        nav_order = None;
    }
    let nav_has_entry = nav_title.is_some();

    let sidecar = ContentSidecar {
        alias: alias.clone().unwrap_or_default(),
        title: payload.title.clone(),
        mime: mime.clone(),
        tags: payload.tags.clone(),
        nav_title,
        nav_parent_id,
        nav_order,
        original_filename: payload.original_filename.clone(),
        theme: payload.theme.clone(),
    };
    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }
    let blob = blob_path(&context.runtime_paths().content_dir, content_id, version);
    if let Some(parent) = blob.parent()
        && let Err(err) = fs::create_dir_all(parent)
    {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Failed to create shard dir: {}", err),
        );
    }
    if let Err(err) = fs::write(&blob, &payload.content) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Failed to write content: {}", err),
        );
    }

    let sidecar_path = sidecar_path(&context.runtime_paths().content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    if let Some(body) = markdown_body {
        content_workflows::enqueue_markdown_upsert_in_memory(
            context,
            content_id,
            version,
            &sidecar,
            body,
            "content.upload.in_memory",
        );
    }

    content_workflows::invalidate_cache(context).await;
    if nav_has_entry {
        content_workflows::bump_release_tracker_for_nav_change(context, content_id);
    }
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPLOAD_OK,
        workflow_id,
        payload: ResponsePayload::ContentUpload(ContentUploadResponse {
            id: content_id_hex(content_id),
            alias: alias.unwrap_or_default(),
            mime: mime.clone(),
            is_markdown: mime == "text/markdown",
        }),
    }
}

async fn handle_nav_index<C>(
    _payload: ContentNavIndexRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_NAV_INDEX_ERR, workflow_id, &err),
    };

    let items = cache
        .list_nav_objects()
        .into_iter()
        .map(|object| ContentNavIndexEntry {
            id: content_id_hex(object.key.id),
            alias: object.alias,
            title: object.title,
            nav_title: object.nav_title,
            nav_parent_id: object.nav_parent_id,
            nav_order: object.nav_order,
        })
        .collect();

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_NAV_INDEX_OK,
        workflow_id,
        payload: ResponsePayload::ContentNavIndex(ContentNavIndexResponse { items }),
    }
}

async fn handle_binary_prevalidate<C>(
    payload: BinaryPrevalidateRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    if let Err(err) = validate_binary_prevalidate(&payload) {
        return response_err(CONTENT_ACTION_BINARY_PREVALIDATE_ERR, workflow_id, &err);
    }

    let decision = validate_binary_file_inputs(
        &payload.filename,
        &payload.mime,
        payload.size_bytes,
        context,
    );
    let (accepted, message) = match decision {
        Ok(_) => (true, "Accepted".to_string()),
        Err(err) => (false, err),
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_BINARY_PREVALIDATE_OK,
        workflow_id,
        payload: ResponsePayload::ContentBinaryPrevalidate(BinaryPrevalidateResponse {
            accepted,
            message,
        }),
    }
}

async fn handle_binary_upload_init<C>(
    payload: BinaryUploadInitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    if let Err(err) = validate_binary_upload_init(&payload) {
        return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err);
    }
    if let Err(err) = validate_binary_file_inputs(
        &payload.filename,
        &payload.mime,
        payload.size_bytes,
        context,
    ) {
        return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err);
    }

    let reserved_paths = ReservedPaths::from_config(context.config());
    let alias = match payload.alias.as_deref() {
        Some(value) => match canonicalize_optional_with_reserved_paths(value, &reserved_paths) {
            Ok(alias) => alias,
            Err(err) => {
                return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err);
            }
        },
        None => None,
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err),
    };

    if let Some(alias) = alias.as_ref()
        && cache.get_by_alias(alias).is_some()
    {
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
            workflow_id,
            "Alias already exists",
        );
    }

    let content_id = match generate_content_id() {
        Ok(id) => id,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
                workflow_id,
                &format!("Failed to generate ID: {}", err),
            );
        }
    };
    let version = ContentVersion(1);
    let blob = blob_path(&context.runtime_paths().content_dir, content_id, version);
    let temp_path = temp_upload_path(&blob);

    let max_bytes = match resolve_upload_limit(payload.size_bytes, context.config()) {
        Ok(max_bytes) => max_bytes,
        Err(err) => return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err),
    };

    let init_config = UploadBeginConfig::builder(
        connection_id,
        UploadKind::Binary(BinaryUploadMeta {
            content_id: content_id.0,
            version: version.0,
            alias: alias.clone().unwrap_or_default(),
            title: payload.title.clone(),
            tags: payload.tags.clone(),
            filename: payload.filename.clone(),
            mime: payload.mime.clone(),
        }),
        temp_path,
        payload.size_bytes,
        max_bytes,
        DEFAULT_STREAM_CHUNK_BYTES,
    )
    .validate_utf8(false)
    .build();

    let init = match context.begin_upload(init_config).await {
        Ok(init) => init,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUploadStreamInit(UploadStreamInitResponse {
            upload_id: init.upload_id,
            stream_id: init.stream_id,
            max_bytes: init.max_bytes,
            chunk_bytes: init.chunk_bytes,
        }),
    }
}

async fn handle_binary_upload_commit<C>(
    payload: BinaryUploadCommitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    let record = match context.take_upload(payload.upload_id).await {
        Ok(record) => record,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let UploadRecord {
        kind,
        temp_path,
        connection_id: record_connection_id,
        complete,
        ..
    } = record;

    if record_connection_id != connection_id {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            "Upload session mismatch",
        );
    }

    if !complete {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            "Upload stream not complete",
        );
    }

    let meta = match kind {
        UploadKind::Binary(meta) => meta,
        _ => {
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
                workflow_id,
                "Upload type mismatch",
            );
        }
    };

    let content_id = ContentId(meta.content_id);
    let version = ContentVersion(meta.version);
    let blob = blob_path(&context.runtime_paths().content_dir, content_id, version);
    if let Err(err) = fs::rename(&temp_path, &blob) {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            &format!("Failed to finalize upload: {}", err),
        );
    }

    let detected_mime = detect_mime_for_upload(&blob, &meta.filename);
    let sidecar = ContentSidecar {
        alias: meta.alias.clone(),
        title: meta.title.clone(),
        mime: detected_mime.clone(),
        tags: meta.tags.clone(),
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: Some(meta.filename.clone()),
        theme: None,
    };
    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }
    let sidecar_path = sidecar_path(&context.runtime_paths().content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    content_workflows::invalidate_cache(context).await;
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUpload(ContentUploadResponse {
            id: content_id_hex(content_id),
            alias: meta.alias,
            mime: detected_mime.clone(),
            is_markdown: detected_mime == "text/markdown",
        }),
    }
}

async fn handle_upload_stream_init<C>(
    payload: ContentUploadStreamInitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    if let Err(err) = validate_content_upload_stream_init(&payload) {
        return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err);
    }
    let max_bytes = match resolve_upload_limit(payload.size_bytes, context.config()) {
        Ok(max_bytes) => max_bytes,
        Err(err) => return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err),
    };

    let reserved_paths = ReservedPaths::from_config(context.config());
    let alias = match payload.alias.as_deref() {
        Some(value) => match canonicalize_optional_with_reserved_paths(value, &reserved_paths) {
            Ok(alias) => alias,
            Err(err) => {
                return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err);
            }
        },
        None => None,
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err),
    };

    if let Some(alias) = alias.as_ref()
        && cache.get_by_alias(alias).is_some()
    {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            workflow_id,
            "Alias already exists",
        );
    }

    let content_id = match generate_content_id() {
        Ok(id) => id,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
                workflow_id,
                &format!("Failed to generate ID: {}", err),
            );
        }
    };
    let version = ContentVersion(1);

    let nav_title = normalize_nav_title_value(&payload.nav_title);
    let mut nav_parent_id = normalize_nav_parent_value(&payload.nav_parent_id, nav_title.is_some());
    let mut nav_order = normalize_nav_order_value(&payload.nav_order, nav_title.is_some());
    if nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, None)
    {
        return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err);
    }

    if nav_title.is_none() {
        nav_parent_id = None;
        nav_order = None;
    }

    let sidecar = ContentSidecar {
        alias: alias.clone().unwrap_or_default(),
        title: payload.title.clone(),
        mime: "text/markdown".to_string(),
        tags: payload.tags.clone(),
        nav_title,
        nav_parent_id,
        nav_order,
        original_filename: None,
        theme: payload.theme.clone(),
    };
    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }

    let blob = blob_path(&context.runtime_paths().content_dir, content_id, version);
    let temp_path = temp_upload_path(&blob);
    let init_config = UploadBeginConfig::builder(
        connection_id,
        UploadKind::MarkdownCreate(MarkdownUploadMeta {
            content_id: content_id.0,
            version: version.0,
            sidecar,
        }),
        temp_path,
        payload.size_bytes,
        max_bytes,
        DEFAULT_STREAM_CHUNK_BYTES,
    )
    .validate_utf8(true)
    .build();

    let init = match context.begin_upload(init_config).await {
        Ok(init) => init,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUploadStreamInit(UploadStreamInitResponse {
            upload_id: init.upload_id,
            stream_id: init.stream_id,
            max_bytes: init.max_bytes,
            chunk_bytes: init.chunk_bytes,
        }),
    }
}

async fn handle_upload_stream_commit<C>(
    payload: ContentUploadStreamCommitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    let record = match context.take_upload(payload.upload_id).await {
        Ok(record) => record,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let UploadRecord {
        kind,
        temp_path,
        connection_id: record_connection_id,
        complete,
        ..
    } = record;

    if record_connection_id != connection_id {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload session mismatch",
        );
    }

    if !complete {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload stream not complete",
        );
    }

    let meta = match kind {
        UploadKind::MarkdownCreate(meta) => meta,
        _ => {
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
                workflow_id,
                "Upload type mismatch",
            );
        }
    };

    let content_id = ContentId(meta.content_id);
    let version = ContentVersion(meta.version);
    let blob = blob_path(&context.runtime_paths().content_dir, content_id, version);
    if let Err(err) = fs::rename(&temp_path, &blob) {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to finalize upload: {}", err),
        );
    }

    let sidecar_path = sidecar_path(&context.runtime_paths().content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &meta.sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    content_workflows::enqueue_markdown_upsert_from_disk(
        context,
        content_id,
        version,
        true,
        "content.upload_stream_commit.from_disk",
    );

    content_workflows::invalidate_cache(context).await;
    if meta.sidecar.nav_title.is_some() {
        content_workflows::bump_release_tracker_for_nav_change(context, content_id);
    }
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUpload(ContentUploadResponse {
            id: content_id_hex(content_id),
            alias: meta.sidecar.alias,
            mime: "text/markdown".to_string(),
            is_markdown: true,
        }),
    }
}

async fn handle_update_stream_init<C>(
    payload: ContentUpdateStreamInitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    if let Err(err) = validate_content_update_stream_init(&payload) {
        return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
    }
    let max_bytes = match resolve_upload_limit(payload.size_bytes, context.config()) {
        Ok(max_bytes) => max_bytes,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err),
    };

    let reserved_paths = ReservedPaths::from_config(context.config());
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Content not found",
            );
        }
    };

    if !object.is_markdown {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            workflow_id,
            "Only markdown content can be edited",
        );
    }

    let current_sidecar_path = sidecar_path(
        &context.runtime_paths().content_dir,
        object.key.id,
        object.key.version,
    );
    let mut sidecar = match read_sidecar(&current_sidecar_path) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                &format!("Failed to read sidecar: {}", err),
            );
        }
    };

    let mut alias_changed = false;
    if let Some(new_alias) = payload.new_alias.clone() {
        let canonical = match canonicalize_optional_with_reserved_paths(&new_alias, &reserved_paths)
        {
            Ok(alias) => alias,
            Err(err) => {
                return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
            }
        };
        if object.alias == HOME_ALIAS && canonical.as_deref() != Some(HOME_ALIAS) {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Index alias cannot be changed",
            );
        }
        if let Some(canonical) = canonical.as_ref()
            && canonical != &object.alias
            && let Some(existing) = cache.get_by_alias(canonical)
            && existing.key.id != object.key.id
        {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Alias already in use",
            );
        }
        let canonical_alias = canonical.unwrap_or_default();
        alias_changed = canonical_alias != object.alias;
        sidecar.alias = canonical_alias;
    }

    if let Some(title) = payload.title.clone() {
        let trimmed = title.trim();
        if trimmed.is_empty() {
            sidecar.title = None;
        } else {
            sidecar.title = Some(trimmed.to_string());
        }
    }

    if let Some(tags) = payload.tags.clone() {
        if let Err(err) = validate_tags(&tags) {
            return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
        }
        sidecar.tags = tags;
    }

    let current_nav_title = normalize_nav_title_value(&sidecar.nav_title);
    let current_nav_parent_id =
        normalize_nav_parent_value(&sidecar.nav_parent_id, current_nav_title.is_some());
    let current_nav_order =
        normalize_nav_order_value(&sidecar.nav_order, current_nav_title.is_some());
    let mut nav_title = current_nav_title.clone();
    let mut nav_parent_id = current_nav_parent_id.clone();
    let mut nav_order = current_nav_order;

    let mut nav_title_updated = false;
    let mut nav_parent_updated = false;
    let mut nav_order_updated = false;

    if let Some(value) = payload.nav_title.clone() {
        nav_title_updated = true;
        nav_title = normalize_nav_title_input(&value);
        if nav_title.is_none() {
            nav_parent_id = None;
            nav_order = None;
        }
    }

    if let Some(value) = payload.nav_parent_id.clone() {
        nav_parent_updated = true;
        nav_parent_id = normalize_nav_parent_input(&value);
    }

    if let Some(value) = payload.nav_order {
        nav_order_updated = true;
        nav_order = Some(value);
    }

    let nav_modified = nav_title_updated || nav_parent_updated || nav_order_updated;
    let clear_children = nav_modified && current_nav_title.is_some() && nav_title.is_none();
    if nav_modified && nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_modified
        && nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, Some(object.key.id))
    {
        return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
    }

    if nav_modified {
        sidecar.nav_title = nav_title.clone();
        sidecar.nav_parent_id = nav_parent_id.clone();
        sidecar.nav_order = nav_order;
    }
    let nav_entry_after = nav_title.is_some();
    let nav_changed = (nav_modified
        && (nav_title != current_nav_title
            || nav_parent_id != current_nav_parent_id
            || nav_order != current_nav_order))
        || (alias_changed && nav_entry_after);

    if let Some(theme) = payload.theme.clone() {
        let trimmed = theme.trim();
        if trimmed.is_empty() {
            sidecar.theme = None;
        } else {
            sidecar.theme = Some(trimmed.to_string());
        }
    }

    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }

    let next_version = match object.key.version.0.checked_add(1) {
        Some(version) => ContentVersion(version),
        None => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Version overflow",
            );
        }
    };
    let blob = blob_path(
        &context.runtime_paths().content_dir,
        object.key.id,
        next_version,
    );
    let temp_path = temp_upload_path(&blob);

    let init_config = UploadBeginConfig::builder(
        connection_id,
        UploadKind::MarkdownUpdate(MarkdownUpdateMeta {
            content_id: object.key.id.0,
            base_version: object.key.version.0,
            sidecar,
            clear_children,
            nav_changed,
        }),
        temp_path,
        payload.size_bytes,
        max_bytes,
        DEFAULT_STREAM_CHUNK_BYTES,
    )
    .validate_utf8(true)
    .build();

    let init = match context.begin_upload(init_config).await {
        Ok(init) => init,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUploadStreamInit(UploadStreamInitResponse {
            upload_id: init.upload_id,
            stream_id: init.stream_id,
            max_bytes: init.max_bytes,
            chunk_bytes: init.chunk_bytes,
        }),
    }
}

async fn handle_update_stream_commit<C>(
    payload: ContentUpdateStreamCommitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: ContentContext,
{
    let record = match context.take_upload(payload.upload_id).await {
        Ok(record) => record,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let UploadRecord {
        kind,
        temp_path,
        connection_id: record_connection_id,
        complete,
        ..
    } = record;

    if record_connection_id != connection_id {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload session mismatch",
        );
    }

    if !complete {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload stream not complete",
        );
    }

    let meta = match kind {
        UploadKind::MarkdownUpdate(meta) => meta,
        _ => {
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
                workflow_id,
                "Upload type mismatch",
            );
        }
    };

    let content_id = ContentId(meta.content_id);
    let next_version = match meta.base_version.checked_add(1) {
        Some(version) => ContentVersion(version),
        None => {
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
                workflow_id,
                "Version overflow",
            );
        }
    };

    let blob = blob_path(
        &context.runtime_paths().content_dir,
        content_id,
        next_version,
    );
    if let Err(err) = fs::rename(&temp_path, &blob) {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to finalize upload: {}", err),
        );
    }

    let sidecar_path = sidecar_path(
        &context.runtime_paths().content_dir,
        content_id,
        next_version,
    );
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &meta.sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    let mut child_nav_changed = false;
    if meta.clear_children
        && let Ok(cache) = get_cache(context).await
    {
        match clear_child_nav_titles(&cache, &context.runtime_paths().content_dir, content_id) {
            Ok(changed) => child_nav_changed = changed,
            Err(err) => {
                return response_err(CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR, workflow_id, &err);
            }
        }
    }

    content_workflows::enqueue_markdown_upsert_from_disk(
        context,
        content_id,
        next_version,
        true,
        "content.update_stream_commit.from_disk",
    );

    content_workflows::invalidate_cache(context).await;
    if meta.nav_changed || child_nav_changed {
        content_workflows::bump_release_tracker_for_nav_change(context, content_id);
    }
    response_ok(
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
        workflow_id,
        "Content updated successfully",
    )
}

async fn get_cache<C>(context: &C) -> Result<PageMetaCache, String>
where
    C: ContentContext,
{
    if let Some(cache) = context.page_cache() {
        return Ok(cache.as_ref().clone());
    }

    let cache = PageMetaCache::new(
        context.runtime_paths().content_dir.clone(),
        context.runtime_paths().state_sys_dir.clone(),
        ReservedPaths::from_config(context.config()),
    );
    cache
        .rebuild_cache(true)
        .await
        .map_err(|err| format!("Failed to rebuild cache: {}", err))?;
    Ok(cache)
}

fn upload_max_bytes(config: &ValidatedConfig) -> Result<Option<u64>, String> {
    let max_mb = config.upload.max_file_size_mb;
    if max_mb == 0 {
        return Ok(None);
    }
    max_mb
        .checked_mul(1024)
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| "Upload size limit overflow".to_string())
        .map(Some)
}

fn resolve_upload_limit(size_bytes: u64, config: &ValidatedConfig) -> Result<u64, String> {
    if size_bytes == 0 {
        return Err("Upload size must be greater than 0".to_string());
    }
    let limit = upload_max_bytes(config)?;
    if let Some(max_bytes) = limit {
        if size_bytes > max_bytes {
            return Err("Content exceeds maximum size".to_string());
        }
        return Ok(max_bytes);
    }
    Ok(size_bytes)
}

fn ensure_allowed_extension(filename: &str, config: &ValidatedConfig) -> Result<(), String> {
    let ext = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .ok_or_else(|| "Filename must include an extension".to_string())?;

    if config.upload.allowed_extensions.is_empty() {
        return Ok(());
    }

    if config
        .upload
        .allowed_extensions
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&ext))
    {
        Ok(())
    } else {
        Err("File type is not allowed".to_string())
    }
}

fn temp_upload_path(blob_path: &Path) -> std::path::PathBuf {
    let mut temp = blob_path.to_path_buf();
    let file_name = blob_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("upload");
    temp.set_file_name(format!("{}.upload", file_name));
    temp
}

fn validate_binary_file_inputs<C>(
    filename: &str,
    _mime: &str,
    size_bytes: u64,
    context: &C,
) -> Result<(), String>
where
    C: ContentContext,
{
    resolve_upload_limit(size_bytes, context.config())?;
    ensure_allowed_extension(filename, context.config())?;
    validate_new_file_path(filename, &context.runtime_paths().content_dir)?;
    Ok(())
}

/// Detect MIME type using content-based detection (infer) with fallback to extension-based
/// (mime_guess).
pub fn detect_mime_type(file_path: &Path, file_content: &[u8]) -> String {
    if let Some(mime_type) = infer::get(file_content) {
        return mime_type.mime_type().to_string();
    }

    let mime_guess = mime_guess::from_path(file_path);
    if let Some(mime_type) = mime_guess.first() {
        return mime_type.to_string();
    }

    "application/octet-stream".to_string()
}

fn detect_mime_for_upload(blob_path: &Path, filename: &str) -> String {
    let mut buffer = vec![0u8; 8192];
    let mut read_len = 0usize;
    if let Ok(mut file) = fs::File::open(blob_path)
        && let Ok(bytes) = file.read(&mut buffer)
    {
        read_len = bytes;
    }
    buffer.truncate(read_len);
    detect_mime_type(Path::new(filename), &buffer)
}

fn delete_all_versions(content_dir: &Path, id: ContentId) -> Result<(), std::io::Error> {
    let shard = format!("{:02x}", (id.0 & 0xff) as u8);
    let dir = content_dir.join(shard);
    if !dir.exists() {
        return Ok(());
    }

    let prefix = format!("{:016x}.", id.0);
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with(&prefix) {
            continue;
        }
        fs::remove_file(entry.path())?;
    }
    Ok(())
}

fn canonicalize_optional_or_err(value: &str) -> Result<Option<String>, String> {
    let alias = normalize_optional_alias(value).map_err(|err| err.to_string())?;
    if let Some(alias) = alias.as_ref()
        && alias.chars().count() > MAX_ALIAS_CHARS
    {
        return Err("Alias too long".to_string());
    }
    Ok(alias)
}

fn canonicalize_optional_with_reserved_paths(
    value: &str,
    reserved_paths: &ReservedPaths,
) -> Result<Option<String>, String> {
    let alias = canonicalize_optional_or_err(value)?;
    if let Some(alias) = alias.as_ref()
        && reserved_paths.alias_is_reserved(alias)
    {
        return Err("Alias uses reserved path".to_string());
    }
    Ok(alias)
}

fn parse_id_or_err(value: &str) -> Result<ContentId, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Content ID is required".to_string());
    }
    parse_content_id_hex(trimmed)
}

fn validate_tags(tags: &[String]) -> Result<(), String> {
    if tags.len() > MAX_TAG_COUNT {
        return Err("Too many tags".to_string());
    }
    for tag in tags {
        if tag.chars().count() > MAX_TAG_CHARS {
            return Err("Tag is too long".to_string());
        }
        if !tag.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '/'
        }) {
            return Err(format!("Invalid tag id '{}'", tag));
        }
    }
    Ok(())
}

fn normalize_nav_title_input(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_nav_title_value(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .and_then(|value| normalize_nav_title_input(value))
}

fn normalize_nav_parent_input(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn normalize_nav_parent_value(value: &Option<String>, has_nav_title: bool) -> Option<String> {
    if !has_nav_title {
        return None;
    }
    let normalized = value
        .as_ref()
        .and_then(|value| normalize_nav_parent_input(value))?;
    if parse_content_id_hex(&normalized).is_err() {
        return None;
    }
    Some(normalized)
}

fn normalize_nav_order_value(value: &Option<i32>, has_nav_title: bool) -> Option<i32> {
    if has_nav_title { *value } else { None }
}

fn validate_nav_parent_id(
    parent_id: &str,
    cache: &PageMetaCache,
    self_id: Option<ContentId>,
) -> Result<(), String> {
    let parent_id = parse_content_id_hex(parent_id)
        .map_err(|err| format!("Invalid navbar parent id: {}", err))?;
    if let Some(self_id) = self_id
        && self_id == parent_id
    {
        return Err("Navbar parent cannot reference itself".to_string());
    }

    let parent = cache
        .list_objects()
        .into_iter()
        .find(|object| object.key.id == parent_id)
        .ok_or_else(|| "Navbar parent not found".to_string())?;
    if parent.nav_title.is_none() {
        return Err("Navbar parent must have a navbar title".to_string());
    }
    if parent.nav_parent_id.is_some() {
        return Err("Navbar parent must be a root item".to_string());
    }
    Ok(())
}

fn clear_child_nav_titles(
    cache: &PageMetaCache,
    content_dir: &Path,
    parent_id: ContentId,
) -> Result<bool, String> {
    let parent_id_hex = content_id_hex(parent_id);
    let children: Vec<_> = cache
        .list_objects()
        .into_iter()
        .filter(|object| object.nav_parent_id.as_deref() == Some(parent_id_hex.as_str()))
        .collect();

    let mut changed = false;
    for child in children {
        let sidecar_path = sidecar_path(content_dir, child.key.id, child.key.version);
        let mut sidecar = read_sidecar(&sidecar_path)
            .map_err(|err| format!("Failed to read child sidecar: {}", err))?;
        let had_nav = sidecar.nav_title.is_some()
            || sidecar.nav_parent_id.is_some()
            || sidecar.nav_order.is_some();
        if !had_nav {
            continue;
        }
        sidecar.nav_title = None;
        sidecar.nav_parent_id = None;
        sidecar.nav_order = None;
        write_sidecar_atomic(&sidecar_path, &sidecar)
            .map_err(|err| format!("Failed to update child sidecar: {}", err))?;
        changed = true;
    }
    Ok(changed)
}

fn validate_content_list(request: &ContentListRequest) -> Result<(), String> {
    if request.page_size == 0 || request.page_size > MAX_PAGE_SIZE {
        return Err("Invalid page size".to_string());
    }
    if let Some(query) = &request.query
        && query.chars().count() > MAX_QUERY_CHARS
    {
        return Err("Query too long".to_string());
    }
    if let Some(tags) = &request.tags {
        if tags.iter().any(|tag| tag.trim().is_empty()) {
            return Err("Tag cannot be empty".to_string());
        }
        validate_tags(tags)?;
    }
    Ok(())
}

fn validate_content_upload(request: &ContentUploadRequest) -> Result<(), String> {
    if let Some(alias) = &request.alias {
        canonicalize_optional_or_err(alias)?;
    }
    if request.mime.trim().is_empty() {
        return Err("Missing mime".to_string());
    }
    if request.mime.chars().count() > MAX_MIME_CHARS {
        return Err("Mime too long".to_string());
    }
    if let Some(title) = &request.title
        && title.chars().count() > MAX_TITLE_CHARS
    {
        return Err("Title too long".to_string());
    }
    if let Some(filename) = &request.original_filename
        && filename.chars().count() > MAX_ORIGINAL_FILENAME_CHARS
    {
        return Err("Original filename too long".to_string());
    }
    if let Some(theme) = &request.theme
        && theme.chars().count() > MAX_THEME_CHARS
    {
        return Err("Theme too long".to_string());
    }
    if request.content.is_empty() {
        return Err("Content cannot be empty".to_string());
    }
    validate_tags(&request.tags)?;
    Ok(())
}

fn validate_content_update(request: &ContentUpdateRequest) -> Result<(), String> {
    parse_id_or_err(&request.id)?;
    if let Some(new_alias) = &request.new_alias {
        canonicalize_optional_or_err(new_alias)?;
    }
    if let Some(title) = &request.title
        && title.chars().count() > MAX_TITLE_CHARS
    {
        return Err("Title too long".to_string());
    }
    if let Some(tags) = &request.tags {
        validate_tags(tags)?;
    }
    if let Some(theme) = &request.theme
        && theme.chars().count() > MAX_THEME_CHARS
    {
        return Err("Theme too long".to_string());
    }
    if let Some(content) = &request.content
        && content.is_empty()
    {
        return Err("Content cannot be empty".to_string());
    }
    Ok(())
}

fn validate_binary_prevalidate(request: &BinaryPrevalidateRequest) -> Result<(), String> {
    if request.filename.trim().is_empty() {
        return Err("Filename is required".to_string());
    }
    if request.filename.chars().count() > MAX_ORIGINAL_FILENAME_CHARS {
        return Err("Filename too long".to_string());
    }
    if request.mime.trim().is_empty() {
        return Err("Missing mime".to_string());
    }
    if request.mime.chars().count() > MAX_MIME_CHARS {
        return Err("Mime too long".to_string());
    }
    if request.size_bytes == 0 {
        return Err("Upload size must be greater than 0".to_string());
    }
    Ok(())
}

fn validate_binary_upload_init(request: &BinaryUploadInitRequest) -> Result<(), String> {
    if let Some(alias) = &request.alias {
        canonicalize_optional_or_err(alias)?;
    }
    if let Some(title) = &request.title
        && title.chars().count() > MAX_TITLE_CHARS
    {
        return Err("Title too long".to_string());
    }
    if request.filename.trim().is_empty() {
        return Err("Filename is required".to_string());
    }
    if request.filename.chars().count() > MAX_ORIGINAL_FILENAME_CHARS {
        return Err("Filename too long".to_string());
    }
    if request.mime.trim().is_empty() {
        return Err("Missing mime".to_string());
    }
    if request.mime.chars().count() > MAX_MIME_CHARS {
        return Err("Mime too long".to_string());
    }
    if request.size_bytes == 0 {
        return Err("Upload size must be greater than 0".to_string());
    }
    validate_tags(&request.tags)?;
    Ok(())
}

fn validate_content_upload_stream_init(
    request: &ContentUploadStreamInitRequest,
) -> Result<(), String> {
    if let Some(alias) = &request.alias {
        canonicalize_optional_or_err(alias)?;
    }
    if let Some(title) = &request.title
        && title.chars().count() > MAX_TITLE_CHARS
    {
        return Err("Title too long".to_string());
    }
    if let Some(theme) = &request.theme
        && theme.chars().count() > MAX_THEME_CHARS
    {
        return Err("Theme too long".to_string());
    }
    if request.size_bytes == 0 {
        return Err("Upload size must be greater than 0".to_string());
    }
    validate_tags(&request.tags)?;
    Ok(())
}

fn validate_content_update_stream_init(
    request: &ContentUpdateStreamInitRequest,
) -> Result<(), String> {
    parse_id_or_err(&request.id)?;
    if let Some(new_alias) = &request.new_alias {
        canonicalize_optional_or_err(new_alias)?;
    }
    if let Some(title) = &request.title
        && title.chars().count() > MAX_TITLE_CHARS
    {
        return Err("Title too long".to_string());
    }
    if let Some(tags) = &request.tags {
        validate_tags(tags)?;
    }
    if let Some(theme) = &request.theme
        && theme.chars().count() > MAX_THEME_CHARS
    {
        return Err("Theme too long".to_string());
    }
    if request.size_bytes == 0 {
        return Err("Upload size must be greater than 0".to_string());
    }
    Ok(())
}

fn response_ok(action_id: u32, workflow_id: u32, message: &str) -> ManagementResponse {
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id,
        workflow_id,
        payload: ResponsePayload::Message(MessageResponse {
            message: message.to_string(),
        }),
    }
}

fn response_err(action_id: u32, workflow_id: u32, message: &str) -> ManagementResponse {
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id,
        workflow_id,
        payload: ResponsePayload::Message(MessageResponse {
            message: message.to_string(),
        }),
    }
}

pub struct ContentListRequestCodec;

impl RequestCodec for ContentListRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("query", FieldLimit::MaxChars(MAX_QUERY_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentListRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::List(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::List(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content list codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::List(request)) => {
                validate_content_list(request)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(query) = &request.query {
                    values.insert_len("query", query.chars().count());
                }
                if let Some(tags) = &request.tags {
                    values.insert_count("tags", tags.len());
                    values.insert_lens("tag", tags.iter().map(|tag| tag.chars().count()).collect());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content list codec",
            )),
        }
    }
}

pub struct ContentReadRequestCodec;

impl RequestCodec for ContentReadRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_READ)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("id", FieldLimit::MaxChars(MAX_ID_CHARS))])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentReadRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Read(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Read(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content read codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Read(request)) => {
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                parse_id_or_err(&request.id)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content read codec",
            )),
        }
    }
}

pub struct ContentUpdateRequestCodec;

impl RequestCodec for ContentUpdateRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("new_alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUpdateRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Update(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Update(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Update(request)) => {
                validate_content_update(request)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                if let Some(new_alias) = &request.new_alias {
                    values.insert_len("new_alias", new_alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                if let Some(tags) = &request.tags {
                    values.insert_count("tags", tags.len());
                    values.insert_lens("tag", tags.iter().map(|tag| tag.chars().count()).collect());
                }
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update codec",
            )),
        }
    }
}

pub struct ContentDeleteRequestCodec;

impl RequestCodec for ContentDeleteRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_DELETE)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("id", FieldLimit::MaxChars(MAX_ID_CHARS))])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentDeleteRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Delete(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Delete(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content delete codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Delete(request)) => {
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                parse_id_or_err(&request.id)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content delete codec",
            )),
        }
    }
}

pub struct ContentUploadRequestCodec;

impl RequestCodec for ContentUploadRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            (
                "original_filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUploadRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Upload(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Upload(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Upload(request)) => {
                validate_content_upload(request)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(alias) = &request.alias {
                    values.insert_len("alias", alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_len("mime", request.mime.chars().count());
                values.insert_count("tags", request.tags.len());
                values.insert_lens(
                    "tag",
                    request.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(filename) = &request.original_filename {
                    values.insert_len("original_filename", filename.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload codec",
            )),
        }
    }
}

pub struct ContentNavIndexRequestCodec;

impl RequestCodec for ContentNavIndexRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentNavIndexRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::NavIndex(
            request,
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::NavIndex(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content nav index codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::NavIndex(_)) => Ok(()),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content nav index codec",
            )),
        }
    }
}

pub struct BinaryPrevalidateRequestCodec;

impl RequestCodec for BinaryPrevalidateRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            (
                "filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: BinaryPrevalidateRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::BinaryPrevalidate(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryPrevalidate(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary prevalidate codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryPrevalidate(request)) => {
                validate_binary_prevalidate(request)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                values.insert_len("filename", request.filename.chars().count());
                values.insert_len("mime", request.mime.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary prevalidate codec",
            )),
        }
    }
}

pub struct BinaryUploadInitRequestCodec;

impl RequestCodec for BinaryUploadInitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_INIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            (
                "filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: BinaryUploadInitRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::BinaryUploadInit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryUploadInit(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary upload init codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryUploadInit(request)) => {
                validate_binary_upload_init(request)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(alias) = &request.alias {
                    values.insert_len("alias", alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_count("tags", request.tags.len());
                values.insert_lens(
                    "tag",
                    request.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                values.insert_len("filename", request.filename.chars().count());
                values.insert_len("mime", request.mime.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary upload init codec",
            )),
        }
    }
}

pub struct BinaryUploadCommitRequestCodec;

impl RequestCodec for BinaryUploadCommitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_COMMIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: BinaryUploadCommitRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::BinaryUploadCommit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryUploadCommit(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary upload commit codec",
            )),
        }
    }
}

pub struct ContentUploadStreamInitRequestCodec;

impl RequestCodec for ContentUploadStreamInitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_INIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUploadStreamInitRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UploadStreamInit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UploadStreamInit(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload stream init codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UploadStreamInit(request)) => {
                validate_content_upload_stream_init(request)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(alias) = &request.alias {
                    values.insert_len("alias", alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_count("tags", request.tags.len());
                values.insert_lens(
                    "tag",
                    request.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload stream init codec",
            )),
        }
    }
}

pub struct ContentUploadStreamCommitRequestCodec;

impl RequestCodec for ContentUploadStreamCommitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_COMMIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUploadStreamCommitRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UploadStreamCommit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UploadStreamCommit(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload stream commit codec",
            )),
        }
    }
}

pub struct ContentUpdateStreamInitRequestCodec;

impl RequestCodec for ContentUpdateStreamInitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_INIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("new_alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUpdateStreamInitRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UpdateStreamInit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UpdateStreamInit(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update stream init codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UpdateStreamInit(request)) => {
                validate_content_update_stream_init(request)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                if let Some(new_alias) = &request.new_alias {
                    values.insert_len("new_alias", new_alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                if let Some(tags) = &request.tags {
                    values.insert_count("tags", tags.len());
                    values.insert_lens("tag", tags.iter().map(|tag| tag.chars().count()).collect());
                }
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update stream init codec",
            )),
        }
    }
}

pub struct ContentUpdateStreamCommitRequestCodec;

impl RequestCodec for ContentUpdateStreamCommitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_COMMIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUpdateStreamCommitRequest = codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UpdateStreamCommit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UpdateStreamCommit(request)) => {
                codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update stream commit codec",
            )),
        }
    }
}

pub struct MessageResponseCodec {
    action_id: u32,
}

impl MessageResponseCodec {
    pub fn new(action_id: u32) -> Self {
        Self { action_id }
    }
}

impl ResponseCodec for MessageResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, self.action_id)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content message codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = codec::decode_payload(payload)
            .map_err(|err| CodecError::new(ManagementErrorKind::Codec, err.to_string()))?;
        Ok(ResponsePayload::Message(message))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content message codec",
            )),
        }
    }
}

pub struct ContentListResponseCodec;

impl ResponseCodec for ContentListResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("items", FieldLimit::MaxEntries(MAX_PAGE_SIZE as usize)),
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            (
                "original_filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentList(payload) => codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content list codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentListResponse = codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentList(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentList(payload) => {
                let mut values = FieldValues::new();
                values.insert_count("items", payload.items.len());
                values.insert_lens(
                    "id",
                    payload
                        .items
                        .iter()
                        .map(|item| item.id.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "alias",
                    payload
                        .items
                        .iter()
                        .map(|item| item.alias.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "mime",
                    payload
                        .items
                        .iter()
                        .map(|item| item.mime.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "original_filename",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.original_filename
                                .as_ref()
                                .map(|name| name.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "tags",
                    payload.items.iter().map(|item| item.tags.len()).collect(),
                );
                values.insert_lens(
                    "tag",
                    payload
                        .items
                        .iter()
                        .flat_map(|item| item.tags.iter())
                        .map(|tag| tag.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "nav_title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "nav_parent_id",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_parent_id
                                .as_ref()
                                .map(|id| id.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content list codec",
            )),
        }
    }
}

pub struct ContentNavIndexResponseCodec;

impl ResponseCodec for ContentNavIndexResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("items", FieldLimit::MaxEntries(MAX_NAV_INDEX_ITEMS)),
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentNavIndex(payload) => codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content nav index codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentNavIndexResponse = codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentNavIndex(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentNavIndex(payload) => {
                let mut values = FieldValues::new();
                values.insert_count("items", payload.items.len());
                values.insert_lens(
                    "id",
                    payload
                        .items
                        .iter()
                        .map(|item| item.id.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "alias",
                    payload
                        .items
                        .iter()
                        .map(|item| item.alias.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "nav_title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "nav_parent_id",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_parent_id
                                .as_ref()
                                .map(|id| id.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content nav index codec",
            )),
        }
    }
}

pub struct ContentReadResponseCodec;

impl ResponseCodec for ContentReadResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_READ_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            (
                "original_filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentRead(payload) => codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content read codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentReadResponse = codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentRead(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentRead(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("id", payload.id.chars().count());
                values.insert_len("alias", payload.alias.chars().count());
                if let Some(title) = &payload.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_len("mime", payload.mime.chars().count());
                values.insert_count("tags", payload.tags.len());
                values.insert_lens(
                    "tag",
                    payload.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                if let Some(theme) = &payload.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                if let Some(nav_title) = &payload.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &payload.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(name) = &payload.original_filename {
                    values.insert_len("original_filename", name.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content read codec",
            )),
        }
    }
}

pub struct ContentUploadResponseCodec {
    action_id: u32,
}

impl ContentUploadResponseCodec {
    pub fn new(action_id: u32) -> Self {
        Self { action_id }
    }
}

impl ResponseCodec for ContentUploadResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, self.action_id)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentUpload(payload) => codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content upload codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentUploadResponse = codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentUpload(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentUpload(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("id", payload.id.chars().count());
                values.insert_len("alias", payload.alias.chars().count());
                values.insert_len("mime", payload.mime.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content upload codec",
            )),
        }
    }
}

pub struct BinaryPrevalidateResponseCodec;

impl ResponseCodec for BinaryPrevalidateResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentBinaryPrevalidate(payload) => codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for binary prevalidate codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: BinaryPrevalidateResponse = codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentBinaryPrevalidate(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentBinaryPrevalidate(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for binary prevalidate codec",
            )),
        }
    }
}

pub struct UploadStreamInitResponseCodec {
    action_id: u32,
}

impl UploadStreamInitResponseCodec {
    pub fn new(action_id: u32) -> Self {
        Self { action_id }
    }
}

impl ResponseCodec for UploadStreamInitResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, self.action_id)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentUploadStreamInit(payload) => codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for upload stream init codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: UploadStreamInitResponse = codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentUploadStreamInit(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_content_store::flat_storage::{ContentId, ContentVersion};
    use nop_management_contract::WireDecode;
    use nop_management_contract::wire::{WireReader, WireWriter};
    use nop_rt_page_cache::{ContentKey, ResolvedRoles};

    fn make_object(
        id: u64,
        title: Option<&str>,
        alias: &str,
        tags: &[&str],
        mime: &str,
        nav_title: Option<&str>,
    ) -> CachedObject {
        CachedObject {
            key: ContentKey {
                id: ContentId(id),
                version: ContentVersion(1),
            },
            alias: alias.to_string(),
            title: title.map(str::to_string),
            theme: None,
            mime: mime.to_string(),
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
            nav_title: nav_title.map(str::to_string),
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            last_modified: std::time::SystemTime::UNIX_EPOCH,
            is_markdown: mime == "text/markdown",
            resolved_roles: ResolvedRoles::Public,
        }
    }

    #[test]
    fn sorts_by_title_with_nulls_last_and_id_tiebreaker() {
        let mut items = vec![
            make_object(2, Some("Beta"), "beta", &[], "text/markdown", None),
            make_object(5, Some("Same"), "same-b", &[], "text/markdown", None),
            make_object(4, Some("Same"), "same-a", &[], "text/markdown", None),
            make_object(1, Some("Alpha"), "alpha", &[], "text/markdown", None),
            make_object(3, None, "untitled", &[], "text/markdown", None),
        ];

        sort_content_items(
            &mut items,
            ContentSortField::Title,
            ContentSortDirection::Asc,
        );

        let ids: Vec<u64> = items.iter().map(|item| item.key.id.0).collect();
        assert_eq!(ids, vec![1, 2, 4, 5, 3]);
    }

    #[test]
    fn sorts_by_title_desc_with_nulls_last_and_id_tiebreaker() {
        let mut items = vec![
            make_object(2, Some("Beta"), "beta", &[], "text/markdown", None),
            make_object(5, Some("Same"), "same-b", &[], "text/markdown", None),
            make_object(4, Some("Same"), "same-a", &[], "text/markdown", None),
            make_object(1, Some("Alpha"), "alpha", &[], "text/markdown", None),
            make_object(3, None, "untitled", &[], "text/markdown", None),
        ];

        sort_content_items(
            &mut items,
            ContentSortField::Title,
            ContentSortDirection::Desc,
        );

        let ids: Vec<u64> = items.iter().map(|item| item.key.id.0).collect();
        assert_eq!(ids, vec![4, 5, 2, 1, 3]);
    }

    #[test]
    fn sorts_by_tags_with_empty_last() {
        let mut items = vec![
            make_object(1, Some("Beta"), "beta", &["beta"], "text/markdown", None),
            make_object(2, Some("Alpha"), "alpha", &["alpha"], "text/markdown", None),
            make_object(3, Some("Empty"), "empty", &[], "text/markdown", None),
        ];

        sort_content_items(
            &mut items,
            ContentSortField::Tags,
            ContentSortDirection::Asc,
        );

        let ids: Vec<u64> = items.iter().map(|item| item.key.id.0).collect();
        assert_eq!(ids, vec![2, 1, 3]);
    }

    #[test]
    fn rejects_unknown_sort_field() {
        let mut writer = WireWriter::new();
        writer.write_u32(99);
        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        let err = ContentSortField::decode(&mut reader).unwrap_err();
        assert!(err.to_string().contains("Unknown sort field"));
    }

    #[test]
    fn rejects_unknown_sort_direction() {
        let mut writer = WireWriter::new();
        writer.write_u32(42);
        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        let err = ContentSortDirection::decode(&mut reader).unwrap_err();
        assert!(err.to_string().contains("Unknown sort direction"));
    }
}
