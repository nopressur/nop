// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::{ContentId, content_id_hex, parse_content_id_hex};
use crate::content::reserved_paths::ReservedPaths;
use crate::management::codec::{FieldLimit, FieldLimits, FieldValues};
use crate::management::content::{ContentSummary, content_summary_from_object};
use crate::management::core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse, ResponsePayload,
};
use crate::management::errors::DomainResult;
use crate::management::registry::{DomainActionKey, ManagementHandler, ManagementRegistry};
use crate::management::{OptionMap, WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use crate::public::page_meta_cache::PageMetaCache;
use crate::public::page_meta_cache::cache::CachedObject;
use crate::search::{QueryAdminRequest, ReindexReason, UpsertMarkdownFromDiskRequest};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;

pub const SEARCH_DOMAIN_ID: u32 = 21;

pub const SEARCH_ACTION_FIND: u32 = 1;
pub const SEARCH_ACTION_INVALIDATE: u32 = 2;
pub const SEARCH_ACTION_RESET: u32 = 3;

pub const SEARCH_ACTION_FIND_OK: u32 = 101;
pub const SEARCH_ACTION_FIND_ERR: u32 = 102;
pub const SEARCH_ACTION_INVALIDATE_OK: u32 = 201;
pub const SEARCH_ACTION_INVALIDATE_ERR: u32 = 202;
pub const SEARCH_ACTION_RESET_OK: u32 = 301;
pub const SEARCH_ACTION_RESET_ERR: u32 = 302;

pub const MAX_QUERY_CHARS: usize = 256;
pub const MIN_QUERY_CHARS: usize = 3;
const MAX_TAG_COUNT: usize = 256;
const MAX_TAG_CHARS: usize = 128;
const MAX_HITS: usize = 128;
const MAX_ID_CHARS: usize = 16;
const MAX_ALIAS_CHARS: usize = 512;
const MAX_TITLE_CHARS: usize = 256;
const MAX_MIME_CHARS: usize = 128;
const MAX_NAV_PARENT_CHARS: usize = 16;
const MAX_ORIGINAL_FILENAME_CHARS: usize = 512;

#[derive(Debug, Clone)]
pub enum SearchCommand {
    Find(SearchFindRequest),
    Invalidate(SearchInvalidateRequest),
    Reset(SearchResetRequest),
}

impl SearchCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            SearchCommand::Find(_) => SEARCH_ACTION_FIND,
            SearchCommand::Invalidate(_) => SEARCH_ACTION_INVALIDATE,
            SearchCommand::Reset(_) => SEARCH_ACTION_RESET,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFindRequest {
    pub query: String,
    pub tags: Option<Vec<String>>,
    pub markdown_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFindResponse {
    pub hits: Vec<ContentSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchInvalidateRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResetRequest {}

impl WireEncode for SearchFindRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.tags.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.query)?;
        writer.write_bool(self.markdown_only);
        if let Some(tags) = &self.tags {
            writer.write_vec(tags, |writer, tag| writer.write_string(tag))?;
        }
        Ok(())
    }
}

impl WireDecode for SearchFindRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        let query = reader.read_string()?;
        let markdown_only = reader.read_bool()?;
        let tags = if flags[0] {
            Some(reader.read_vec(|reader| reader.read_string())?)
        } else {
            None
        };
        Ok(Self {
            query,
            tags,
            markdown_only,
        })
    }
}

impl WireEncode for SearchFindResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_vec(&self.hits, |writer, item| item.encode(writer))
    }
}

impl WireDecode for SearchFindResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let hits = reader.read_vec(|reader| ContentSummary::decode(reader))?;
        Ok(Self { hits })
    }
}

impl WireEncode for SearchInvalidateRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.id)?;
        Ok(())
    }
}

impl WireDecode for SearchInvalidateRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let id = reader.read_string()?;
        Ok(Self { id })
    }
}

impl WireEncode for SearchResetRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for SearchResetRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl SearchFindRequest {
    fn validate(&self) -> Result<(), String> {
        let query = self.query.trim();
        let query_len = query.chars().count();
        if !(MIN_QUERY_CHARS..=MAX_QUERY_CHARS).contains(&query_len) {
            return Err(format!(
                "Query must be between {} and {} characters",
                MIN_QUERY_CHARS, MAX_QUERY_CHARS
            ));
        }
        if let Some(tags) = &self.tags {
            if tags.is_empty() {
                return Err("Tags cannot be empty".to_string());
            }
            if tags.iter().any(|tag| tag.trim().is_empty()) {
                return Err("Tag cannot be empty".to_string());
            }
            validate_tags(tags)?;
        }
        Ok(())
    }
}

impl SearchInvalidateRequest {
    fn validate(&self) -> Result<ContentId, String> {
        let trimmed = self.id.trim();
        if trimmed.is_empty() {
            return Err("Content ID is required".to_string());
        }
        parse_content_id_hex(trimmed)
    }
}

impl SearchResetRequest {
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), crate::management::RegistryError> {
    registry.register_domain(crate::management::registry::DomainDescriptor {
        name: "search",
        id: SEARCH_DOMAIN_ID,
        actions: vec![
            crate::management::registry::ActionDescriptor {
                name: "find",
                id: SEARCH_ACTION_FIND,
            },
            crate::management::registry::ActionDescriptor {
                name: "invalidate",
                id: SEARCH_ACTION_INVALIDATE,
            },
            crate::management::registry::ActionDescriptor {
                name: "reset",
                id: SEARCH_ACTION_RESET,
            },
            crate::management::registry::ActionDescriptor {
                name: "find_ok",
                id: SEARCH_ACTION_FIND_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "find_err",
                id: SEARCH_ACTION_FIND_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "invalidate_ok",
                id: SEARCH_ACTION_INVALIDATE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "invalidate_err",
                id: SEARCH_ACTION_INVALIDATE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "reset_ok",
                id: SEARCH_ACTION_RESET_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "reset_err",
                id: SEARCH_ACTION_RESET_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_search_request(request, context).await })
    });
    registry.register_handler(
        DomainActionKey::new(SEARCH_DOMAIN_ID, SEARCH_ACTION_FIND),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SEARCH_DOMAIN_ID, SEARCH_ACTION_INVALIDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SEARCH_DOMAIN_ID, SEARCH_ACTION_RESET),
        handler,
    )?;

    register_request_codecs!(
        registry,
        [
            SearchFindRequestCodec,
            SearchInvalidateRequestCodec,
            SearchResetRequestCodec
        ]
    );

    register_response_codecs!(
        registry,
        [
            SearchFindResponseCodec,
            MessageResponseCodec::new(SEARCH_ACTION_FIND_ERR),
            MessageResponseCodec::new(SEARCH_ACTION_INVALIDATE_OK),
            MessageResponseCodec::new(SEARCH_ACTION_INVALIDATE_ERR),
            MessageResponseCodec::new(SEARCH_ACTION_RESET_OK),
            MessageResponseCodec::new(SEARCH_ACTION_RESET_ERR)
        ]
    );

    Ok(())
}

define_domain_responses!(SEARCH_DOMAIN_ID);

define_message_response_codec!(
    MessageResponseCodec,
    domain_id = SEARCH_DOMAIN_ID,
    error = "Unsupported response payload for search message codec",
);

define_request_codec!(
    SearchFindRequestCodec,
    domain = Search,
    command = SearchCommand,
    variant = Find,
    domain_id = SEARCH_DOMAIN_ID,
    action_id = SEARCH_ACTION_FIND,
    request = SearchFindRequest,
    limits = FieldLimits::new(vec![
        (
            "query",
            FieldLimit::Range {
                min: MIN_QUERY_CHARS,
                max: MAX_QUERY_CHARS,
            },
        ),
        ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
        ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
    ]),
    values = |request| {
        let mut values = FieldValues::new();
        values.insert_len("query", request.query.chars().count());
        if let Some(tags) = &request.tags {
            values.insert_count("tags", tags.len());
            values.insert_lens("tag", tags.iter().map(|tag| tag.chars().count()).collect());
        }
        values
    },
    error = "Unsupported request payload for search find codec",
);

define_request_codec!(
    SearchInvalidateRequestCodec,
    domain = Search,
    command = SearchCommand,
    variant = Invalidate,
    domain_id = SEARCH_DOMAIN_ID,
    action_id = SEARCH_ACTION_INVALIDATE,
    request = SearchInvalidateRequest,
    limits = FieldLimits::new(vec![("id", FieldLimit::MaxChars(MAX_ID_CHARS))]),
    values = |request| {
        let mut values = FieldValues::new();
        values.insert_len("id", request.id.chars().count());
        values
    },
    error = "Unsupported request payload for search invalidate codec",
);

define_request_codec!(
    SearchResetRequestCodec,
    domain = Search,
    command = SearchCommand,
    variant = Reset,
    domain_id = SEARCH_DOMAIN_ID,
    action_id = SEARCH_ACTION_RESET,
    request = SearchResetRequest,
    limits = FieldLimits::new(vec![]),
    values = |_request| FieldValues::new(),
    error = "Unsupported request payload for search reset codec",
);

define_response_codec!(
    SearchFindResponseCodec,
    domain_id = SEARCH_DOMAIN_ID,
    action_id = SEARCH_ACTION_FIND_OK,
    payload = SearchFind,
    response = SearchFindResponse,
    limits = FieldLimits::new(vec![
        ("hits", FieldLimit::MaxEntries(MAX_HITS)),
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
    ]),
    values = |payload| {
        let mut values = FieldValues::new();
        values.insert_count("hits", payload.hits.len());
        values.insert_lens(
            "id",
            payload
                .hits
                .iter()
                .map(|item| item.id.chars().count())
                .collect(),
        );
        values.insert_lens(
            "alias",
            payload
                .hits
                .iter()
                .map(|item| item.alias.chars().count())
                .collect(),
        );
        values.insert_lens(
            "title",
            payload
                .hits
                .iter()
                .map(|item| {
                    item.title
                        .as_ref()
                        .map(|value| value.chars().count())
                        .unwrap_or(0)
                })
                .collect(),
        );
        values.insert_lens(
            "tags",
            payload.hits.iter().map(|item| item.tags.len()).collect(),
        );
        values.insert_lens(
            "tag",
            payload
                .hits
                .iter()
                .flat_map(|item| item.tags.iter())
                .map(|tag| tag.chars().count())
                .collect(),
        );
        values.insert_lens(
            "mime",
            payload
                .hits
                .iter()
                .map(|item| item.mime.chars().count())
                .collect(),
        );
        values.insert_lens(
            "nav_title",
            payload
                .hits
                .iter()
                .map(|item| {
                    item.nav_title
                        .as_ref()
                        .map(|value| value.chars().count())
                        .unwrap_or(0)
                })
                .collect(),
        );
        values.insert_lens(
            "nav_parent_id",
            payload
                .hits
                .iter()
                .map(|item| {
                    item.nav_parent_id
                        .as_ref()
                        .map(|value| value.chars().count())
                        .unwrap_or(0)
                })
                .collect(),
        );
        values.insert_lens(
            "original_filename",
            payload
                .hits
                .iter()
                .map(|item| {
                    item.original_filename
                        .as_ref()
                        .map(|value| value.chars().count())
                        .unwrap_or(0)
                })
                .collect(),
        );
        values
    },
    error = "Unsupported response payload for search find codec",
);

async fn handle_search_request(
    request: ManagementRequest,
    context: Arc<ManagementContext>,
) -> DomainResult<ManagementResponse> {
    let workflow_id = request.workflow_id;
    let command = match request.command {
        ManagementCommand::Search(command) => command,
        _ => {
            return Ok(response_err(
                SEARCH_ACTION_FIND_ERR,
                workflow_id,
                "Invalid search command",
            ));
        }
    };

    let response = match command {
        SearchCommand::Find(payload) => handle_find(payload, workflow_id, context.as_ref()).await,
        SearchCommand::Invalidate(payload) => {
            handle_invalidate(payload, workflow_id, context.as_ref()).await
        }
        SearchCommand::Reset(payload) => handle_reset(payload, workflow_id, context.as_ref()).await,
    };

    Ok(response)
}

async fn handle_find(
    payload: SearchFindRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(SEARCH_ACTION_FIND_ERR, workflow_id, &err);
    }
    let Some(search_service) = context.search_service.as_ref() else {
        return response_err(
            SEARCH_ACTION_FIND_ERR,
            workflow_id,
            "Search service unavailable",
        );
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(SEARCH_ACTION_FIND_ERR, workflow_id, &err),
    };

    let trimmed_query = payload.query.trim();
    let needle = trimmed_query.to_ascii_lowercase();
    let tag_filter = payload.tags.as_ref().map(|tags| {
        tags.iter()
            .map(|tag| tag.to_ascii_lowercase())
            .collect::<Vec<String>>()
    });

    let mut title_hits: Vec<ContentSummary> = cache
        .list_objects()
        .into_iter()
        .filter(|object| matches_filters(object, payload.markdown_only, tag_filter.as_deref()))
        .filter(|object| {
            object
                .title
                .as_ref()
                .map(|title| title.to_ascii_lowercase().contains(&needle))
                .unwrap_or(false)
        })
        .map(|object| content_summary_from_object(&object))
        .collect();
    sort_by_title_then_id(&mut title_hits);

    let relevance_hits = match search_service.query_admin(QueryAdminRequest {
        query: trimmed_query.to_string(),
        tags: tag_filter.clone(),
    }) {
        Ok(hits) => hits,
        Err(err) => return response_err(SEARCH_ACTION_FIND_ERR, workflow_id, &err),
    };

    let mut seen = HashSet::new();
    let mut merged = Vec::new();
    for item in title_hits {
        seen.insert(item.id.clone());
        merged.push(item);
        if merged.len() >= MAX_HITS {
            break;
        }
    }

    if merged.len() < MAX_HITS {
        for hit in relevance_hits {
            if merged.len() >= MAX_HITS {
                break;
            }
            if seen.contains(&hit.id) {
                continue;
            }
            let content_id = match parse_content_id_hex(&hit.id) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let Some(object) = cache.get_by_id(content_id) else {
                continue;
            };
            if payload.markdown_only && !object.is_markdown {
                continue;
            }
            let item = content_summary_from_object(&object);
            seen.insert(hit.id);
            merged.push(item);
        }
    }

    ManagementResponse {
        domain_id: SEARCH_DOMAIN_ID,
        action_id: SEARCH_ACTION_FIND_OK,
        workflow_id,
        payload: ResponsePayload::SearchFind(SearchFindResponse { hits: merged }),
    }
}

async fn handle_invalidate(
    payload: SearchInvalidateRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let content_id = match payload.validate() {
        Ok(id) => id,
        Err(err) => return response_err(SEARCH_ACTION_INVALIDATE_ERR, workflow_id, &err),
    };
    let Some(search_service) = context.search_service.as_ref() else {
        return response_err(
            SEARCH_ACTION_INVALIDATE_ERR,
            workflow_id,
            "Search service unavailable",
        );
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(SEARCH_ACTION_INVALIDATE_ERR, workflow_id, &err),
    };
    let Some(object) = cache.get_by_id(content_id) else {
        return response_err(
            SEARCH_ACTION_INVALIDATE_ERR,
            workflow_id,
            "Content not found",
        );
    };
    if !object.is_markdown {
        return response_err(
            SEARCH_ACTION_INVALIDATE_ERR,
            workflow_id,
            "Search invalidation is only supported for markdown content",
        );
    }

    if let Err(err) =
        search_service.enqueue_upsert_markdown_from_disk(UpsertMarkdownFromDiskRequest {
            id: content_id,
            version: object.key.version,
        })
    {
        return response_err(SEARCH_ACTION_INVALIDATE_ERR, workflow_id, &err);
    }

    response_ok(
        SEARCH_ACTION_INVALIDATE_OK,
        workflow_id,
        &format!("Search invalidated for {}", content_id_hex(content_id)),
    )
}

async fn handle_reset(
    _payload: SearchResetRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let Some(search_service) = context.search_service.as_ref() else {
        return response_err(
            SEARCH_ACTION_RESET_ERR,
            workflow_id,
            "Search service unavailable",
        );
    };

    if let Err(err) = search_service.reindex_all_markdown(ReindexReason::Forced) {
        return response_err(SEARCH_ACTION_RESET_ERR, workflow_id, &err);
    }

    response_ok(
        SEARCH_ACTION_RESET_OK,
        workflow_id,
        "Search reset completed",
    )
}

fn matches_filters(object: &CachedObject, markdown_only: bool, tags: Option<&[String]>) -> bool {
    if markdown_only && !object.is_markdown {
        return false;
    }
    if let Some(filter_tags) = tags
        && !filter_tags
            .iter()
            .all(|tag| object.tags.iter().any(|item| item == tag))
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use crate::public::page_meta_cache::PageMetaCache;
    use crate::runtime_paths::RuntimePaths;
    use crate::search::initialize;
    use crate::util::test_config::TestConfigBuilder;
    use crate::util::test_fixtures::TestFixtureRoot;
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

    #[test]
    fn find_validation_rejects_short_query() {
        let request = SearchFindRequest {
            query: "hi".to_string(),
            tags: None,
            markdown_only: false,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn find_validation_reports_query_bounds() {
        let request = SearchFindRequest {
            query: "hi".to_string(),
            tags: None,
            markdown_only: false,
        };
        let err = request.validate().expect_err("expected bounds error");
        assert_eq!(
            err,
            format!(
                "Query must be between {} and {} characters",
                MIN_QUERY_CHARS, MAX_QUERY_CHARS
            )
        );
    }

    #[test]
    fn find_validation_accepts_trimmed_query() {
        let request = SearchFindRequest {
            query: "  valid query  ".to_string(),
            tags: None,
            markdown_only: false,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn find_validation_rejects_empty_tags() {
        let request = SearchFindRequest {
            query: "valid".to_string(),
            tags: Some(Vec::new()),
            markdown_only: false,
        };
        let err = request.validate().expect_err("expected empty tags error");
        assert!(err.to_ascii_lowercase().contains("tags"));
    }

    #[test]
    fn sort_by_title_then_id_orders_titles_and_ids() {
        fn summary(id: &str, title: Option<&str>) -> ContentSummary {
            ContentSummary {
                id: id.to_string(),
                alias: String::new(),
                title: title.map(|value| value.to_string()),
                mime: "text/markdown".to_string(),
                tags: Vec::new(),
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                is_markdown: true,
            }
        }

        let mut items = vec![
            summary("b", Some("Beta")),
            summary("a", Some("alpha")),
            summary("d", Some("alpha")),
            summary("c", None),
        ];
        sort_by_title_then_id(&mut items);

        let titles: Vec<Option<&str>> = items.iter().map(|item| item.title.as_deref()).collect();
        assert_eq!(
            titles,
            vec![Some("Beta"), Some("alpha"), Some("alpha"), None]
        );
        let ids: Vec<&str> = items.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "a", "d", "c"]);
    }

    #[test]
    fn validate_tags_rejects_invalid_characters() {
        let err = validate_tags(&vec!["BadTag".to_string()]).expect_err("expected invalid tag");
        assert!(err.contains("Invalid tag id"));
    }

    #[test]
    fn validate_tags_accepts_allowed_characters() {
        validate_tags(&vec!["tag-a_b/1".to_string()]).expect("valid tag");
    }

    #[actix_web::test]
    async fn search_find_merges_title_and_relevance_hits() {
        let fixture = TestFixtureRoot::new_unique("search-find-merge").expect("fixture");
        fixture.init_runtime_layout().expect("layout");
        let runtime_paths = fixture.runtime_paths().expect("paths");

        write_markdown(
            &runtime_paths,
            ContentId(10),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/title".to_string(),
                title: Some("Alpha Title".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["team".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "body",
        );
        write_markdown(
            &runtime_paths,
            ContentId(11),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/body".to_string(),
                title: Some("Zeta".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["team".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "alpha body match",
        );
        write_markdown(
            &runtime_paths,
            ContentId(12),
            ContentVersion(1),
            ContentSidecar {
                alias: "docs/other".to_string(),
                title: Some("Other".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["other".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            },
            "alpha body match",
        );

        let config = Arc::new(TestConfigBuilder::new().build());
        let page_cache = Arc::new(PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            ReservedPaths::from_config(&config),
        ));
        page_cache.rebuild_cache(true).await.expect("cache rebuild");

        let search_startup = initialize(
            &runtime_paths,
            &config.search,
            ReservedPaths::from_config(&config),
            false,
        )
        .expect("search startup");
        let context = ManagementContext::from_components_with_user_services_and_cache(
            runtime_paths.root.clone(),
            config,
            runtime_paths.clone(),
            None,
            Some(page_cache),
        )
        .expect("context")
        .with_search_service(search_startup.service.clone());

        let response = handle_find(
            SearchFindRequest {
                query: "alpha".to_string(),
                tags: Some(vec!["team".to_string()]),
                markdown_only: true,
            },
            1,
            &context,
        )
        .await;

        let ResponsePayload::SearchFind(payload) = response.payload else {
            panic!("unexpected response payload");
        };
        assert_eq!(payload.hits.len(), 2);
        assert_eq!(payload.hits[0].alias, "docs/title");
        assert_eq!(payload.hits[1].alias, "docs/body");
    }

    #[test]
    fn invalidate_validation_rejects_empty_id() {
        let request = SearchInvalidateRequest {
            id: " ".to_string(),
        };
        let err = request.validate().expect_err("expected id error");
        assert!(err.to_ascii_lowercase().contains("content id"));
    }
}

fn sort_by_title_then_id(items: &mut [ContentSummary]) {
    items.sort_by(|left, right| {
        let ordering = compare_optional_str(left.title.as_deref(), right.title.as_deref());
        ordering.then_with(|| left.id.cmp(&right.id))
    });
}

fn compare_optional_str(left: Option<&str>, right: Option<&str>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => left.cmp(right),
    }
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

async fn get_cache(context: &ManagementContext) -> Result<PageMetaCache, String> {
    if let Some(cache) = context.page_cache.as_ref() {
        return Ok(cache.as_ref().clone());
    }

    let cache = PageMetaCache::new(
        context.runtime_paths.content_dir.clone(),
        context.runtime_paths.state_sys_dir.clone(),
        ReservedPaths::from_config(&context.config),
    );
    cache
        .rebuild_cache(true)
        .await
        .map_err(|err| format!("Failed to rebuild cache: {}", err))?;
    Ok(cache)
}
