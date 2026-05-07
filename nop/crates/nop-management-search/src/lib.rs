// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop_content_store::flat_storage::{ContentId, content_id_hex, parse_content_id_hex};
use nop_management_contract::content::ContentSummary;
pub use nop_management_contract::search::{
    SEARCH_ACTION_FIND, SEARCH_ACTION_FIND_ERR, SEARCH_ACTION_FIND_OK, SEARCH_ACTION_INVALIDATE,
    SEARCH_ACTION_INVALIDATE_ERR, SEARCH_ACTION_INVALIDATE_OK, SEARCH_ACTION_RESET,
    SEARCH_ACTION_RESET_ERR, SEARCH_ACTION_RESET_OK, SEARCH_DOMAIN_ID, SearchCommand,
    SearchFindRequest, SearchFindResponse, SearchInvalidateRequest, SearchResetRequest,
};
use nop_management_contract::{
    FieldLimit, FieldLimits, FieldValues, ManagementCommand, ManagementRequest, ManagementResponse,
    ResponsePayload, define_domain_responses, define_message_response_codec, define_request_codec,
    define_response_codec,
};
use nop_management_errors::DomainResult;
use nop_management_workflows::cache as workflow_cache;
use nop_management_workflows::capabilities::{ConfigAccess, PageCacheAccess, SearchServiceAccess};
use nop_rt_page_cache::CachedObject;
use nop_rt_search_service::{QueryAdminRequest, ReindexReason, UpsertMarkdownFromDiskRequest};
use std::cmp::Ordering;
use std::collections::HashSet;

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

pub trait SearchContext: ConfigAccess + PageCacheAccess + SearchServiceAccess {}

impl<T> SearchContext for T where T: ConfigAccess + PageCacheAccess + SearchServiceAccess {}

fn content_summary_from_object(object: &CachedObject) -> ContentSummary {
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

fn validate_search_find(request: &SearchFindRequest) -> Result<(), String> {
    let query = request.query.trim();
    let query_len = query.chars().count();
    if !(MIN_QUERY_CHARS..=MAX_QUERY_CHARS).contains(&query_len) {
        return Err(format!(
            "Query must be between {} and {} characters",
            MIN_QUERY_CHARS, MAX_QUERY_CHARS
        ));
    }
    if let Some(tags) = &request.tags {
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

fn validate_search_invalidate(request: &SearchInvalidateRequest) -> Result<ContentId, String> {
    let trimmed = request.id.trim();
    if trimmed.is_empty() {
        return Err("Content ID is required".to_string());
    }
    parse_content_id_hex(trimmed)
}

fn validate_search_reset(_request: &SearchResetRequest) -> Result<(), String> {
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
    validate = |request| validate_search_find(request),
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
    validate = |request| validate_search_invalidate(request),
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
    validate = |request| validate_search_reset(request),
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

pub async fn handle_search_request<C>(
    request: ManagementRequest,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: SearchContext,
{
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
        SearchCommand::Find(payload) => handle_find(payload, workflow_id, context).await,
        SearchCommand::Invalidate(payload) => {
            handle_invalidate(payload, workflow_id, context).await
        }
        SearchCommand::Reset(payload) => handle_reset(payload, workflow_id, context).await,
    };

    Ok(response)
}

async fn handle_find<C>(
    payload: SearchFindRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: SearchContext,
{
    if let Err(err) = validate_search_find(&payload) {
        return response_err(SEARCH_ACTION_FIND_ERR, workflow_id, &err);
    }
    let Some(search_service) = context.search_service() else {
        return response_err(
            SEARCH_ACTION_FIND_ERR,
            workflow_id,
            "Search service unavailable",
        );
    };

    let cache = match workflow_cache::load_page_cache(context).await {
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

async fn handle_invalidate<C>(
    payload: SearchInvalidateRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: SearchContext,
{
    let content_id = match validate_search_invalidate(&payload) {
        Ok(id) => id,
        Err(err) => return response_err(SEARCH_ACTION_INVALIDATE_ERR, workflow_id, &err),
    };
    let Some(search_service) = context.search_service() else {
        return response_err(
            SEARCH_ACTION_INVALIDATE_ERR,
            workflow_id,
            "Search service unavailable",
        );
    };

    let cache = match workflow_cache::load_page_cache(context).await {
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

async fn handle_reset<C>(
    _payload: SearchResetRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: SearchContext,
{
    let Some(search_service) = context.search_service() else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use nop_config::{Config, ValidatedConfig};
    use nop_content_store::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use nop_content_store::reserved_paths::ReservedPaths;
    use nop_management_workflows::capabilities::{
        ConfigAccess, PageCacheAccess, SearchServiceAccess,
    };
    use nop_rt_page_cache::PageMetaCache;
    use nop_rt_paths::RuntimePaths;
    use nop_rt_search_service::{SearchService, initialize};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;

    struct TestContext {
        config: Arc<ValidatedConfig>,
        runtime_paths: RuntimePaths,
        page_cache: Option<Arc<PageMetaCache>>,
        search_service: Option<Arc<SearchService>>,
    }

    impl ConfigAccess for TestContext {
        fn config(&self) -> &ValidatedConfig {
            self.config.as_ref()
        }
    }

    impl PageCacheAccess for TestContext {
        fn page_cache(&self) -> Option<&Arc<PageMetaCache>> {
            self.page_cache.as_ref()
        }

        fn runtime_paths(&self) -> &RuntimePaths {
            &self.runtime_paths
        }
    }

    impl SearchServiceAccess for TestContext {
        fn search_service(&self) -> Option<&Arc<SearchService>> {
            self.search_service.as_ref()
        }
    }

    fn load_test_config(root: &Path) -> Arc<ValidatedConfig> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let config_path = manifest_dir.join("../../../examples/config.yaml.example");
        let users_path = manifest_dir.join("../../../examples/users.yaml.example");
        let config = std::fs::read_to_string(&config_path).expect("read config example");
        let users = std::fs::read_to_string(&users_path).expect("read users example");
        std::fs::write(root.join("config.yaml"), config).expect("write config");
        std::fs::write(root.join("users.yaml"), users).expect("write users");
        Arc::new(Config::load_and_validate(root).expect("validate config"))
    }

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
        assert!(validate_search_find(&request).is_err());
    }

    #[test]
    fn find_validation_reports_query_bounds() {
        let request = SearchFindRequest {
            query: "hi".to_string(),
            tags: None,
            markdown_only: false,
        };
        let err = validate_search_find(&request).expect_err("expected bounds error");
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
        assert!(validate_search_find(&request).is_ok());
    }

    #[test]
    fn find_validation_rejects_empty_tags() {
        let request = SearchFindRequest {
            query: "valid".to_string(),
            tags: Some(Vec::new()),
            markdown_only: false,
        };
        let err = validate_search_find(&request).expect_err("expected empty tags error");
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
        let err = validate_tags(&["BadTag".to_string()]).expect_err("expected invalid tag");
        assert!(err.contains("Invalid tag id"));
    }

    #[test]
    fn validate_tags_accepts_allowed_characters() {
        validate_tags(&["tag-a_b/1".to_string()]).expect("valid tag");
    }

    #[tokio::test]
    async fn search_find_merges_title_and_relevance_hits() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config = load_test_config(temp_dir.path());
        let runtime_paths =
            RuntimePaths::from_root(temp_dir.path(), &config).expect("runtime paths");

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
        let context = TestContext {
            config,
            runtime_paths,
            page_cache: Some(page_cache),
            search_service: Some(search_startup.service.clone()),
        };

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
        let err = validate_search_invalidate(&request).expect_err("expected id error");
        assert!(err.to_ascii_lowercase().contains("content id"));
    }
}
