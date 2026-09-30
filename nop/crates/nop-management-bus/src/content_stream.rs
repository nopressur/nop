// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::core::ManagementContext;
use crate::ws::{BlobStreamProducer, StreamError, StreamErrorKind};
use nop_content_store::flat_storage::{blob_path, parse_content_id_hex};
use nop_content_store::reserved_paths::ReservedPaths;
use nop_management_contract::{ManagementResponse, ResponsePayload};
use nop_rt_page_cache::PageMetaCache;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentStreamPlan {
    pub content_id: String,
    pub stream_id: u32,
    pub chunk_bytes: u32,
    pub size_bytes: u64,
}

pub fn assign_content_stream_id(
    response: &mut ManagementResponse,
    stream_id: u32,
) -> Option<ContentStreamPlan> {
    match &mut response.payload {
        ResponsePayload::ContentRead(payload) => {
            if payload.content.is_some() {
                return None;
            }
            let chunk_bytes = payload.chunk_bytes?;
            let size_bytes = payload.size_bytes?;
            payload.stream_id = Some(stream_id);
            Some(ContentStreamPlan {
                content_id: payload.id.clone(),
                stream_id,
                chunk_bytes,
                size_bytes,
            })
        }
        _ => None,
    }
}

pub async fn open_content_blob_stream(
    context: &ManagementContext,
    plan: &ContentStreamPlan,
) -> Result<BlobStreamProducer, StreamError> {
    let content_id = parse_content_id_hex(&plan.content_id).map_err(|err| {
        StreamError::new(
            StreamErrorKind::UnknownStream,
            format!("Invalid content id for streaming: {}", err),
        )
    })?;
    let cache = get_cache_for_stream(context).await?;
    let object = cache.get_by_id(content_id).ok_or_else(|| {
        StreamError::new(
            StreamErrorKind::UnknownStream,
            "Content not found for streaming",
        )
    })?;
    let path = blob_path(
        &context.runtime_paths.content_dir,
        object.key.id,
        object.key.version,
    );
    BlobStreamProducer::open_file(plan.stream_id, &path, plan.size_bytes, plan.chunk_bytes).await
}

async fn get_cache_for_stream(context: &ManagementContext) -> Result<PageMetaCache, StreamError> {
    if let Some(cache) = context.page_cache.as_ref() {
        return Ok(cache.as_ref().clone());
    }

    let cache = PageMetaCache::new(
        context.runtime_paths.content_dir.clone(),
        context.runtime_paths.state_sys_dir.clone(),
        ReservedPaths::from_config(&context.config),
    );
    cache.rebuild_cache(true).await.map_err(|err| {
        StreamError::new(
            StreamErrorKind::SourceReadFailed,
            format!("Failed to rebuild cache: {}", err),
        )
    })?;
    Ok(cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_content_store::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use nop_management_contract::content::{
        CONTENT_ACTION_READ_OK, CONTENT_DOMAIN_ID, ContentReadResponse, ContentWidthMode,
    };
    use nop_testing::test_config::TestConfigBuilder;
    use nop_testing::test_runtime_paths::short_runtime_paths;

    #[test]
    fn assign_content_stream_id_ignores_inline_content() {
        let mut response = ManagementResponse {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ_OK,
            workflow_id: 4,
            payload: ResponsePayload::ContentRead(Box::new(ContentReadResponse {
                id: "0000000000000001".to_string(),
                alias: "docs/small".to_string(),
                title: Some("Small".to_string()),
                mime: "text/markdown".to_string(),
                tags: Vec::new(),
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
                disable_navbar: false,
                disable_floating_nav: false,
                content_width: ContentWidthMode::Auto,
                content: Some("# Small".to_string()),
                stream_id: None,
                chunk_bytes: None,
                size_bytes: None,
            })),
        };

        assert_eq!(assign_content_stream_id(&mut response, 11), None);
    }

    #[test]
    fn assign_content_stream_id_sets_connector_stream_id() {
        let mut response = ManagementResponse {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ_OK,
            workflow_id: 4,
            payload: ResponsePayload::ContentRead(Box::new(ContentReadResponse {
                id: "0000000000000001".to_string(),
                alias: "assets/blob".to_string(),
                title: None,
                mime: "application/octet-stream".to_string(),
                tags: Vec::new(),
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
                disable_navbar: false,
                disable_floating_nav: false,
                content_width: ContentWidthMode::Auto,
                content: None,
                stream_id: None,
                chunk_bytes: Some(64),
                size_bytes: Some(1024),
            })),
        };

        let plan = assign_content_stream_id(&mut response, 0x8000_0000).expect("stream plan");
        assert_eq!(
            plan,
            ContentStreamPlan {
                content_id: "0000000000000001".to_string(),
                stream_id: 0x8000_0000,
                chunk_bytes: 64,
                size_bytes: 1024,
            }
        );
        assert_eq!(
            assign_content_stream_id(&mut response, 0x8000_0001),
            Some(ContentStreamPlan {
                content_id: "0000000000000001".to_string(),
                stream_id: 0x8000_0001,
                chunk_bytes: 64,
                size_bytes: 1024,
            })
        );
    }

    #[tokio::test]
    async fn open_content_blob_stream_reads_cached_content_blob() {
        let (_temp, runtime_paths) = short_runtime_paths("content-stream-producer");
        let content_id = ContentId(1);
        let version = ContentVersion(0);
        let body = b"abcdef";
        tokio::fs::create_dir_all(
            blob_path(&runtime_paths.content_dir, content_id, version)
                .parent()
                .unwrap(),
        )
        .await
        .expect("create shard");
        tokio::fs::write(
            blob_path(&runtime_paths.content_dir, content_id, version),
            body,
        )
        .await
        .expect("write blob");
        let sidecar = ContentSidecar {
            alias: "docs/blob".to_string(),
            title: Some("Blob".to_string()),
            mime: "text/markdown".to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            theme: None,
            disable_navbar: false,
            disable_floating_nav: false,
            content_width: Default::default(),
        };
        write_sidecar_atomic(
            &sidecar_path(&runtime_paths.content_dir, content_id, version),
            &sidecar,
        )
        .expect("write sidecar");
        let config = TestConfigBuilder::new().build();
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(config),
            runtime_paths,
        )
        .expect("context");
        let plan = ContentStreamPlan {
            content_id: "0000000000000001".to_string(),
            stream_id: 3,
            chunk_bytes: 3,
            size_bytes: body.len() as u64,
        };

        let mut producer = open_content_blob_stream(&context, &plan)
            .await
            .expect("producer");
        let first = producer
            .next_chunk()
            .await
            .expect("first result")
            .expect("first chunk");
        let second = producer
            .next_chunk()
            .await
            .expect("second result")
            .expect("second chunk");
        assert_eq!(first.payload, b"abc");
        assert_eq!(second.payload, b"def");
        assert!(second.is_final());
    }
}
