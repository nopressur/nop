// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::cache;
use crate::capabilities::{PageCacheAccess, ReleaseTrackerAccess, SearchServiceAccess};
use nop_content_store::flat_storage::{ContentId, ContentSidecar, ContentVersion, content_id_hex};
use nop_rt_search_service::{UpsertMarkdownFromDiskRequest, UpsertMarkdownInMemoryRequest};

pub fn enqueue_markdown_upsert_in_memory<C>(
    context: &C,
    id: ContentId,
    version: ContentVersion,
    sidecar: &ContentSidecar,
    body: String,
    source: &str,
) where
    C: SearchServiceAccess,
{
    if sidecar.mime.trim() != "text/markdown" {
        return;
    }
    let Some(search_service) = context.search_service() else {
        return;
    };
    let Some(title) = sidecar.title.as_ref() else {
        log::warn!(
            "Search enqueue skipped for {} id={} due to missing markdown title",
            source,
            content_id_hex(id)
        );
        return;
    };
    let request = UpsertMarkdownInMemoryRequest {
        id,
        version,
        alias: sidecar.alias.clone(),
        title: title.clone(),
        tags: sidecar.tags.clone(),
        body,
    };
    if let Err(err) = search_service.enqueue_upsert_markdown_in_memory(request) {
        log::warn!(
            "Search enqueue failed for {} id={} version={}: {}",
            source,
            content_id_hex(id),
            version.0,
            err
        );
    }
}

pub fn enqueue_markdown_upsert_from_disk<C>(
    context: &C,
    id: ContentId,
    version: ContentVersion,
    is_markdown: bool,
    source: &str,
) where
    C: SearchServiceAccess,
{
    if !is_markdown {
        return;
    }
    let Some(search_service) = context.search_service() else {
        return;
    };
    if let Err(err) = search_service
        .enqueue_upsert_markdown_from_disk(UpsertMarkdownFromDiskRequest { id, version })
    {
        log::warn!(
            "Search enqueue failed for {} id={} version={}: {}",
            source,
            content_id_hex(id),
            version.0,
            err
        );
    }
}

pub fn enqueue_markdown_delete<C>(context: &C, id: ContentId, is_markdown: bool, source: &str)
where
    C: SearchServiceAccess,
{
    if !is_markdown {
        return;
    }
    let Some(search_service) = context.search_service() else {
        return;
    };
    if let Err(err) = search_service.enqueue_delete_markdown(id) {
        log::warn!(
            "Search enqueue failed for {} id={}: {}",
            source,
            content_id_hex(id),
            err
        );
    }
}

pub async fn invalidate_cache<C>(context: &C)
where
    C: PageCacheAccess,
{
    cache::invalidate_cache(context).await;
}

pub fn bump_release_tracker_for_nav_change<C>(context: &C, content_id: ContentId)
where
    C: ReleaseTrackerAccess,
{
    if let Some(tracker) = context.release_tracker() {
        tracker.bump(&format!("nav updated ({})", content_id_hex(content_id)));
    }
}
