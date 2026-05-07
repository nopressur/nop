// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::capabilities::{ConfigAccess, PageCacheAccess};
use nop_content_store::reserved_paths::ReservedPaths;
use nop_rt_page_cache::PageMetaCache;

pub async fn load_page_cache<C>(context: &C) -> Result<PageMetaCache, String>
where
    C: PageCacheAccess + ConfigAccess,
{
    if let Some(cache) = context.page_cache() {
        return Ok(cache.as_ref().clone());
    }

    let runtime_paths = context.runtime_paths();
    let cache = PageMetaCache::new(
        runtime_paths.content_dir.clone(),
        runtime_paths.state_sys_dir.clone(),
        ReservedPaths::from_config(context.config()),
    );
    cache
        .rebuild_cache(true)
        .await
        .map_err(|err| format!("Failed to rebuild cache: {}", err))?;
    Ok(cache)
}

pub async fn invalidate_cache<C>(context: &C)
where
    C: PageCacheAccess,
{
    if let Some(cache) = context.page_cache()
        && let Err(err) = cache.invalidate().await
    {
        log::error!("Failed to invalidate page cache: {}", err);
    }
}
