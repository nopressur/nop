// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use async_trait::async_trait;
use nop_config::ValidatedConfig;
use nop_roles::TagRoleRecord;
use nop_rt_page_cache::PageMetaCache;
use nop_rt_paths::RuntimePaths;
use nop_rt_release::ReleaseTracker;
use nop_rt_search_service::SearchService;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct UserRoleEntry {
    pub email: String,
    pub roles: Vec<String>,
}

pub trait RoleStoreAccess {
    fn roles_snapshot(&self) -> Result<BTreeSet<String>, String>;
    fn persist_roles(&self, roles: BTreeSet<String>) -> Result<(), String>;
}

pub trait TagStoreAccess {
    fn tags_snapshot(&self) -> Result<BTreeMap<String, TagRoleRecord>, String>;
    fn persist_tags(&self, tags: BTreeMap<String, TagRoleRecord>) -> Result<(), String>;
}

#[async_trait]
pub trait UserServicesAccess {
    async fn list_user_roles(&self) -> Result<Vec<UserRoleEntry>, String>;
    async fn update_user_roles(&self, email: &str, roles: Vec<String>) -> Result<(), String>;
}

pub trait PageCacheAccess {
    fn page_cache(&self) -> Option<&Arc<PageMetaCache>>;
    fn runtime_paths(&self) -> &RuntimePaths;
}

pub trait SearchServiceAccess {
    fn search_service(&self) -> Option<&Arc<SearchService>>;
}

pub trait ReleaseTrackerAccess {
    fn release_tracker(&self) -> Option<&Arc<ReleaseTracker>>;
}

pub trait ConfigAccess {
    fn config(&self) -> &ValidatedConfig;
}
