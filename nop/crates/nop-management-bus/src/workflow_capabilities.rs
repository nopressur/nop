// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use async_trait::async_trait;
use nop_management_workflows::capabilities::{
    ConfigAccess, PageCacheAccess, ReleaseTrackerAccess, RoleStoreAccess, SearchServiceAccess,
    TagStoreAccess, UserRoleEntry, UserServicesAccess,
};
use nop_roles::TagRoleRecord;
use std::collections::{BTreeMap, BTreeSet};

use crate::core::ManagementContext;
use nop_management_tags::TagRecord;

fn to_tag_role_record(record: &TagRecord) -> TagRoleRecord {
    TagRoleRecord {
        name: record.name.clone(),
        roles: record.roles.clone(),
        access_rule: record.access_rule.clone(),
    }
}

fn from_tag_role_record(record: TagRoleRecord) -> TagRecord {
    TagRecord {
        name: record.name,
        roles: record.roles,
        access_rule: record.access_rule,
    }
}

impl RoleStoreAccess for ManagementContext {
    fn roles_snapshot(&self) -> Result<BTreeSet<String>, String> {
        self.role_store.snapshot().map_err(|err| err.to_string())
    }

    fn persist_roles(&self, roles: BTreeSet<String>) -> Result<(), String> {
        self.role_store
            .persist(roles)
            .map_err(|err| err.to_string())
    }
}

impl TagStoreAccess for ManagementContext {
    fn tags_snapshot(&self) -> Result<BTreeMap<String, TagRoleRecord>, String> {
        let tags = self.tag_store.snapshot().map_err(|err| err.to_string())?;
        Ok(tags
            .iter()
            .map(|(key, record)| (key.clone(), to_tag_role_record(record)))
            .collect())
    }

    fn persist_tags(&self, tags: BTreeMap<String, TagRoleRecord>) -> Result<(), String> {
        let mapped: BTreeMap<String, TagRecord> = tags
            .into_iter()
            .map(|(key, record)| (key, from_tag_role_record(record)))
            .collect();
        self.tag_store
            .persist(mapped)
            .map_err(|err| err.to_string())
    }
}

#[async_trait]
impl UserServicesAccess for ManagementContext {
    async fn list_user_roles(&self) -> Result<Vec<UserRoleEntry>, String> {
        let Some(services) = self.user_services.as_ref() else {
            return Ok(Vec::new());
        };
        let users = services.list_users().map_err(|err| err.to_string())?;
        Ok(users
            .into_iter()
            .map(|user| UserRoleEntry {
                email: user.email,
                roles: user.roles,
            })
            .collect())
    }

    async fn update_user_roles(&self, email: &str, roles: Vec<String>) -> Result<(), String> {
        let Some(services) = self.user_services.as_ref() else {
            return Ok(());
        };
        services
            .update_user_complete(email, None, None, Some(roles))
            .await
            .map_err(|err| err.to_string())
    }
}

impl PageCacheAccess for ManagementContext {
    fn page_cache(&self) -> Option<&std::sync::Arc<nop_rt_page_cache::PageMetaCache>> {
        self.page_cache.as_ref()
    }

    fn runtime_paths(&self) -> &nop_rt_paths::RuntimePaths {
        &self.runtime_paths
    }
}

impl SearchServiceAccess for ManagementContext {
    fn search_service(&self) -> Option<&std::sync::Arc<nop_rt_search_service::SearchService>> {
        self.search_service.as_ref()
    }
}

impl ReleaseTrackerAccess for ManagementContext {
    fn release_tracker(&self) -> Option<&std::sync::Arc<nop_rt_release::ReleaseTracker>> {
        self.release_tracker.as_ref()
    }
}

impl ConfigAccess for ManagementContext {
    fn config(&self) -> &nop_config::ValidatedConfig {
        self.config.as_ref()
    }
}
