// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::{
    ContentId, ContentVersion, canonicalize_alias, content_id_hex, parse_content_id_hex,
};
use crate::content::reserved_paths::ReservedPaths;
use log::error;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentKey {
    pub id: ContentId,
    pub version: ContentVersion,
}

#[derive(Debug, Clone)]
pub enum ResolvedRoles {
    Public,
    Restricted(Vec<String>),
    Deny,
}

#[derive(Debug, Clone)]
pub struct CachedObject {
    pub key: ContentKey,
    pub alias: String,
    pub title: Option<String>,
    pub theme: Option<String>,
    pub mime: String,
    pub tags: Vec<String>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
    pub original_filename: Option<String>,
    pub last_modified: SystemTime,
    pub is_markdown: bool,
    pub resolved_roles: ResolvedRoles,
}

#[derive(Debug, Clone, Copy)]
pub enum TagMatch {
    Any,
    All,
}

#[derive(Debug, Clone)]
pub(super) struct CacheData {
    pub(super) objects: HashMap<ContentKey, CachedObject>,
    pub(super) alias_map: HashMap<String, ContentKey>,
    pub(super) id_map: HashMap<ContentId, ContentKey>,
    pub(super) tag_index: HashMap<String, Vec<ContentKey>>,
    pub(super) unique_roles: HashSet<String>,
}

impl CacheData {
    pub(super) fn new() -> Self {
        Self {
            objects: HashMap::new(),
            alias_map: HashMap::new(),
            id_map: HashMap::new(),
            tag_index: HashMap::new(),
            unique_roles: HashSet::new(),
        }
    }
}

#[derive(Clone)]
pub struct PageMetaCache {
    pub(super) data: Arc<RwLock<CacheData>>,
    pub(super) content_dir: PathBuf,
    pub(super) state_sys_dir: PathBuf,
    pub(super) reserved_paths: ReservedPaths,
}

impl PageMetaCache {
    pub fn new(
        content_dir: PathBuf,
        state_sys_dir: PathBuf,
        reserved_paths: ReservedPaths,
    ) -> Self {
        Self {
            data: Arc::new(RwLock::new(CacheData::new())),
            content_dir,
            state_sys_dir,
            reserved_paths,
        }
    }

    pub fn get_by_alias(&self, alias: &str) -> Option<CachedObject> {
        let canonical = canonicalize_cache_alias(alias)?;
        if let Some(id_hex) = canonical.strip_prefix("id/") {
            let id = parse_content_id_hex(id_hex).ok()?;
            return self.get_by_id(id);
        }
        let data = match self.data.read() {
            Ok(data) => data,
            Err(_) => {
                error!("🚨 CRITICAL: PageMetaCache read lock poisoned in get_by_alias");
                return None;
            }
        };
        let key = data.alias_map.get(&canonical)?;
        data.objects.get(key).cloned()
    }

    pub fn get_by_id(&self, id: ContentId) -> Option<CachedObject> {
        let data = match self.data.read() {
            Ok(data) => data,
            Err(_) => {
                error!("🚨 CRITICAL: PageMetaCache read lock poisoned in get_by_id");
                return None;
            }
        };
        let key = data.id_map.get(&id)?;
        data.objects.get(key).cloned()
    }

    pub fn list_nav_objects(&self) -> Vec<CachedObject> {
        let data = match self.data.read() {
            Ok(data) => data,
            Err(_) => {
                error!("🚨 CRITICAL: PageMetaCache read lock poisoned in list_nav_objects");
                return Vec::new();
            }
        };
        let mut entries: Vec<CachedObject> = data
            .objects
            .values()
            .filter(|object| object.nav_title.is_some())
            .cloned()
            .collect();

        entries.sort_by(|a, b| {
            let left = a.nav_order.unwrap_or(0);
            let right = b.nav_order.unwrap_or(0);
            left.cmp(&right)
                .then_with(|| alias_or_id(a).cmp(&alias_or_id(b)))
        });

        entries
    }

    #[allow(dead_code)]
    pub fn list_nav_roots(&self) -> Vec<CachedObject> {
        let data = match self.data.read() {
            Ok(data) => data,
            Err(_) => {
                error!("🚨 CRITICAL: PageMetaCache read lock poisoned in list_nav_roots");
                return Vec::new();
            }
        };
        let mut entries: Vec<CachedObject> = data
            .objects
            .values()
            .filter(|object| object.nav_title.is_some() && object.nav_parent_id.is_none())
            .cloned()
            .collect();

        entries.sort_by(|a, b| {
            let left = a.nav_order.unwrap_or(0);
            let right = b.nav_order.unwrap_or(0);
            left.cmp(&right)
                .then_with(|| alias_or_id(a).cmp(&alias_or_id(b)))
        });

        entries
    }

    pub fn list_by_tags(&self, tags: &[String], match_rule: TagMatch) -> Vec<CachedObject> {
        if tags.is_empty() {
            return Vec::new();
        }

        let data = match self.data.read() {
            Ok(data) => data,
            Err(_) => {
                error!("🚨 CRITICAL: PageMetaCache read lock poisoned in list_by_tags");
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        for object in data.objects.values() {
            let matches = match match_rule {
                TagMatch::Any => tags.iter().any(|tag| object.tags.contains(tag)),
                TagMatch::All => tags.iter().all(|tag| object.tags.contains(tag)),
            };

            if matches {
                results.push(object.clone());
            }
        }

        results.sort_by(|a, b| {
            let left = a.title.clone().unwrap_or_else(|| alias_or_id(a));
            let right = b.title.clone().unwrap_or_else(|| alias_or_id(b));
            left.cmp(&right)
        });

        results
    }

    pub fn list_objects(&self) -> Vec<CachedObject> {
        let data = match self.data.read() {
            Ok(data) => data,
            Err(_) => {
                error!("🚨 CRITICAL: PageMetaCache read lock poisoned in list_objects");
                return Vec::new();
            }
        };

        data.objects.values().cloned().collect()
    }
}

fn alias_or_id(object: &CachedObject) -> String {
    if object.alias.trim().is_empty() {
        content_id_hex(object.key.id)
    } else {
        object.alias.clone()
    }
}

fn canonicalize_cache_alias(alias: &str) -> Option<String> {
    let trimmed = alias.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed.trim_start_matches('/').to_ascii_lowercase();
    if let Some(id_hex) = normalized.strip_prefix("id/") {
        if id_hex.contains('/') {
            return None;
        }
        if parse_content_id_hex(id_hex).is_err() {
            return None;
        }
        return Some(format!("id/{}", id_hex));
    }

    canonicalize_alias(trimmed).ok()
}
