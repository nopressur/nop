// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::cache::{CacheData, CachedObject, ContentKey, PageMetaCache, ResolvedRoles};
use crate::content::flat_storage::{
    ContentId, ContentVersion, blob_path, content_id_hex, content_shard, normalize_optional_alias,
    read_sidecar,
};
use crate::management::AccessRule;
use crate::util::is_temp_upload_name;
use log::{debug, error, warn};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

impl PageMetaCache {
    /// Rebuild the entire cache asynchronously.
    pub async fn rebuild_cache(
        &self,
        cleanup_temp_uploads: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tag_map = load_tag_map(&self.state_sys_dir);
        let unique_roles = collect_unique_roles(&tag_map);

        let mut latest_by_id: HashMap<ContentId, CachedObject> = HashMap::new();
        scan_content_root(
            &self.content_dir,
            &tag_map,
            cleanup_temp_uploads,
            &mut latest_by_id,
            &self.reserved_paths,
        )?;

        let mut new_cache = CacheData::new();
        new_cache.unique_roles = unique_roles;

        for (_, object) in latest_by_id {
            let has_alias = !object.alias.trim().is_empty();
            if has_alias && new_cache.alias_map.contains_key(&object.alias) {
                warn!(
                    "Alias collision detected for '{}', skipping object {:?}",
                    object.alias, object.key
                );
                continue;
            }

            for tag in &object.tags {
                new_cache
                    .tag_index
                    .entry(tag.clone())
                    .or_default()
                    .push(object.key);
            }

            if has_alias {
                new_cache.alias_map.insert(object.alias.clone(), object.key);
            }
            new_cache.id_map.insert(object.key.id, object.key);
            if !object.is_markdown {
                let id_alias = format!("id/{}", content_id_hex(object.key.id));
                match new_cache.alias_map.entry(id_alias) {
                    Entry::Vacant(entry) => {
                        entry.insert(object.key);
                    }
                    Entry::Occupied(entry) => {
                        warn!(
                            "ID alias collision detected for '{}', skipping ID alias for {:?}",
                            entry.key(),
                            object.key
                        );
                    }
                }
            }
            new_cache.objects.insert(object.key, object);
        }

        let mut data = match self.data.write() {
            Ok(data) => data,
            Err(_) => {
                error!("🚨 CRITICAL: PageMetaCache write lock poisoned during rebuild");
                return Err("PageMetaCache write lock poisoned".into());
            }
        };

        *data = new_cache;

        Ok(())
    }

    /// Invalidate and rebuild the cache.
    pub async fn invalidate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Invalidating and rebuilding cache.");
        self.rebuild_cache(false).await
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TagRecord {
    #[allow(dead_code)]
    name: String,
    #[serde(default)]
    roles: Vec<String>,
    access_rule: Option<AccessRule>,
}

fn load_tag_map(state_sys_dir: &Path) -> BTreeMap<String, TagRecord> {
    let tags_file = state_sys_dir.join("tags.yaml");
    if !tags_file.exists() {
        return BTreeMap::new();
    }

    match fs::read_to_string(&tags_file) {
        Ok(content) => match serde_yaml::from_str::<BTreeMap<String, TagRecord>>(&content) {
            Ok(map) => map,
            Err(err) => {
                warn!("Failed to parse tags file {}: {}", tags_file.display(), err);
                BTreeMap::new()
            }
        },
        Err(err) => {
            warn!("Failed to read tags file {}: {}", tags_file.display(), err);
            BTreeMap::new()
        }
    }
}

fn collect_unique_roles(tag_map: &BTreeMap<String, TagRecord>) -> HashSet<String> {
    let mut roles = HashSet::new();
    for record in tag_map.values() {
        for role in &record.roles {
            roles.insert(role.clone());
        }
    }
    roles
}

fn scan_content_root(
    content_dir: &Path,
    tag_map: &BTreeMap<String, TagRecord>,
    cleanup_temp_uploads: bool,
    latest_by_id: &mut HashMap<ContentId, CachedObject>,
    reserved_paths: &crate::content::reserved_paths::ReservedPaths,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stack = vec![content_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with('.') {
                if cleanup_temp_uploads && is_temp_upload_name(name_str.as_ref()) {
                    cleanup_temp_entry(&path);
                }
                continue;
            }

            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                if should_skip_directory(content_dir, &path, &name_str) {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if !file_type.is_file() {
                continue;
            }

            if cleanup_temp_uploads && is_temp_upload_name(name_str.as_ref()) {
                cleanup_temp_entry(&path);
                continue;
            }

            if !name_str.ends_with(".ron") {
                continue;
            }

            let (id, version) = match parse_sidecar_filename(&name_str) {
                Some(parsed) => parsed,
                None => {
                    warn!("Skipping unrecognized sidecar file: {}", path.display());
                    continue;
                }
            };

            if let Some(parent) = path.parent()
                && let Some(shard_name) = parent.file_name().and_then(|value| value.to_str())
            {
                let expected = content_shard(id);
                if shard_name != expected {
                    warn!(
                        "Sidecar {} is in shard '{}' but expected '{}'",
                        path.display(),
                        shard_name,
                        expected
                    );
                    continue;
                }
            }

            if !blob_exists_for_sidecar(content_dir, id, version) {
                warn!(
                    "Skipping sidecar {} because blob is missing",
                    path.display()
                );
                continue;
            }

            let sidecar = match read_sidecar(&path) {
                Ok(sidecar) => sidecar,
                Err(err) => {
                    warn!("Failed to read sidecar {}: {}", path.display(), err);
                    continue;
                }
            };

            let canonical_alias = match normalize_optional_alias(&sidecar.alias) {
                Ok(Some(alias)) => Some(alias),
                Ok(None) => None,
                Err(err) => {
                    warn!(
                        "Sidecar {} has invalid alias '{}': {}",
                        path.display(),
                        sidecar.alias,
                        err
                    );
                    continue;
                }
            };

            if let Some(alias) = canonical_alias.as_ref()
                && reserved_paths.alias_is_reserved(alias)
            {
                warn!(
                    "Sidecar {} uses reserved alias '{}'; skipping",
                    path.display(),
                    alias
                );
                continue;
            }

            let key = ContentKey { id, version };
            let is_markdown = sidecar.mime == "text/markdown";
            let resolved_roles = resolve_roles(&sidecar.tags, tag_map);
            let last_modified = latest_modified(&path, &blob_path(content_dir, id, version));

            let nav_title = normalize_nav_title(&sidecar.nav_title);
            let nav_parent_id =
                normalize_nav_parent_id(&sidecar.nav_parent_id, nav_title.is_some());
            let nav_order = if nav_title.is_some() {
                sidecar.nav_order
            } else {
                None
            };

            let object = CachedObject {
                key,
                alias: canonical_alias.unwrap_or_default(),
                title: sidecar.title,
                theme: sidecar.theme,
                mime: sidecar.mime,
                tags: sidecar.tags,
                nav_title,
                nav_parent_id,
                nav_order,
                original_filename: sidecar.original_filename,
                last_modified,
                is_markdown,
                resolved_roles,
            };

            let replace = match latest_by_id.get(&id) {
                Some(existing) => version.0 > existing.key.version.0,
                None => true,
            };

            if replace {
                latest_by_id.insert(id, object);
            }
        }
    }

    Ok(())
}

fn cleanup_temp_entry(path: &Path) {
    let delete_result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };

    if let Err(err) = delete_result {
        warn!("Failed to remove temp entry {}: {}", path.display(), err);
    } else {
        debug!("Removed temp entry {}", path.display());
    }
}

fn should_skip_directory(content_root: &Path, path: &Path, name: &str) -> bool {
    if name == "legacy"
        && let Ok(relative) = path.strip_prefix(content_root)
        && relative.components().count() == 1
    {
        return true;
    }

    if let Ok(relative) = path.strip_prefix(content_root)
        && relative.components().count() == 1
    {
        return !is_shard_dir(name);
    }

    true
}

fn is_shard_dir(name: &str) -> bool {
    name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()) && name == name.to_lowercase()
}

fn parse_sidecar_filename(filename: &str) -> Option<(ContentId, ContentVersion)> {
    let trimmed = filename.strip_suffix(".ron")?;
    let mut parts = trimmed.split('.');
    let id_part = parts.next()?;
    let version_part = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let id = u64::from_str_radix(id_part, 16).ok()?;
    let version = version_part.parse::<u32>().ok()?;
    Some((ContentId(id), ContentVersion(version)))
}

fn blob_exists_for_sidecar(content_dir: &Path, id: ContentId, version: ContentVersion) -> bool {
    let shard = content_shard(id);
    let filename = format!("{:016x}.{}", id.0, version.0);
    content_dir.join(shard).join(filename).exists()
}

fn latest_modified(sidecar_path: &Path, blob_path: &Path) -> SystemTime {
    let sidecar_modified = read_modified_time(sidecar_path);
    let blob_modified = read_modified_time(blob_path);
    std::cmp::max(sidecar_modified, blob_modified)
}

fn read_modified_time(path: &Path) -> SystemTime {
    match fs::metadata(path).and_then(|metadata| metadata.modified()) {
        Ok(modified) => modified,
        Err(err) => {
            warn!(
                "Failed to read modified time for {}: {}",
                path.display(),
                err
            );
            SystemTime::UNIX_EPOCH
        }
    }
}

fn resolve_roles(tags: &[String], tag_map: &BTreeMap<String, TagRecord>) -> ResolvedRoles {
    if tags.is_empty() {
        return ResolvedRoles::Public;
    }

    let mut role_sets: Vec<HashSet<String>> = Vec::new();
    let mut any_union = false;
    let mut any_intersect = false;
    let mut has_roles = false;

    for tag in tags {
        if let Some(record) = tag_map.get(tag) {
            if record.access_rule == Some(AccessRule::Union) {
                any_union = true;
            }
            if record.access_rule == Some(AccessRule::Intersect) {
                any_intersect = true;
            }
            if !record.roles.is_empty() {
                has_roles = true;
                role_sets.push(record.roles.iter().cloned().collect());
            }
        }
    }

    if !has_roles {
        return ResolvedRoles::Public;
    }

    let resolved = if any_intersect {
        intersect_role_sets(&role_sets)
    } else if any_union {
        union_role_sets(&role_sets)
    } else {
        intersect_role_sets(&role_sets)
    };

    if resolved.is_empty() {
        return ResolvedRoles::Deny;
    }

    let mut roles: Vec<String> = resolved.into_iter().collect();
    roles.sort();
    ResolvedRoles::Restricted(roles)
}

fn normalize_nav_title(value: &Option<String>) -> Option<String> {
    let title = value.as_ref()?.trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

fn normalize_nav_parent_id(raw: &Option<String>, has_nav_title: bool) -> Option<String> {
    if !has_nav_title {
        return None;
    }
    let value = raw.as_ref()?.trim();
    if value.is_empty() {
        return None;
    }
    if value.len() != 16 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        warn!("Ignoring invalid nav_parent_id '{}'", value);
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn union_role_sets(sets: &[HashSet<String>]) -> HashSet<String> {
    let mut union = HashSet::new();
    for set in sets {
        for role in set {
            union.insert(role.clone());
        }
    }
    union
}

fn intersect_role_sets(sets: &[HashSet<String>]) -> HashSet<String> {
    let mut iter = sets.iter();
    let Some(first) = iter.next() else {
        return HashSet::new();
    };

    let mut intersection = first.clone();
    for set in iter {
        intersection.retain(|role| set.contains(role));
    }
    intersection
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::flat_storage::{
        ContentSidecar, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use crate::util::test_fixtures::TestFixtureRoot;
    use tokio::runtime::Builder;

    struct CacheHarness {
        _fixture: TestFixtureRoot,
        cache: PageMetaCache,
    }

    fn build_cache(tags_yaml: &str, sidecars: Vec<ContentSidecar>) -> CacheHarness {
        let fixture = TestFixtureRoot::new_unique("page-meta-cache").expect("fixture root");
        fixture.init_runtime_layout().expect("runtime layout");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");

        fs::write(runtime_paths.state_sys_dir.join("tags.yaml"), tags_yaml).expect("write tags");

        for (idx, sidecar) in sidecars.into_iter().enumerate() {
            let content_id = ContentId((idx + 1) as u64);
            let content_version = ContentVersion(1);
            let blob = blob_path(&runtime_paths.content_dir, content_id, content_version);
            if let Some(parent) = blob.parent() {
                fs::create_dir_all(parent).expect("create shard dir");
            }
            fs::write(&blob, b"test").expect("write blob");
            let sidecar_path =
                sidecar_path(&runtime_paths.content_dir, content_id, content_version);
            write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
        }

        let cache = PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            crate::content::reserved_paths::ReservedPaths::default(),
        );
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(cache.rebuild_cache(true))
            .expect("cache rebuild");

        CacheHarness {
            _fixture: fixture,
            cache,
        }
    }

    #[test]
    fn test_cache_alias_canonicalization() {
        let tags_yaml = "docs:\n  name: docs\n  roles: []\n";
        let harness = build_cache(
            tags_yaml,
            vec![ContentSidecar {
                alias: "Docs/Getting-Started".to_string(),
                title: Some("Getting Started".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["docs".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            }],
        );

        let object = harness
            .cache
            .get_by_alias("docs/getting-started")
            .expect("alias resolved");
        assert_eq!(object.alias, "docs/getting-started");
        assert!(harness.cache.get_by_alias("Docs/Getting-Started").is_some());
    }

    #[test]
    fn test_cache_allows_missing_alias() {
        let tags_yaml = "docs:\n  name: docs\n  roles: []\n";
        let harness = build_cache(
            tags_yaml,
            vec![ContentSidecar {
                alias: "".to_string(),
                title: Some("Untitled".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["docs".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            }],
        );

        let object = harness.cache.get_by_id(ContentId(1)).expect("id resolved");
        assert!(object.alias.is_empty());
        assert!(harness.cache.get_by_alias("id/0000000000000001").is_some());
    }

    #[test]
    fn test_tag_roles_empty_public() {
        let tags_yaml = "public:\n  name: Public\n  roles: []\n";
        let harness = build_cache(
            tags_yaml,
            vec![ContentSidecar {
                alias: "public".to_string(),
                title: Some("Public".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["public".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            }],
        );

        let roles = harness
            .cache
            .resolved_roles("public")
            .expect("public roles");
        assert!(matches!(roles, ResolvedRoles::Public));
    }

    #[test]
    fn test_intersect_ignores_empty_role_tags() {
        let tags_yaml = r#"public:
  name: Public
  roles: []
admin-only:
  name: Admin Only
  roles:
    - admin
"#;

        let harness = build_cache(
            tags_yaml,
            vec![ContentSidecar {
                alias: "mixed".to_string(),
                title: Some("Mixed".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["public".to_string(), "admin-only".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            }],
        );

        let roles = harness.cache.resolved_roles("mixed").expect("mixed roles");
        match roles {
            ResolvedRoles::Restricted(required) => {
                assert_eq!(required, vec!["admin".to_string()]);
            }
            other => panic!("unexpected roles: {:?}", other),
        }
    }

    #[test]
    fn test_tag_role_precedence_union_vs_intersect() {
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

        let harness = build_cache(
            tags_yaml,
            vec![
                ContentSidecar {
                    alias: "union".to_string(),
                    title: Some("Union".to_string()),
                    mime: "text/markdown".to_string(),
                    tags: vec!["tag-a".to_string(), "tag-b".to_string()],
                    nav_title: None,
                    nav_parent_id: None,
                    nav_order: None,
                    original_filename: None,
                    theme: None,
                },
                ContentSidecar {
                    alias: "intersect".to_string(),
                    title: Some("Intersect".to_string()),
                    mime: "text/markdown".to_string(),
                    tags: vec!["tag-a".to_string(), "tag-c".to_string()],
                    nav_title: None,
                    nav_parent_id: None,
                    nav_order: None,
                    original_filename: None,
                    theme: None,
                },
            ],
        );

        let union_roles = harness.cache.resolved_roles("union").expect("union roles");
        match union_roles {
            ResolvedRoles::Restricted(roles) => {
                assert_eq!(roles, vec!["alpha".to_string(), "beta".to_string()]);
            }
            other => panic!("unexpected roles: {:?}", other),
        }

        let intersect_roles = harness
            .cache
            .resolved_roles("intersect")
            .expect("intersect roles");
        assert!(matches!(intersect_roles, ResolvedRoles::Deny));
    }
}
