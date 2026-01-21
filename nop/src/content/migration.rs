// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::{
    ContentSidecar, ContentVersion, canonicalize_alias, generate_content_id,
    normalize_optional_alias, read_sidecar, sidecar_path, validate_sidecar, write_sidecar_atomic,
};
use crate::management::{AccessRule, RoleStore, TagRecord, TagStore};
use crate::public::nav::capitalize_and_clean;
use crate::runtime_paths::RuntimePaths;
use crate::util::detect_mime_type;
use gray_matter::{Matter, engine::YAML};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MIGRATION_MARKER_NAME: &str = "flat-storage-v1";
const LEGACY_DIR_NAME: &str = "legacy";
const HOME_ALIAS: &str = "index";
const MAX_ALIAS_CHARS: usize = 512;
const MAX_TAG_NAME_CHARS: usize = 256;
const PLACEHOLDER_INDEX_TITLE: &str = "Home";
const PLACEHOLDER_INDEX_CONTENT: &str = "# Home\n\nThis placeholder page was created during migration because no legacy index.md was found.\nPlease update this content.\n";

#[derive(Debug)]
pub struct MigrationReport {
    pub migrated: bool,
    pub files_migrated: usize,
    pub tags_created: usize,
    pub index_placeholder_created: bool,
}

#[derive(Debug)]
pub struct MigrationError {
    message: String,
}

impl MigrationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for MigrationError {}

impl From<io::Error> for MigrationError {
    fn from(err: io::Error) -> Self {
        MigrationError::new(format!("I/O error: {}", err))
    }
}

struct MigrationState {
    used_aliases: HashSet<String>,
    tag_map: BTreeMap<String, TagRecord>,
    role_tag_cache: HashMap<Vec<String>, String>,
    tags_created: usize,
    roles: BTreeSet<String>,
    roles_changed: bool,
    created_paths: Vec<PathBuf>,
}

pub fn migrate_legacy_content(
    runtime_paths: &RuntimePaths,
) -> Result<MigrationReport, MigrationError> {
    let marker_path = migration_marker_path(&runtime_paths.state_sys_dir);
    if marker_path.exists() {
        return Ok(MigrationReport {
            migrated: false,
            files_migrated: 0,
            tags_created: 0,
            index_placeholder_created: false,
        });
    }

    let legacy_files = collect_legacy_files(&runtime_paths.content_dir)?;
    if legacy_files.is_empty() {
        return Ok(MigrationReport {
            migrated: false,
            files_migrated: 0,
            tags_created: 0,
            index_placeholder_created: false,
        });
    }

    let legacy_root_has_index = legacy_root_has_index(&legacy_files, &runtime_paths.content_dir);
    let tag_store = TagStore::new(runtime_paths.state_sys_dir.clone())
        .map_err(|err| MigrationError::new(err.to_string()))?;
    let tag_map = tag_store
        .snapshot()
        .map_err(|err| MigrationError::new(err.to_string()))?;
    let role_store = RoleStore::new(runtime_paths.state_sys_dir.clone())
        .map_err(|err| MigrationError::new(err.to_string()))?;
    let roles = role_store
        .snapshot()
        .map_err(|err| MigrationError::new(err.to_string()))?;
    let mut state = MigrationState {
        used_aliases: collect_existing_aliases(&runtime_paths.content_dir)?,
        tag_map,
        role_tag_cache: HashMap::new(),
        tags_created: 0,
        roles,
        roles_changed: false,
        created_paths: Vec::new(),
    };

    let mut migrated_files = 0usize;
    let mut index_placeholder_created = false;
    for legacy_path in &legacy_files {
        let result = migrate_one_file(legacy_path, &runtime_paths.content_dir, &mut state);
        if let Err(err) = result {
            rollback_created_files(&state.created_paths);
            return Err(MigrationError::new(format!(
                "Migration failed for {}: {}",
                legacy_path.display(),
                err
            )));
        }
        migrated_files += 1;
    }

    if !legacy_root_has_index && !state.used_aliases.contains(HOME_ALIAS) {
        if let Err(err) = create_index_placeholder(
            &runtime_paths.content_dir,
            &mut state.used_aliases,
            &mut state.created_paths,
        ) {
            rollback_created_files(&state.created_paths);
            return Err(MigrationError::new(format!(
                "Failed to create placeholder index: {}",
                err
            )));
        }
        index_placeholder_created = true;
    }

    if state.tags_created > 0 {
        tag_store
            .persist(std::mem::take(&mut state.tag_map))
            .map_err(|err| MigrationError::new(err.to_string()))?;
    }
    if state.roles_changed {
        role_store
            .persist(std::mem::take(&mut state.roles))
            .map_err(|err| MigrationError::new(err.to_string()))?;
    }

    move_legacy_entries(&runtime_paths.content_dir)?;
    write_marker(
        &marker_path,
        migrated_files,
        state.tags_created,
        index_placeholder_created,
    )?;

    Ok(MigrationReport {
        migrated: true,
        files_migrated: migrated_files,
        tags_created: state.tags_created,
        index_placeholder_created,
    })
}

fn migration_marker_path(state_sys_dir: &Path) -> PathBuf {
    state_sys_dir.join("migrations").join(MIGRATION_MARKER_NAME)
}

fn collect_legacy_files(content_dir: &Path) -> Result<Vec<PathBuf>, MigrationError> {
    let mut files = Vec::new();
    let mut stack = vec![content_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;

            if file_type.is_symlink() {
                continue;
            }

            if should_skip_path(content_dir, &path) {
                continue;
            }

            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn collect_existing_aliases(content_dir: &Path) -> Result<HashSet<String>, MigrationError> {
    let mut aliases = HashSet::new();
    if !content_dir.exists() {
        return Ok(aliases);
    }

    for entry in fs::read_dir(content_dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if !file_type.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|value| value.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if !is_shard_dir(name) {
            continue;
        }

        for sidecar_entry in fs::read_dir(path)? {
            let sidecar_entry = sidecar_entry?;
            let sidecar_path = sidecar_entry.path();
            if sidecar_path.extension().and_then(|ext| ext.to_str()) != Some("ron") {
                continue;
            }
            if let Ok(sidecar) = read_sidecar(&sidecar_path)
                && let Ok(Some(alias)) = normalize_optional_alias(&sidecar.alias)
            {
                aliases.insert(alias);
            }
        }
    }

    Ok(aliases)
}

fn legacy_root_has_index(legacy_files: &[PathBuf], content_dir: &Path) -> bool {
    legacy_files.iter().any(|path| {
        let relative = match path.strip_prefix(content_dir) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if relative.components().count() != 1 {
            return false;
        }
        let file_name = match relative.file_name().and_then(|value| value.to_str()) {
            Some(name) => name,
            None => return false,
        };
        let lower = file_name.to_ascii_lowercase();
        lower == "index.md" || lower == "index.markdown"
    })
}

fn create_index_placeholder(
    content_dir: &Path,
    used_aliases: &mut HashSet<String>,
    created_paths: &mut Vec<PathBuf>,
) -> Result<(), MigrationError> {
    used_aliases.insert(HOME_ALIAS.to_string());

    let version = ContentVersion(0);
    let content_id = generate_content_id()
        .map_err(|err| MigrationError::new(format!("Failed to generate ID: {}", err)))?;
    let sidecar = ContentSidecar {
        alias: HOME_ALIAS.to_string(),
        title: Some(PLACEHOLDER_INDEX_TITLE.to_string()),
        mime: "text/markdown".to_string(),
        tags: Vec::new(),
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: Some("index.md".to_string()),
        theme: None,
    };
    validate_sidecar(&sidecar)
        .map_err(|err| MigrationError::new(format!("Invalid sidecar: {}", err)))?;

    let blob_path = crate::content::flat_storage::blob_path(content_dir, content_id, version);
    if let Some(parent) = blob_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&blob_path, PLACEHOLDER_INDEX_CONTENT.as_bytes())?;
    created_paths.push(blob_path.clone());

    let sidecar_path = sidecar_path(content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        let _ = fs::remove_file(&blob_path);
        return Err(MigrationError::new(format!(
            "Failed to write sidecar: {}",
            err
        )));
    }
    created_paths.push(sidecar_path);

    Ok(())
}

fn migrate_one_file(
    legacy_path: &Path,
    content_dir: &Path,
    state: &mut MigrationState,
) -> Result<(), MigrationError> {
    let relative = legacy_path
        .strip_prefix(content_dir)
        .map_err(|_| MigrationError::new("Legacy path is outside content root"))?;

    let file_name = legacy_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| MigrationError::new("Legacy file name is not valid UTF-8"))?;

    let is_markdown = is_markdown_file(file_name);
    let content_bytes = fs::read(legacy_path)?;
    let (front_matter, mime, blob_bytes) = if is_markdown {
        let text = String::from_utf8(content_bytes)
            .map_err(|_| MigrationError::new("Markdown is not valid UTF-8"))?;
        let (front_matter, markdown_body) = parse_front_matter(&text);
        (
            front_matter,
            "text/markdown".to_string(),
            markdown_body.unwrap_or_default().into_bytes(),
        )
    } else {
        (
            LegacyFrontMatter::default(),
            detect_mime_type(legacy_path, &content_bytes),
            content_bytes,
        )
    };

    let alias = derive_alias(relative, is_markdown)?;
    let canonical = canonicalize_alias(&alias)
        .map_err(|err| MigrationError::new(format!("Invalid alias '{}': {}", alias, err)))?;
    if canonical.chars().count() > MAX_ALIAS_CHARS {
        return Err(MigrationError::new(format!(
            "Alias '{}' is too long",
            canonical
        )));
    }

    let alias = dedupe_alias(&canonical, &mut state.used_aliases)?;

    let version = ContentVersion(0);
    let content_id = generate_content_id()
        .map_err(|err| MigrationError::new(format!("Failed to generate ID: {}", err)))?;

    let title = front_matter
        .title
        .clone()
        .or_else(|| cleaned_title(file_name))
        .filter(|value| !value.trim().is_empty());

    let theme = front_matter.theme.clone();

    let mut tags = Vec::new();
    if !front_matter.roles.is_empty() {
        let normalized_roles = normalize_roles(&front_matter.roles)?;
        let tag_id = ensure_role_tag(
            &normalized_roles,
            &mut state.tag_map,
            &mut state.role_tag_cache,
            &mut state.tags_created,
            &mut state.roles,
            &mut state.roles_changed,
        )?;
        tags.push(tag_id);
    }

    let sidecar = ContentSidecar {
        alias: alias.clone(),
        title,
        mime: mime.clone(),
        tags,
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: Some(file_name.to_string()),
        theme,
    };
    validate_sidecar(&sidecar)
        .map_err(|err| MigrationError::new(format!("Invalid sidecar: {}", err)))?;

    let blob_path = crate::content::flat_storage::blob_path(content_dir, content_id, version);
    if let Some(parent) = blob_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&blob_path, &blob_bytes)?;
    state.created_paths.push(blob_path.clone());

    let sidecar_path = sidecar_path(content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        let _ = fs::remove_file(&blob_path);
        return Err(MigrationError::new(format!(
            "Failed to write sidecar: {}",
            err
        )));
    }
    state.created_paths.push(sidecar_path.clone());

    Ok(())
}

fn parse_front_matter(content: &str) -> (LegacyFrontMatter, Option<String>) {
    let matter = Matter::<YAML>::new();
    let parsed = matter.parse(content);
    let mut front_matter = LegacyFrontMatter::default();

    if let Some(data) = parsed.data
        && let gray_matter::Pod::Hash(map) = data
    {
        if let Some(value) = map.get("title")
            && let Ok(title) = value.as_string()
        {
            front_matter.title = Some(title);
        }
        if let Some(value) = map.get("theme")
            && let Ok(theme) = value.as_string()
        {
            front_matter.theme = Some(theme);
        }
        if let Some(value) = map.get("roles") {
            if let Ok(roles) = value.as_vec() {
                front_matter.roles = parse_role_list(&roles);
            } else if let Ok(role) = value.as_string() {
                front_matter.roles = vec![role];
            }
        } else if let Some(value) = map.get("role")
            && let Ok(role) = value.as_string()
        {
            front_matter.roles = vec![role];
        }
    }

    (front_matter, Some(parsed.content))
}

fn parse_role_list(values: &[gray_matter::Pod]) -> Vec<String> {
    values
        .iter()
        .filter_map(|item| item.as_string().ok())
        .collect()
}

fn normalize_roles(roles: &[String]) -> Result<Vec<String>, MigrationError> {
    let mut normalized =
        crate::roles::normalize_roles(roles).map_err(|err| MigrationError::new(err.to_string()))?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn ensure_role_tag(
    roles: &[String],
    tag_map: &mut BTreeMap<String, TagRecord>,
    role_tag_cache: &mut HashMap<Vec<String>, String>,
    tags_created: &mut usize,
    role_set: &mut BTreeSet<String>,
    roles_changed: &mut bool,
) -> Result<String, MigrationError> {
    if let Some(existing) = role_tag_cache.get(roles) {
        return Ok(existing.clone());
    }

    for role in roles {
        if role_set.insert(role.clone()) {
            *roles_changed = true;
        }
    }

    let hash = hash_roles(roles);
    let tag_id = format!("legacy/roles/{}", hash);

    if let Some(existing) = tag_map.get(&tag_id) {
        if existing.roles != roles || existing.access_rule != Some(AccessRule::Union) {
            return Err(MigrationError::new(format!(
                "Existing tag '{}' conflicts with legacy role mapping",
                tag_id
            )));
        }
    } else {
        let mut name = format!("Legacy roles: {}", roles.join(", "));
        if name.chars().count() > MAX_TAG_NAME_CHARS {
            name.truncate(MAX_TAG_NAME_CHARS);
        }
        tag_map.insert(
            tag_id.clone(),
            TagRecord {
                name,
                roles: roles.to_vec(),
                access_rule: Some(AccessRule::Union),
            },
        );
        *tags_created += 1;
    }

    role_tag_cache.insert(roles.to_vec(), tag_id.clone());
    Ok(tag_id)
}

fn hash_roles(roles: &[String]) -> String {
    let mut hasher = Sha256::new();
    for role in roles {
        hasher.update(role.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

fn derive_alias(relative: &Path, is_markdown: bool) -> Result<String, MigrationError> {
    let rel_string = relative
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string();

    if is_markdown {
        let stem_path = relative.with_extension("");
        let stem_string = stem_path.to_string_lossy().replace('\\', "/");
        let stem_name = stem_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if stem_name.eq_ignore_ascii_case("index") {
            let parent = stem_path
                .parent()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if parent.is_empty() {
                return Ok("index".to_string());
            }
            return Ok(parent.replace('\\', "/"));
        }
        return Ok(stem_string.trim_start_matches('/').to_string());
    }

    Ok(rel_string)
}

fn cleaned_title(file_name: &str) -> Option<String> {
    let stem = Path::new(file_name)
        .file_stem()
        .and_then(|value| value.to_str())?;
    let cleaned = capitalize_and_clean(stem);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn dedupe_alias(alias: &str, used_aliases: &mut HashSet<String>) -> Result<String, MigrationError> {
    if !used_aliases.contains(alias) {
        used_aliases.insert(alias.to_string());
        return Ok(alias.to_string());
    }

    let (base, ext) = split_alias_extension(alias);
    for i in 2..1000 {
        let candidate = format!("{}-{}{}", base, i, ext);
        if candidate.chars().count() > MAX_ALIAS_CHARS {
            return Err(MigrationError::new("Deduped alias exceeds max length"));
        }
        if !used_aliases.contains(&candidate) {
            used_aliases.insert(candidate.clone());
            return Ok(candidate);
        }
    }

    Err(MigrationError::new("Unable to dedupe alias"))
}

fn split_alias_extension(alias: &str) -> (String, String) {
    let last_slash = alias.rfind('/');
    let last_dot = alias.rfind('.');
    if let Some(dot) = last_dot
        && last_slash.map(|slash| dot > slash).unwrap_or(true)
    {
        return (alias[..dot].to_string(), alias[dot..].to_string());
    }
    (alias.to_string(), String::new())
}

fn is_markdown_file(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.ends_with(".md") || lower.ends_with(".markdown")
}

fn should_skip_path(content_root: &Path, path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
        if name.starts_with('.') {
            return true;
        }
        if name == LEGACY_DIR_NAME
            && let Ok(relative) = path.strip_prefix(content_root)
            && relative.components().count() == 1
        {
            return true;
        }
        if is_shard_dir(name)
            && let Ok(relative) = path.strip_prefix(content_root)
            && relative.components().count() == 1
        {
            return true;
        }
    }
    false
}

fn is_shard_dir(name: &str) -> bool {
    name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()) && name == name.to_lowercase()
}

fn move_legacy_entries(content_dir: &Path) -> Result<(), MigrationError> {
    let legacy_root = content_dir.join(LEGACY_DIR_NAME);
    fs::create_dir_all(&legacy_root)?;

    for entry in fs::read_dir(content_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|value| value.to_str()) {
            Some(name) => name,
            None => continue,
        };

        if name.starts_with('.') || name == LEGACY_DIR_NAME || is_shard_dir(name) {
            continue;
        }

        let mut destination = legacy_root.join(name);
        if destination.exists() {
            let mut suffix = 2;
            loop {
                let candidate = legacy_root.join(format!("{}-{}", name, suffix));
                if !candidate.exists() {
                    destination = candidate;
                    break;
                }
                suffix += 1;
            }
        }

        fs::rename(&path, &destination)?;
    }

    Ok(())
}

fn write_marker(
    marker_path: &Path,
    files_migrated: usize,
    tags_created: usize,
    index_placeholder_created: bool,
) -> Result<(), MigrationError> {
    let parent = marker_path
        .parent()
        .ok_or_else(|| MigrationError::new("Marker path missing parent"))?;
    fs::create_dir_all(parent)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let content = format!(
        "migrated_at_unix={timestamp}\nfiles_migrated={files_migrated}\ntags_created={tags_created}\nindex_placeholder_created={index_placeholder_created}\n"
    );
    fs::write(marker_path, content)?;
    Ok(())
}

fn rollback_created_files(created_paths: &[PathBuf]) {
    for path in created_paths.iter().rev() {
        let _ = fs::remove_file(path);
    }
}

#[derive(Default)]
struct LegacyFrontMatter {
    title: Option<String>,
    theme: Option<String>,
    roles: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::flat_storage::read_sidecar;
    use crate::runtime_paths::RuntimePaths;
    use tempfile::TempDir;

    fn build_runtime_paths(root: &Path) -> RuntimePaths {
        let content_dir = root.join("content");
        let themes_dir = root.join("themes");
        let state_dir = root.join("state");
        let state_sys_dir = state_dir.join("sys");
        let state_sc_dir = state_dir.join("sc");
        fs::create_dir_all(&content_dir).expect("content dir");
        fs::create_dir_all(&themes_dir).expect("themes dir");
        fs::create_dir_all(&state_sys_dir).expect("state sys dir");
        fs::create_dir_all(&state_sc_dir).expect("state sc dir");

        RuntimePaths {
            root: root.to_path_buf(),
            config_file: root.join("config.yaml"),
            users_file: root.join("users.yaml"),
            content_dir,
            themes_dir,
            state_dir,
            state_sys_dir,
            state_sc_dir,
            logs_dir: root.join("logs"),
        }
    }

    fn collect_sidecars(content_dir: &Path) -> Vec<(PathBuf, ContentSidecar)> {
        let mut sidecars = Vec::new();
        for entry in fs::read_dir(content_dir).expect("content dir read") {
            let entry = entry.expect("content entry");
            let path = entry.path();
            let file_type = entry.file_type().expect("content type");
            if !file_type.is_dir() {
                continue;
            }
            let name = match path.file_name().and_then(|value| value.to_str()) {
                Some(name) => name,
                None => continue,
            };
            if !is_shard_dir(name) {
                continue;
            }
            for sidecar_entry in fs::read_dir(&path).expect("shard dir read") {
                let sidecar_entry = sidecar_entry.expect("sidecar entry");
                let sidecar_path = sidecar_entry.path();
                if sidecar_path.extension().and_then(|ext| ext.to_str()) != Some("ron") {
                    continue;
                }
                let sidecar = read_sidecar(&sidecar_path).expect("sidecar parse");
                sidecars.push((sidecar_path, sidecar));
            }
        }
        sidecars
    }

    #[test]
    fn migrate_strips_front_matter_and_maps_roles() {
        let temp = TempDir::new().expect("temp dir");
        let runtime_paths = build_runtime_paths(temp.path());

        let legacy_dir = runtime_paths.content_dir.join("docs");
        fs::create_dir_all(&legacy_dir).expect("legacy dir");

        let content = r#"---
title: "Getting Started"
nav: true
roles:
  - admin
  - editor
theme: "landing"
---
# Hello

Body content.
"#;
        fs::write(legacy_dir.join("getting-started.md"), content).expect("legacy write");

        let report = migrate_legacy_content(&runtime_paths).expect("migration");
        assert!(report.migrated);
        assert_eq!(report.files_migrated, 1);
        assert_eq!(report.tags_created, 1);
        assert!(report.index_placeholder_created);

        let sidecars = collect_sidecars(&runtime_paths.content_dir);
        assert_eq!(sidecars.len(), 2);
        let (sidecar_path, sidecar) = sidecars
            .iter()
            .find(|(_, sidecar)| sidecar.alias == "docs/getting-started")
            .expect("docs sidecar");

        assert_eq!(sidecar.alias, "docs/getting-started");
        assert_eq!(sidecar.title.as_deref(), Some("Getting Started"));
        assert_eq!(sidecar.mime, "text/markdown");
        assert!(sidecar.nav_title.is_none());
        assert!(sidecar.nav_parent_id.is_none());
        assert!(sidecar.nav_order.is_none());
        assert_eq!(
            sidecar.original_filename.as_deref(),
            Some("getting-started.md")
        );
        assert_eq!(sidecar.theme.as_deref(), Some("landing"));
        assert_eq!(sidecar.tags.len(), 1);

        let tag_id = &sidecar.tags[0];
        let tags_path = runtime_paths.state_sys_dir.join("tags.yaml");
        let tags_content = fs::read_to_string(tags_path).expect("tags file");
        let tags: BTreeMap<String, TagRecord> =
            serde_yaml::from_str(&tags_content).expect("tags parse");
        let tag = tags.get(tag_id).expect("legacy tag");
        assert_eq!(tag.access_rule, Some(AccessRule::Union));
        assert_eq!(tag.roles, vec!["admin".to_string(), "editor".to_string()]);

        let blob_name = sidecar_path
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("blob name");
        let blob_path = sidecar_path.with_file_name(blob_name);
        let blob_content = fs::read_to_string(blob_path).expect("blob read");
        assert!(blob_content.starts_with("# Hello"));
        assert!(!blob_content.contains("title:"));

        let legacy_path = runtime_paths
            .content_dir
            .join("legacy")
            .join("docs")
            .join("getting-started.md");
        assert!(legacy_path.exists());
    }

    #[test]
    fn migrate_dedupes_aliases() {
        let temp = TempDir::new().expect("temp dir");
        let runtime_paths = build_runtime_paths(temp.path());

        let legacy_dir = runtime_paths.content_dir.join("docs");
        fs::create_dir_all(&legacy_dir).expect("legacy dir");
        fs::write(legacy_dir.join("intro.md"), "# Intro").expect("intro md");
        fs::write(legacy_dir.join("intro.markdown"), "# Intro duplicate").expect("intro markdown");

        let report = migrate_legacy_content(&runtime_paths).expect("migration");
        assert!(report.migrated);
        assert_eq!(report.files_migrated, 2);

        let sidecars = collect_sidecars(&runtime_paths.content_dir);
        let aliases: HashSet<String> = sidecars
            .into_iter()
            .map(|(_, sidecar)| sidecar.alias)
            .collect();
        assert!(aliases.contains("docs/intro"));
        assert!(aliases.iter().any(|alias| alias.starts_with("docs/intro-")));
    }

    #[test]
    fn migration_marker_prevents_rerun() {
        let temp = TempDir::new().expect("temp dir");
        let runtime_paths = build_runtime_paths(temp.path());

        let legacy_dir = runtime_paths.content_dir.join("docs");
        fs::create_dir_all(&legacy_dir).expect("legacy dir");
        fs::write(legacy_dir.join("index.md"), "# Home").expect("index write");

        let report = migrate_legacy_content(&runtime_paths).expect("migration");
        assert!(report.migrated);
        assert_eq!(report.files_migrated, 1);

        let second = migrate_legacy_content(&runtime_paths).expect("second migration");
        assert!(!second.migrated);
        assert_eq!(second.files_migrated, 0);
    }

    #[test]
    fn migration_creates_placeholder_index_when_missing() {
        let temp = TempDir::new().expect("temp dir");
        let runtime_paths = build_runtime_paths(temp.path());

        let legacy_dir = runtime_paths.content_dir.join("docs");
        fs::create_dir_all(&legacy_dir).expect("legacy dir");
        fs::write(legacy_dir.join("intro.md"), "# Intro").expect("intro md");

        let report = migrate_legacy_content(&runtime_paths).expect("migration");
        assert!(report.migrated);
        assert!(report.index_placeholder_created);

        let sidecars = collect_sidecars(&runtime_paths.content_dir);
        let (sidecar_path, sidecar) = sidecars
            .into_iter()
            .find(|(_, sidecar)| sidecar.alias == "index")
            .expect("index sidecar");
        assert_eq!(sidecar.title.as_deref(), Some(PLACEHOLDER_INDEX_TITLE));

        let blob_name = sidecar_path
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("blob name");
        let blob_path = sidecar_path.with_file_name(blob_name);
        let blob_content = fs::read_to_string(blob_path).expect("blob read");
        assert!(blob_content.contains("placeholder page was created during migration"));
    }
}
