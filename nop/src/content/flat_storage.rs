// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentVersion(pub u32);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSidecar {
    #[serde(default)]
    pub alias: String,
    pub title: Option<String>,
    pub mime: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub nav_title: Option<String>,
    #[serde(default)]
    pub nav_parent_id: Option<String>,
    #[serde(default)]
    pub nav_order: Option<i32>,
    #[serde(default)]
    pub original_filename: Option<String>,
    #[serde(default)]
    pub theme: Option<String>,
}

#[derive(Debug)]
pub enum AliasError {
    Empty,
    ContainsControl,
    ContainsBackslash,
    ContainsDotSegment,
    ContainsInvalidCharacter,
    ReservedPrefix(&'static str),
}

impl fmt::Display for AliasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AliasError::Empty => write!(f, "alias must not be empty"),
            AliasError::ContainsControl => write!(f, "alias contains control characters"),
            AliasError::ContainsBackslash => write!(f, "alias contains backslash"),
            AliasError::ContainsDotSegment => write!(f, "alias contains '.' or '..' path segments"),
            AliasError::ContainsInvalidCharacter => {
                write!(f, "alias contains invalid URL characters")
            }
            AliasError::ReservedPrefix(prefix) => {
                write!(f, "alias uses reserved prefix '{}/'", prefix)
            }
        }
    }
}

impl std::error::Error for AliasError {}

#[derive(Debug)]
pub enum SidecarError {
    Io(std::io::Error),
    Ron(ron::error::SpannedError),
    InvalidAlias(AliasError),
    MissingMime,
    MissingTitle,
    InvalidTags,
}

impl fmt::Display for SidecarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SidecarError::Io(err) => write!(f, "sidecar I/O failed: {}", err),
            SidecarError::Ron(err) => write!(f, "sidecar parse failed: {}", err),
            SidecarError::InvalidAlias(err) => write!(f, "sidecar alias invalid: {}", err),
            SidecarError::MissingMime => write!(f, "sidecar missing mime"),
            SidecarError::MissingTitle => write!(f, "sidecar missing title for markdown"),
            SidecarError::InvalidTags => write!(f, "sidecar tags contain empty values"),
        }
    }
}

impl std::error::Error for SidecarError {}

impl From<std::io::Error> for SidecarError {
    fn from(err: std::io::Error) -> Self {
        SidecarError::Io(err)
    }
}

impl From<ron::error::Error> for SidecarError {
    fn from(err: ron::error::Error) -> Self {
        SidecarError::Ron(ron::error::SpannedError {
            code: err,
            position: ron::error::Position { line: 0, col: 0 },
        })
    }
}

impl From<ron::error::SpannedError> for SidecarError {
    fn from(err: ron::error::SpannedError) -> Self {
        SidecarError::Ron(err)
    }
}

const RESERVED_ALIAS_PREFIXES: [&str; 2] = ["login", "builtin"];

pub fn canonicalize_alias(raw: &str) -> Result<String, AliasError> {
    let trimmed = raw.trim();
    if trimmed.chars().any(|ch| ch.is_control()) {
        return Err(AliasError::ContainsControl);
    }
    if trimmed.contains('\\') {
        return Err(AliasError::ContainsBackslash);
    }
    if trimmed
        .chars()
        .any(|ch| ch != '/' && !is_url_safe_alias_char(ch))
    {
        return Err(AliasError::ContainsInvalidCharacter);
    }

    let mut parts: Vec<&str> = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return Err(AliasError::ContainsDotSegment);
        }
        parts.push(part);
    }

    let alias = parts.join("/").to_ascii_lowercase();
    if alias.is_empty() {
        return Err(AliasError::Empty);
    }
    if alias.starts_with("id/") {
        return Err(AliasError::ReservedPrefix("id"));
    }
    for prefix in RESERVED_ALIAS_PREFIXES {
        if alias == prefix || alias.starts_with(&format!("{}/", prefix)) {
            return Err(AliasError::ReservedPrefix(prefix));
        }
    }

    Ok(alias)
}

pub fn normalize_optional_alias(raw: &str) -> Result<Option<String>, AliasError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    canonicalize_alias(trimmed).map(Some)
}

fn is_url_safe_alias_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '-' | '.'
                | '_'
                | '~'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
                | ':'
                | '@'
        )
}

pub fn content_id_hex(id: ContentId) -> String {
    format!("{:016x}", id.0)
}

pub fn parse_content_id_hex(raw: &str) -> Result<ContentId, String> {
    let trimmed = raw.trim();
    if trimmed.len() != 16 {
        return Err("content id must be 16 hex chars".to_string());
    }
    if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("content id must be hex".to_string());
    }
    let value =
        u64::from_str_radix(trimmed, 16).map_err(|_| "content id parse failed".to_string())?;
    Ok(ContentId(value))
}

pub fn content_shard(id: ContentId) -> String {
    format!("{:02x}", (id.0 & 0xff) as u8)
}

pub fn blob_path(content_root: &Path, id: ContentId, version: ContentVersion) -> PathBuf {
    let shard = content_shard(id);
    let filename = format!("{}.{}", content_id_hex(id), version.0);
    content_root.join(shard).join(filename)
}

pub fn sidecar_path(content_root: &Path, id: ContentId, version: ContentVersion) -> PathBuf {
    let mut path = blob_path(content_root, id, version);
    let filename = match path.file_name() {
        Some(name) => format!("{}.ron", name.to_string_lossy()),
        None => "unknown.ron".to_string(),
    };
    path.set_file_name(filename);
    path
}

pub fn read_sidecar(path: &Path) -> Result<ContentSidecar, SidecarError> {
    let raw = fs::read_to_string(path)?;
    let sidecar: ContentSidecar = ron::from_str(&raw)?;
    validate_sidecar(&sidecar)?;
    Ok(sidecar)
}

pub fn write_sidecar_atomic(path: &Path, sidecar: &ContentSidecar) -> Result<(), SidecarError> {
    validate_sidecar(sidecar)?;
    let parent = path.parent().ok_or_else(|| {
        SidecarError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sidecar path has no parent",
        ))
    })?;
    fs::create_dir_all(parent)?;

    let content = ron::ser::to_string_pretty(
        sidecar,
        ron::ser::PrettyConfig::new().separate_tuple_members(true),
    )
    .map_err(SidecarError::from)?;

    let mut temp_path = path.to_path_buf();
    let temp_name = match path.file_name() {
        Some(name) => format!("{}.tmp", name.to_string_lossy()),
        None => "sidecar.tmp".to_string(),
    };
    temp_path.set_file_name(temp_name);

    fs::write(&temp_path, content)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

pub fn validate_sidecar(sidecar: &ContentSidecar) -> Result<(), SidecarError> {
    normalize_optional_alias(&sidecar.alias).map_err(SidecarError::InvalidAlias)?;
    if sidecar.mime.trim().is_empty() {
        return Err(SidecarError::MissingMime);
    }
    if sidecar.mime.trim() == "text/markdown" && sidecar.title.as_deref().unwrap_or("").is_empty() {
        return Err(SidecarError::MissingTitle);
    }
    if sidecar.tags.iter().any(|tag| tag.trim().is_empty()) {
        return Err(SidecarError::InvalidTags);
    }
    Ok(())
}

pub fn generate_content_id() -> Result<ContentId, openssl::error::ErrorStack> {
    let mut bytes = [0u8; 8];
    openssl::rand::rand_bytes(&mut bytes)?;
    Ok(ContentId(u64::from_le_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_alias_normalizes_slashes_and_case() {
        let alias = canonicalize_alias("/Docs//Getting-Started/").unwrap();
        assert_eq!(alias, "docs/getting-started");
    }

    #[test]
    fn canonicalize_alias_rejects_empty() {
        assert!(matches!(canonicalize_alias("/"), Err(AliasError::Empty)));
    }

    #[test]
    fn canonicalize_alias_rejects_dot_segments() {
        assert!(matches!(
            canonicalize_alias("docs/../secret"),
            Err(AliasError::ContainsDotSegment)
        ));
    }

    #[test]
    fn canonicalize_alias_rejects_invalid_characters() {
        assert!(matches!(
            canonicalize_alias("docs/hello world"),
            Err(AliasError::ContainsInvalidCharacter)
        ));
        assert!(matches!(
            canonicalize_alias("docs/hello%20world"),
            Err(AliasError::ContainsInvalidCharacter)
        ));
        assert!(matches!(
            canonicalize_alias("docs/hello?world"),
            Err(AliasError::ContainsInvalidCharacter)
        ));
    }

    #[test]
    fn canonicalize_alias_rejects_reserved_prefix() {
        assert!(matches!(
            canonicalize_alias("id/0123456789abcdef"),
            Err(AliasError::ReservedPrefix("id"))
        ));
        assert!(matches!(
            canonicalize_alias("ID/ABCDEF"),
            Err(AliasError::ReservedPrefix("id"))
        ));
        assert!(matches!(
            canonicalize_alias("login"),
            Err(AliasError::ReservedPrefix("login"))
        ));
        assert!(matches!(
            canonicalize_alias("Login/Reset"),
            Err(AliasError::ReservedPrefix("login"))
        ));
        assert!(matches!(
            canonicalize_alias("builtin/admin"),
            Err(AliasError::ReservedPrefix("builtin"))
        ));
    }

    #[test]
    fn storage_paths_use_single_shard() {
        let content_root = PathBuf::from("/content");
        let id = ContentId(0x1122334455667788);
        let version = ContentVersion(0);
        assert_eq!(
            blob_path(&content_root, id, version),
            PathBuf::from("/content/88/1122334455667788.0")
        );
        assert_eq!(
            sidecar_path(&content_root, id, version),
            PathBuf::from("/content/88/1122334455667788.0.ron")
        );
    }

    #[test]
    fn sidecar_requires_title_for_markdown() {
        let sidecar = ContentSidecar {
            alias: "docs/intro".to_string(),
            title: None,
            mime: "text/markdown".to_string(),
            tags: vec![],
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            theme: None,
        };
        assert!(matches!(
            validate_sidecar(&sidecar),
            Err(SidecarError::MissingTitle)
        ));
    }

    #[test]
    fn sidecar_roundtrip_with_valid_data() {
        let sidecar = ContentSidecar {
            alias: "docs/intro".to_string(),
            title: Some("Intro".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec!["docs".to_string()],
            nav_title: Some("Docs".to_string()),
            nav_parent_id: None,
            nav_order: Some(1),
            original_filename: Some("intro.md".to_string()),
            theme: Some("minimal".to_string()),
        };

        let serialized = ron::ser::to_string_pretty(
            &sidecar,
            ron::ser::PrettyConfig::new().separate_tuple_members(true),
        )
        .expect("serialize sidecar");
        let parsed: ContentSidecar = ron::from_str(&serialized).expect("parse sidecar");
        assert!(validate_sidecar(&parsed).is_ok());
    }

    #[test]
    fn sidecar_allows_missing_alias() {
        let sidecar = ContentSidecar {
            alias: "".to_string(),
            title: Some("Untitled".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec![],
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            theme: None,
        };

        assert!(validate_sidecar(&sidecar).is_ok());
    }
}
