// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_TEMP_ATTEMPTS: u32 = 100;

#[derive(Debug)]
pub struct YamlStoreError {
    message: String,
}

impl YamlStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for YamlStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for YamlStoreError {}

pub fn read_yaml_file<T: DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<Option<T>, YamlStoreError> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)
        .map_err(|err| YamlStoreError::new(format!("Failed to read {} file: {}", label, err)))?;
    if content.trim().is_empty() {
        return Ok(None);
    }
    let decoded = serde_yaml::from_str(&content)
        .map_err(|err| YamlStoreError::new(format!("Failed to parse {} file: {}", label, err)))?;
    Ok(Some(decoded))
}

pub fn write_yaml_file<T: Serialize>(
    path: &Path,
    label: &str,
    value: &T,
) -> Result<(), YamlStoreError> {
    let content = serde_yaml::to_string(value)
        .map_err(|err| YamlStoreError::new(format!("Failed to serialize {}: {}", label, err)))?;
    let label_title = title_case(label);
    let parent = path.parent().ok_or_else(|| {
        YamlStoreError::new(format!("{} file path has no parent directory", label_title))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        YamlStoreError::new(format!("{} file path has no file name", label_title))
    })?;
    let (mut file, temp_path) = create_temp_file(parent, file_name, label, &label_title)?;

    if let Ok(metadata) = fs::metadata(path) {
        #[cfg(unix)]
        {
            if let Err(err) = fs::set_permissions(&temp_path, metadata.permissions()) {
                let _ = fs::remove_file(&temp_path);
                return Err(YamlStoreError::new(format!(
                    "Failed to set temp {} file permissions: {}",
                    label, err
                )));
            }
        }
    }

    if let Err(err) = file.write_all(content.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(YamlStoreError::new(format!(
            "Failed to write {} temp file: {}",
            label, err
        )));
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(YamlStoreError::new(format!(
            "Failed to sync {} temp file: {}",
            label, err
        )));
    }

    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(YamlStoreError::new(format!(
            "Failed to replace {} file: {}",
            label, err
        )));
    }

    #[cfg(unix)]
    {
        if let Err(err) = sync_parent_dir(parent) {
            log::warn!("{} directory sync failed: {}", label_title, err);
        }
    }

    Ok(())
}

fn create_temp_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
    label: &str,
    label_title: &str,
) -> Result<(fs::File, PathBuf), YamlStoreError> {
    let file_name = file_name.to_str().ok_or_else(|| {
        YamlStoreError::new(format!("{} file name is not valid UTF-8", label_title))
    })?;
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temp_name = format!(".{}.tmp.{}.{}", file_name, std::process::id(), attempt);
        let temp_path = parent.join(temp_name);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path);
        match file {
            Ok(file) => return Ok((file, temp_path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(YamlStoreError::new(format!(
                    "Failed to create temp {} file: {}",
                    label, err
                )));
            }
        }
    }
    Err(YamlStoreError::new(format!(
        "Failed to create temp {} file after multiple attempts",
        label
    )))
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> Result<(), std::io::Error> {
    let dir = fs::File::open(parent)?;
    dir.sync_all()
}

fn title_case(label: &str) -> String {
    let mut chars = label.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Fixture {
        name: String,
        count: usize,
    }

    fn temp_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        dir.push(format!(
            "nop-yaml-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn yaml_roundtrip_preserves_value() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("fixture.yaml");
        let fixture = Fixture {
            name: "Example".to_string(),
            count: 2,
        };

        write_yaml_file(&path, "fixture", &fixture).expect("write");
        let decoded: Fixture = read_yaml_file(&path, "fixture")
            .expect("read")
            .expect("decoded");
        assert_eq!(decoded, fixture);
    }
}
