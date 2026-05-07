// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::path::{Path, PathBuf};

/// Validates a path for creating new files (without requiring the file to exist)
/// Ensures the path would be within the allowed directory and prevents path traversal
/// Returns Ok(target_path) if valid, or Err(error_message) if invalid
pub fn validate_new_file_path(
    filename: &str,
    content_dir_canonical: &Path,
) -> Result<PathBuf, String> {
    if filename.is_empty() {
        return Err("Empty filename not allowed".to_string());
    }

    if filename.contains("..") || Path::new(filename).is_absolute() {
        return Err("Invalid filename: path traversal or absolute paths detected".to_string());
    }

    let decoded_filename = match urlencoding::decode(filename) {
        Ok(decoded) => decoded,
        Err(_) => return Err("Invalid filename: could not decode URL".to_string()),
    };

    if decoded_filename.contains("..") || Path::new(decoded_filename.as_ref()).is_absolute() {
        return Err(
            "Invalid filename: encoded path traversal or absolute paths detected".to_string(),
        );
    }

    let mut target_path = content_dir_canonical.to_path_buf();
    target_path.push(decoded_filename.as_ref());

    match target_path.strip_prefix(content_dir_canonical) {
        Ok(_) => Ok(target_path),
        Err(_) => Err("Target path is outside content directory".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        dir.push(format!(
            "nop-security-paths-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn validate_new_file_path_accepts_subdir() {
        let dir = temp_dir("allow");
        let result = validate_new_file_path("subdir/file.txt", &dir);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_new_file_path_rejects_traversal_and_absolute() {
        let dir = temp_dir("reject");
        assert!(validate_new_file_path("../escape.txt", &dir).is_err());
        assert!(validate_new_file_path("/absolute/path.txt", &dir).is_err());
    }
}
