// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::public::error;
use actix_web::{HttpResponse, Result};
use log::warn;
use std::path::{Path, PathBuf};

fn not_found(app_name: Option<&str>) -> Result<HttpResponse> {
    match app_name {
        Some(name) => error::serve_404_with_app_name(name, None),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

fn internal_error(app_name: Option<&str>) -> Result<HttpResponse> {
    match app_name {
        Some(name) => error::serve_500_with_app_name(name, None),
        None => Ok(HttpResponse::InternalServerError().finish()),
    }
}

/// Validates that a file path is within the allowed content directory after canonicalization
/// Returns Ok(canonical_path) if valid, or Err(error_response) if invalid
pub fn canonical_path_checks(
    file_path: &std::path::Path,
    content_dir: &str,
    app_name: Option<&str>,
) -> std::result::Result<std::path::PathBuf, Result<HttpResponse>> {
    let canonical_file_path = match file_path.canonicalize() {
        Ok(path) => path,
        Err(_) => return Err(not_found(app_name)),
    };

    let canonical_content_dir = match std::path::Path::new(content_dir).canonicalize() {
        Ok(path) => path,
        Err(_) => return Err(internal_error(app_name)),
    };

    // Use strip_prefix for more robust path validation with strict checking
    // strip_prefix returns Ok(remaining_path) if canonical_file_path is within canonical_content_dir
    // or Err if it's not (meaning it's outside the allowed directory)
    match canonical_file_path.strip_prefix(&canonical_content_dir) {
        Ok(remaining_path) => {
            // Additional validation: ensure the remaining path doesn't contain suspicious patterns
            let remaining_str = remaining_path.to_string_lossy();

            // Even after canonicalization, be extra paranoid about the remaining path
            if remaining_str.contains("..")
                || std::path::Path::new(remaining_str.as_ref()).is_absolute()
            {
                warn!(
                    "🚨 SECURITY: Suspicious remaining path after strip_prefix: {}",
                    remaining_str
                );
                return Err(not_found(app_name));
            }

            // Path is safely within the content directory
            Ok(canonical_file_path)
        }
        Err(_) => {
            // Path is outside the content directory - potential path traversal attempt
            warn!(
                "🚨 SECURITY: Path traversal attempt - file outside content directory: {:?} not in {:?}",
                canonical_file_path, canonical_content_dir
            );
            Err(not_found(app_name))
        }
    }
}

/// Validates a path for creating new files (without requiring the file to exist)
/// Ensures the path would be within the allowed directory and prevents path traversal
/// Returns Ok(target_path) if valid, or Err(error_message) if invalid
pub fn validate_new_file_path(
    filename: &str,
    content_dir_canonical: &Path,
) -> Result<PathBuf, String> {
    // Basic input validation
    if filename.is_empty() {
        return Err("Empty filename not allowed".to_string());
    }

    // Check for obvious path traversal attempts in the filename.
    // Allow internal '/' for subdirectories, but disallow traversal and absolute paths.
    if filename.contains("..") || std::path::Path::new(filename).is_absolute() {
        return Err("Invalid filename: path traversal or absolute paths detected".to_string());
    }

    // URL decode the filename to catch encoded traversal attempts
    let decoded_filename = match urlencoding::decode(filename) {
        Ok(decoded) => decoded,
        Err(_) => return Err("Invalid filename: could not decode URL".to_string()),
    };

    // Check decoded filename for traversal attempts too.
    if decoded_filename.contains("..")
        || std::path::Path::new(decoded_filename.as_ref()).is_absolute()
    {
        return Err(
            "Invalid filename: encoded path traversal or absolute paths detected".to_string(),
        );
    }

    // Build the target path (but don't canonicalize since file doesn't exist yet)
    let mut target_path = content_dir_canonical.to_path_buf();
    target_path.push(decoded_filename.as_ref());

    // Validate that the target path would be within the content directory
    // Use strip_prefix to ensure the target is within the allowed directory
    match target_path.strip_prefix(content_dir_canonical) {
        Ok(_) => Ok(target_path),
        Err(_) => Err("Target path is outside content directory".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_fixtures::TestFixtureRoot;
    use actix_web::http::StatusCode;
    use std::fs;

    #[test]
    fn test_file_upload_validation() {
        let fixture = TestFixtureRoot::new_unique("path-upload").unwrap();
        let temp_dir = fixture.path().to_path_buf();

        // Test valid filename in root
        let result = validate_new_file_path("ollama_thinking.webm", &temp_dir);
        assert!(result.is_ok(), "Should allow valid filename in root");

        // Test valid filename in subdirectory (even if subdirectory doesn't exist yet)
        let result = validate_new_file_path("subdir/ollama_thinking.webm", &temp_dir);
        assert!(
            result.is_ok(),
            "Should allow valid filename in subdirectory"
        );

        // Test path traversal attempt
        let result = validate_new_file_path("../outside.webm", &temp_dir);
        assert!(result.is_err(), "Should reject path traversal attempt");

        // Test absolute path
        let result = validate_new_file_path("/absolute/path.webm", &temp_dir);
        assert!(result.is_err(), "Should reject absolute path");
    }

    #[test]
    fn test_canonical_path_checks_allows_nested_file() {
        let fixture = TestFixtureRoot::new_unique("path-canonical-allow").unwrap();
        fixture.init_runtime_layout().unwrap();
        let content_dir = fixture.content_dir();
        let file_path = content_dir.join("posts/entry.md");
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, "ok").unwrap();

        let result =
            canonical_path_checks(&file_path, &content_dir.to_string_lossy(), Some("Test App"));
        assert!(result.is_ok(), "Expected nested file to be allowed");
    }

    #[test]
    fn test_canonical_path_checks_rejects_outside_file() {
        let content_fixture = TestFixtureRoot::new_unique("path-canonical-content").unwrap();
        content_fixture.init_runtime_layout().unwrap();
        let outside_fixture = TestFixtureRoot::new_unique("path-canonical-outside").unwrap();
        outside_fixture.init_runtime_layout().unwrap();

        let outside_file = outside_fixture.path().join("outside.md");
        fs::write(&outside_file, "nope").unwrap();

        let result = canonical_path_checks(
            &outside_file,
            &content_fixture.content_dir().to_string_lossy(),
            Some("Test App"),
        );
        assert!(result.is_err(), "Expected outside file to be rejected");
        let response = result.err().unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(unix)]
    #[test]
    fn test_canonical_path_checks_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let content_fixture = TestFixtureRoot::new_unique("path-canonical-symlink").unwrap();
        content_fixture.init_runtime_layout().unwrap();
        let outside_fixture = TestFixtureRoot::new_unique("path-canonical-outside-link").unwrap();
        outside_fixture.init_runtime_layout().unwrap();

        let external_dir = outside_fixture.path().join("external");
        fs::create_dir_all(&external_dir).unwrap();
        let external_file = external_dir.join("secret.txt");
        fs::write(&external_file, "secret").unwrap();

        let link_path = content_fixture.content_dir().join("linked.txt");
        symlink(&external_file, &link_path).unwrap();

        let result = canonical_path_checks(
            &link_path,
            &content_fixture.content_dir().to_string_lossy(),
            Some("Test App"),
        );
        assert!(result.is_err(), "Expected symlink escape to be rejected");
        let response = result.err().unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
