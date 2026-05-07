// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::{HttpResponse, Result};
use log::warn;
use nop_rt_templates::error;

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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;
    use nop_security_paths::validate_new_file_path;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct TestFixtureRoot {
        root: TempDir,
    }

    impl TestFixtureRoot {
        fn new_unique(prefix: &str) -> std::io::Result<Self> {
            Ok(Self {
                root: tempfile::Builder::new().prefix(prefix).tempdir()?,
            })
        }

        fn path(&self) -> &Path {
            self.root.path()
        }

        fn content_dir(&self) -> PathBuf {
            self.root.path().join("content")
        }

        fn init_runtime_layout(&self) -> std::io::Result<()> {
            fs::create_dir_all(self.content_dir())?;
            fs::create_dir_all(self.root.path().join("themes"))?;
            let state_dir = self.root.path().join("state");
            fs::create_dir_all(state_dir.join("sys").join("search").join("index"))?;
            fs::create_dir_all(state_dir.join("sc"))?;
            Ok(())
        }
    }

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
