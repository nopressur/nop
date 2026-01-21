// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::ValidatedConfig;
use crate::content::flat_storage::{content_id_hex, parse_content_id_hex};
use crate::public::error::{self, ErrorRenderer};
use crate::public::page_meta_cache::PageMetaCache;
use crate::templates::TemplateEngine;
use actix_web::{HttpRequest, HttpResponse, Result};
use log::warn;

use super::threats::{ThreatTracker, record_violation};

/// Performs security checks on the requested route path
/// Returns None if the route is safe, or Some(error_response) if it should be blocked
pub fn route_checks(
    path: &str,
    req: Option<&HttpRequest>,
    config: Option<&ValidatedConfig>,
    tracker: Option<&ThreatTracker>,
    error_renderer: Option<&ErrorRenderer>,
    template_engine: Option<&dyn TemplateEngine>,
) -> Option<Result<HttpResponse>> {
    // URL decode the path to catch encoded path traversal attempts
    let decoded_path = urlencoding::decode(path).unwrap_or(std::borrow::Cow::Borrowed(path));

    // Security check: block path traversal attempts (check both original and decoded)
    if path.contains("./")
        || path.contains("../")
        || decoded_path.contains("./")
        || decoded_path.contains("../")
    {
        // Log the violation if we have request context
        if let (Some(req), Some(config), Some(tracker)) = (req, config, tracker) {
            record_violation(tracker, req, config, path);
        } else {
            // Fallback logging when we don't have full context
            warn!(
                "🚨 SECURITY THREAT: Path traversal attempt - path: {}",
                path
            );
        }
        return Some(build_404_response(config, error_renderer, template_engine));
    }

    // Check if someone is directly requesting a .md file - return 404 (case insensitive)
    if path.to_lowercase().ends_with(".md") || decoded_path.to_lowercase().ends_with(".md") {
        return Some(build_404_response(config, error_renderer, template_engine));
    }

    None // Route is safe
}

/// Legacy function for backward compatibility (without threat tracking)
pub fn route_checks_legacy(path: &str) -> Option<Result<HttpResponse>> {
    route_checks(path, None, None, None, None, None)
}

/// Validate login return paths to prevent open redirects.
///
/// Rules:
/// - Reject scheme/host-prefixed values (must start with `/`, but not `//`).
/// - Allow `/` as a safe default.
/// - Allow markdown aliases or `/id/<hex>` routes that exist in the PageMetaCache.
/// - Allow admin paths (and subpaths) only when `allow_admin` is true.
pub fn validate_login_return_path(
    raw_path: &str,
    cache: &PageMetaCache,
    config: &ValidatedConfig,
    allow_admin: bool,
) -> Option<String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let cleaned = trimmed.replace(['\r', '\n'], "");
    if cleaned.is_empty() {
        return None;
    }
    if !cleaned.starts_with('/') || cleaned.starts_with("//") {
        return None;
    }
    if cleaned == "/" {
        return Some("/".to_string());
    }

    let split_idx = cleaned.find(['?', '#']);
    let (path_part, suffix) = match split_idx {
        Some(idx) => (&cleaned[..idx], &cleaned[idx..]),
        None => (cleaned.as_str(), ""),
    };

    let admin_root = config.admin.path.trim_end_matches('/');
    if !admin_root.is_empty()
        && (path_part == admin_root || path_part.starts_with(&format!("{}/", admin_root)))
    {
        return if allow_admin { Some(cleaned) } else { None };
    }

    if !suffix.is_empty() {
        return None;
    }

    let alias = path_part.trim_start_matches('/');
    if alias.is_empty() {
        return Some("/".to_string());
    }

    if let Some(id) = parse_id_route(alias) {
        let object = cache.get_by_id(id)?;
        if !object.is_markdown {
            return None;
        }
        return Some(format!("/id/{}", content_id_hex(id)));
    }

    let object = cache.get_by_alias(alias)?;
    if !object.is_markdown {
        return None;
    }

    Some(format!("/{}", object.alias))
}

fn build_404_response(
    config: Option<&ValidatedConfig>,
    error_renderer: Option<&ErrorRenderer>,
    template_engine: Option<&dyn TemplateEngine>,
) -> Result<HttpResponse> {
    if let Some(renderer) = error_renderer {
        error::serve_404(renderer, template_engine)
    } else if let Some(config) = config {
        error::serve_404_with_app_name(&config.app.name, template_engine)
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

/// Normalizes a relative path from a base markdown file path to a target path
/// This function performs logical path normalization without filesystem access
///
/// Args:
/// * `base_md_path`: The path of the current markdown file (e.g., "blog/posts/post1.md")
/// * `relative_path`: The relative path from the link (e.g., "../index" or "about")
///
/// Returns:
/// * `Some(String)`: The normalized path relative to content root
/// * `None`: If the path is invalid or tries to escape the content directory
///
/// Examples:
/// * Base: "index.md", Relative: "about" → Result: "about"
/// * Base: "blog/posts/post1.md", Relative: "../index" → Result: "blog/index"
/// * Base: "blog/post.md", Relative: "../../../escape" → Result: None (escapes root)
pub fn normalize_relative_path(base_md_path: &str, relative_path: &str) -> Option<String> {
    // Handle empty inputs
    if base_md_path.is_empty() && relative_path.is_empty() {
        return Some(String::new());
    }

    // Get the directory part of the base path
    let base_dir_string = if base_md_path.is_empty() {
        String::new()
    } else {
        std::path::Path::new(base_md_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    };
    let base_dir = base_dir_string.as_str();

    // Handle root-relative paths (starting with /)
    let working_path = if relative_path.starts_with('/') {
        relative_path.trim_start_matches('/').to_string()
    } else {
        // Combine base directory with relative path
        if base_dir.is_empty() {
            relative_path.to_string()
        } else {
            format!("{}/{}", base_dir, relative_path)
        }
    };

    // Split into components and normalize
    let mut components = Vec::new();
    let mut escaped_attempts = 0; // Count attempts to go above root

    for component in working_path.split('/') {
        match component {
            "" | "." => {
                // Skip empty components and current directory references
                continue;
            }
            ".." => {
                // Go up one level
                if components.is_empty() {
                    // Already at content root, count escape attempts
                    escaped_attempts += 1;
                } else {
                    components.pop();
                }
            }
            comp => {
                // Regular component
                components.push(comp);
            }
        }
    }

    // Calculate maximum allowed escape attempts based on base directory depth
    let base_depth = if base_dir.is_empty() {
        0
    } else {
        base_dir.split('/').filter(|s| !s.is_empty()).count()
    };

    // If we had more escape attempts than the base depth allows, it's a path traversal
    if escaped_attempts > base_depth {
        return None;
    }

    // Join components back together
    let result = components.join("/");

    // Remove trailing slashes except for empty path
    let result = if result.ends_with('/') && !result.is_empty() {
        result.trim_end_matches('/').to_string()
    } else {
        result
    };

    Some(result)
}

/// Validates if a link target resolves to a known alias in the cache.
///
/// Args:
/// * `target_path`: The normalized alias relative to the content model
/// * `cache`: The PageMetaCache containing alias mappings
///
/// Returns:
/// * `true`: If the alias resolves to a known object
/// * `false`: If the alias is invalid or not found
pub fn is_link_valid(target_path: &str, cache: &PageMetaCache) -> bool {
    cache.get_by_alias(target_path).is_some()
}

fn parse_id_route(raw_path: &str) -> Option<crate::content::flat_storage::ContentId> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.trim_start_matches('/').to_ascii_lowercase();
    let id_hex = normalized.strip_prefix("id/")?;
    if id_hex.contains('/') {
        return None;
    }
    parse_content_id_hex(id_hex).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[test]
    fn test_route_checks_blocks_traversal_and_markdown() {
        let response = route_checks_legacy("../secret").unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = route_checks_legacy("%2e%2e/secret").unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = route_checks_legacy("docs/../secret").unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = route_checks_legacy("about.md").unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        assert!(route_checks_legacy("about").is_none());
    }

    #[test]
    fn test_normalize_relative_path_simple_cases() {
        // Simple file in same directory
        assert_eq!(
            normalize_relative_path("index.md", "about"),
            Some("about".to_string())
        );

        // File with extension
        assert_eq!(
            normalize_relative_path("index.md", "image.jpg"),
            Some("image.jpg".to_string())
        );

        // Empty relative path
        assert_eq!(
            normalize_relative_path("index.md", ""),
            Some("".to_string())
        );
    }

    #[test]
    fn test_normalize_relative_path_subdirectories() {
        // File in subdirectory
        assert_eq!(
            normalize_relative_path("index.md", "blog/post1"),
            Some("blog/post1".to_string())
        );

        // Nested subdirectories
        assert_eq!(
            normalize_relative_path("index.md", "docs/guides/advanced"),
            Some("docs/guides/advanced".to_string())
        );

        // From nested file to same level
        assert_eq!(
            normalize_relative_path("blog/posts/post1.md", "post2"),
            Some("blog/posts/post2".to_string())
        );
    }

    #[test]
    fn test_normalize_relative_path_parent_navigation() {
        // Go up one level
        assert_eq!(
            normalize_relative_path("blog/posts/post1.md", "../index"),
            Some("blog/index".to_string())
        );

        // Go up two levels
        assert_eq!(
            normalize_relative_path("blog/posts/post1.md", "../../about"),
            Some("about".to_string())
        );

        // Go up and then down
        assert_eq!(
            normalize_relative_path("blog/posts/post1.md", "../drafts/draft1"),
            Some("blog/drafts/draft1".to_string())
        );

        // From root level, can't go up
        assert_eq!(normalize_relative_path("index.md", "../escape"), None);
    }

    #[test]
    fn test_normalize_relative_path_current_directory() {
        // Explicit current directory
        assert_eq!(
            normalize_relative_path("blog/index.md", "./post1"),
            Some("blog/post1".to_string())
        );

        // Multiple current directory references
        assert_eq!(
            normalize_relative_path("blog/index.md", "./posts/./post1"),
            Some("blog/posts/post1".to_string())
        );

        // Current directory only
        assert_eq!(
            normalize_relative_path("blog/index.md", "."),
            Some("blog".to_string())
        );
    }

    #[test]
    fn test_normalize_relative_path_complex_combinations() {
        // Mix of .. and . and normal paths
        assert_eq!(
            normalize_relative_path("docs/guides/advanced.md", "../.././blog/../about"),
            Some("about".to_string())
        );

        // From nested file to another nested location
        assert_eq!(
            normalize_relative_path("a/b/c/file.md", "../../../x/y/z"),
            Some("x/y/z".to_string())
        );

        // Complex path that stays within bounds
        assert_eq!(
            normalize_relative_path("a/b/c/d.md", "../../e/../f/g"),
            Some("a/f/g".to_string())
        );
    }

    #[test]
    fn test_normalize_relative_path_invalid_paths() {
        // Too many parent references (escape content root)
        assert_eq!(normalize_relative_path("index.md", "../../../escape"), None);

        // From nested file, too many parent references
        assert_eq!(
            normalize_relative_path("blog/post.md", "../../../escape"),
            None
        );

        // Complex escape attempt
        assert_eq!(
            normalize_relative_path("a/b.md", "../../../../../../escape"),
            None
        );
    }

    #[test]
    fn test_normalize_relative_path_root_relative() {
        // Root-relative paths (should remove leading slash)
        assert_eq!(
            normalize_relative_path("blog/post.md", "/about"),
            Some("about".to_string())
        );

        assert_eq!(
            normalize_relative_path("deep/nested/file.md", "/root-file"),
            Some("root-file".to_string())
        );

        // Root-relative with subdirectories
        assert_eq!(
            normalize_relative_path("anywhere.md", "/blog/posts/post1"),
            Some("blog/posts/post1".to_string())
        );
    }

    #[test]
    fn test_normalize_relative_path_slashes() {
        // Multiple slashes
        assert_eq!(
            normalize_relative_path("index.md", "blog//posts///post1"),
            Some("blog/posts/post1".to_string())
        );

        // Trailing slashes
        assert_eq!(
            normalize_relative_path("index.md", "blog/"),
            Some("blog".to_string())
        );

        // Leading and trailing slashes
        assert_eq!(
            normalize_relative_path("file.md", "/blog/posts/"),
            Some("blog/posts".to_string())
        );
    }

    #[test]
    fn test_normalize_relative_path_edge_cases() {
        // Empty base path
        assert_eq!(
            normalize_relative_path("", "file"),
            Some("file".to_string())
        );

        // Base path without extension
        assert_eq!(
            normalize_relative_path("blog/index", "../about"),
            Some("about".to_string())
        );

        // Base path deeply nested
        assert_eq!(
            normalize_relative_path("a/b/c/d/e/file.md", "../../../../../root-file"),
            Some("root-file".to_string())
        );

        // Just at the boundary (should work)
        assert_eq!(
            normalize_relative_path("a/b/c.md", "../../../file"),
            Some("file".to_string())
        );
    }

    #[test]
    fn test_normalize_relative_path_special_characters() {
        // Paths with special characters (should be preserved)
        assert_eq!(
            normalize_relative_path("index.md", "file-with_chars.123"),
            Some("file-with_chars.123".to_string())
        );

        // URL encoded characters (keep as-is for now)
        assert_eq!(
            normalize_relative_path("index.md", "my%20file"),
            Some("my%20file".to_string())
        );
    }

    #[test]
    fn test_is_link_valid_basic_structure() {
        use std::path::PathBuf;

        let cache = PageMetaCache::new(
            PathBuf::from("/test"),
            PathBuf::from("/test"),
            crate::content::reserved_paths::ReservedPaths::default(),
        );

        // Test with empty cache - all links should be invalid
        assert!(!is_link_valid("nonexistent", &cache));
        assert!(!is_link_valid("", &cache));
        assert!(!is_link_valid("any/path", &cache));
    }

    struct CacheHarness {
        _fixture: crate::util::test_fixtures::TestFixtureRoot,
        cache: PageMetaCache,
    }

    fn build_cache_with_entries(entries: &[(&str, &str)]) -> CacheHarness {
        use crate::content::flat_storage::{
            ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path,
            write_sidecar_atomic,
        };
        use crate::util::test_fixtures::TestFixtureRoot;
        use std::fs;
        use tokio::runtime::Builder;

        let fixture = TestFixtureRoot::new_unique("routing-alias-cache").expect("fixture root");
        fixture.init_runtime_layout().expect("runtime layout");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");

        for (idx, (alias, mime)) in entries.iter().enumerate() {
            let content_id = ContentId((idx + 1) as u64);
            let content_version = ContentVersion(1);
            let blob_path = blob_path(&runtime_paths.content_dir, content_id, content_version);
            if let Some(parent) = blob_path.parent() {
                fs::create_dir_all(parent).expect("create shard dir");
            }
            fs::write(&blob_path, b"test").expect("write blob");

            let sidecar = ContentSidecar {
                alias: alias.to_string(),
                title: Some(format!("Page {}", idx)),
                mime: mime.to_string(),
                tags: Vec::new(),
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
            };
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

    fn build_cache_with_aliases(aliases: &[&str]) -> CacheHarness {
        let entries: Vec<(&str, &str)> = aliases
            .iter()
            .map(|alias| (*alias, "text/markdown"))
            .collect();
        build_cache_with_entries(&entries)
    }

    fn build_test_config(admin_path: &str) -> ValidatedConfig {
        use crate::config::{
            AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
            RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
            UploadConfig, test_local_users_config, test_server_list,
        };

        ValidatedConfig {
            servers: test_server_list(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: admin_path.to_string(),
            },
            users: test_local_users_config(),
            navigation: NavigationConfig {
                max_dropdown_items: 7,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                rotation: LoggingRotationConfig::default(),
            },
            security: SecurityConfig {
                max_violations: 2,
                cooldown_seconds: 30,
                use_forwarded_for: false,
                login_sessions: crate::config::LoginSessionConfig::default(),
                hsts_enabled: false,
                hsts_max_age: 31536000,
                hsts_include_subdomains: true,
                hsts_preload: false,
            },
            tls: None,
            app: AppConfig {
                name: "Test App".to_string(),
                description: "Test Description".to_string(),
            },
            upload: UploadConfig {
                max_file_size_mb: 100,
                allowed_extensions: vec!["jpg".to_string()],
            },
            streaming: StreamingConfig { enabled: true },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            dev_mode: None,
        }
    }

    #[test]
    fn test_is_link_valid_alias_lookup() {
        let harness = build_cache_with_aliases(&["about", "docs/getting-started"]);

        assert!(is_link_valid("about", &harness.cache));
        assert!(is_link_valid("docs/getting-started", &harness.cache));
        assert!(!is_link_valid("missing", &harness.cache));
        assert!(!is_link_valid("about.md", &harness.cache));
    }

    #[test]
    fn test_is_link_valid_canonicalizes_alias() {
        let harness = build_cache_with_aliases(&["docs/getting-started"]);

        assert!(is_link_valid("Docs/Getting-Started", &harness.cache));
        assert!(is_link_valid("docs/getting-started/", &harness.cache));
    }

    #[test]
    fn test_is_link_valid_rejects_invalid_aliases() {
        let harness = build_cache_with_aliases(&["about"]);

        assert!(!is_link_valid("", &harness.cache));
        assert!(!is_link_valid("docs/../secret", &harness.cache));
    }

    #[test]
    fn test_is_link_valid_accepts_id_routes() {
        let harness = build_cache_with_aliases(&["docs/getting-started"]);

        assert!(is_link_valid("id/0000000000000001", &harness.cache));
    }

    #[test]
    fn test_validate_login_return_path_allows_markdown_aliases() {
        let harness = build_cache_with_entries(&[
            ("docs/intro", "text/markdown"),
            ("assets/sample.bin", "application/octet-stream"),
        ]);
        let config = build_test_config("/admin");

        assert_eq!(
            validate_login_return_path("/docs/intro", &harness.cache, &config, false),
            Some("/docs/intro".to_string())
        );
        assert_eq!(
            validate_login_return_path("/Docs/Intro/", &harness.cache, &config, false),
            Some("/docs/intro".to_string())
        );
        assert_eq!(
            validate_login_return_path("/", &harness.cache, &config, false),
            Some("/".to_string())
        );
        assert!(
            validate_login_return_path("/assets/sample.bin", &harness.cache, &config, false)
                .is_none()
        );
        assert_eq!(
            validate_login_return_path("/id/0000000000000001", &harness.cache, &config, false),
            Some("/id/0000000000000001".to_string())
        );
        assert!(
            validate_login_return_path("/id/0000000000000002", &harness.cache, &config, false)
                .is_none()
        );
        assert!(
            validate_login_return_path("/docs/intro?tab=1", &harness.cache, &config, false)
                .is_none()
        );
    }

    #[test]
    fn test_validate_login_return_path_rejects_schemes_and_hosts() {
        let harness = build_cache_with_aliases(&["docs/intro"]);
        let config = build_test_config("/admin");

        assert!(
            validate_login_return_path("//evil.example", &harness.cache, &config, true).is_none()
        );
        assert!(
            validate_login_return_path("https://evil.example", &harness.cache, &config, true)
                .is_none()
        );
        assert!(
            validate_login_return_path("http://evil.example", &harness.cache, &config, true)
                .is_none()
        );
    }

    #[test]
    fn test_validate_login_return_path_allows_admin_paths_for_admins() {
        let harness = build_cache_with_aliases(&["docs/intro"]);
        let config = build_test_config("/admin");

        assert_eq!(
            validate_login_return_path("/admin/pages?tab=1", &harness.cache, &config, true),
            Some("/admin/pages?tab=1".to_string())
        );
        assert!(
            validate_login_return_path("/admin/pages", &harness.cache, &config, false).is_none()
        );
        assert!(validate_login_return_path("/admin-evil", &harness.cache, &config, true).is_none());
    }
}
