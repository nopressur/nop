// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::markdown::listing::{DirectoryItem, generate_tag_listing_html};
use crate::shortcode::{Shortcode, ShortcodeContext, TagMatch};

pub fn handle_tag_list_shortcode(
    shortcode: &Shortcode,
    ctx: &ShortcodeContext<'_>,
) -> Result<String, String> {
    let tags_attr = shortcode.attributes.get("tags");
    let or_attr = shortcode.attributes.get("or");
    let and_attr = shortcode.attributes.get("and");

    let specified = [tags_attr.is_some(), or_attr.is_some(), and_attr.is_some()]
        .iter()
        .filter(|value| **value)
        .count();

    if specified != 1 {
        return Err("tag-list requires exactly one of tags, or, or and".to_string());
    }

    let Some(raw_list) = tags_attr.or(or_attr).or(and_attr) else {
        return Err("tag-list requires exactly one of tags, or, or and".to_string());
    };
    let tag_ids = parse_tag_list(raw_list)?;
    if tag_ids.is_empty() {
        return Err("tag-list requires at least one tag".to_string());
    }

    let match_rule = if and_attr.is_some() {
        TagMatch::All
    } else {
        TagMatch::Any
    };

    let mut pages = ctx.list_accessible_pages_by_tags(&tag_ids, match_rule);

    if let Some(limit) = shortcode.attributes.get("limit") {
        let limit_value = limit
            .trim()
            .parse::<usize>()
            .map_err(|_| "tag-list limit must be a positive integer".to_string())?;
        if limit_value == 0 {
            return Err("tag-list limit must be a positive integer".to_string());
        }
        if pages.len() > limit_value {
            pages.truncate(limit_value);
        }
    }

    let items: Vec<DirectoryItem> = pages
        .into_iter()
        .map(|page| DirectoryItem {
            title: page
                .title
                .unwrap_or_else(|| humanize_alias(&page.route_alias)),
            path: format!("/{}", page.route_alias),
            is_directory: false,
        })
        .collect();

    Ok(generate_tag_listing_html("Tagged Content", &items))
}

fn parse_tag_list(value: &str) -> Result<Vec<String>, String> {
    let mut tags = Vec::new();
    for raw in value.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !is_valid_tag_id(trimmed) {
            return Err(format!("Invalid tag id '{}'", trimmed));
        }
        tags.push(trimmed.to_string());
    }
    Ok(tags)
}

fn is_valid_tag_id(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '/')
}

fn humanize_alias(alias: &str) -> String {
    alias
        .replace(['_', '-'], " ")
        .split('/')
        .rfind(|part| !part.is_empty())
        .unwrap_or(alias)
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestFixtureRoot;
    use nop_content_store::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use nop_rt_iam::types::User;
    use nop_rt_page_cache::PageMetaCache;
    use std::fs;
    use tokio::runtime::Builder;

    struct CacheHarness {
        _fixture: TestFixtureRoot,
        cache: PageMetaCache,
        user: User,
    }

    fn write_object(
        runtime_paths: &nop_rt_paths::RuntimePaths,
        content_id: ContentId,
        alias: &str,
        title: &str,
        tags: Vec<String>,
    ) {
        let content_version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, content_version);
        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent).expect("create shard dir");
        }
        fs::write(&blob, b"test").expect("write blob");
        let sidecar = ContentSidecar {
            alias: alias.to_string(),
            title: Some(title.to_string()),
            mime: "text/markdown".to_string(),
            tags,
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            theme: None,
        };
        let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, content_version);
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
    }

    fn build_cache() -> CacheHarness {
        let fixture = TestFixtureRoot::new_unique("tag-list").expect("fixture root");
        fixture.init_runtime_layout().expect("runtime layout");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");

        let tags_yaml = r#"docs:
  name: docs
  roles:
    - reader
advanced:
  name: advanced
  roles:
    - reader
blog:
  name: blog
  roles:
    - reader
"#;
        fs::write(runtime_paths.state_sys_dir.join("tags.yaml"), tags_yaml).expect("write tags");

        write_object(
            &runtime_paths,
            ContentId(1),
            "docs/getting-started",
            "Getting Started",
            vec!["docs".to_string()],
        );
        write_object(
            &runtime_paths,
            ContentId(2),
            "docs/advanced",
            "Advanced",
            vec!["docs".to_string(), "advanced".to_string()],
        );
        write_object(
            &runtime_paths,
            ContentId(3),
            "blog/post",
            "Blog Post",
            vec!["blog".to_string()],
        );

        let cache = PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            nop_content_store::reserved_paths::ReservedPaths::default(),
        );
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime
            .block_on(cache.rebuild_cache(true))
            .expect("cache rebuild");

        let user = User {
            email: "test@example.com".to_string(),
            name: "Test".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec!["reader".to_string()],
            password_version: 1,
        };

        CacheHarness {
            _fixture: fixture,
            cache,
            user,
        }
    }

    fn make_shortcode(attrs: &[(&str, &str)]) -> Shortcode {
        let mut attributes = std::collections::HashMap::new();
        for (key, value) in attrs {
            attributes.insert((*key).to_string(), (*value).to_string());
        }
        Shortcode {
            name: "tag-list".to_string(),
            attributes,
        }
    }

    #[test]
    fn test_tag_list_any_matches() {
        let harness = build_cache();
        let shortcode = make_shortcode(&[("tags", "docs")]);
        let ctx = ShortcodeContext {
            cache: &harness.cache,
            user: Some(&harness.user),
            md_path: "test.md",
        };

        let html = handle_tag_list_shortcode(&shortcode, &ctx).expect("tag list html");
        assert!(html.contains("/docs/getting-started"));
        assert!(html.contains("/docs/advanced"));
        assert!(!html.contains("/blog/post"));
    }

    #[test]
    fn test_tag_list_and_matches() {
        let harness = build_cache();
        let shortcode = make_shortcode(&[("and", "docs,advanced")]);
        let ctx = ShortcodeContext {
            cache: &harness.cache,
            user: Some(&harness.user),
            md_path: "test.md",
        };

        let html = handle_tag_list_shortcode(&shortcode, &ctx).expect("tag list html");
        assert!(!html.contains("/docs/getting-started"));
        assert!(html.contains("/docs/advanced"));
    }

    #[test]
    fn test_tag_list_limit() {
        let harness = build_cache();
        let shortcode = make_shortcode(&[("tags", "docs"), ("limit", "1")]);
        let ctx = ShortcodeContext {
            cache: &harness.cache,
            user: Some(&harness.user),
            md_path: "test.md",
        };

        let html = handle_tag_list_shortcode(&shortcode, &ctx).expect("tag list html");
        let matches = html.matches("href=\"/docs/").count();
        assert_eq!(matches, 1);
    }

    #[test]
    fn resolve_image_source_passes_external_urls_through_unchanged() {
        let harness = build_cache();
        let ctx = ShortcodeContext {
            cache: &harness.cache,
            user: Some(&harness.user),
            md_path: "any/page",
        };

        let result = ctx
            .resolve_image_source("https://example.com/banner.png?theme=dark")
            .expect("external resolves");

        match result {
            crate::shortcode::ResolvedImage::External(url) => {
                assert_eq!(url, "https://example.com/banner.png?theme=dark");
            }
            other => panic!("expected External, got {:?}", other),
        }
    }

    #[test]
    fn resolve_image_source_rejects_non_image_alias() {
        let harness = build_cache();
        let ctx = ShortcodeContext {
            cache: &harness.cache,
            user: Some(&harness.user),
            md_path: "docs/getting-started",
        };

        // The fixture's "docs/advanced" is a markdown page, not an image,
        // so the resolver must reject it via NotImage.
        let err = ctx
            .resolve_image_source("/docs/advanced")
            .expect_err("non-image alias must error");

        assert_eq!(err, crate::shortcode::ImageSourceError::NotImage);
    }

    #[test]
    fn list_accessible_pages_by_tags_returns_titled_summaries_filtered_by_access() {
        let harness = build_cache();
        let ctx = ShortcodeContext {
            cache: &harness.cache,
            user: Some(&harness.user),
            md_path: "test.md",
        };

        let pages = ctx.list_accessible_pages_by_tags(&["docs".to_string()], TagMatch::Any);

        let aliases: Vec<String> = pages.iter().map(|p| p.route_alias.clone()).collect();
        assert!(aliases.contains(&"docs/getting-started".to_string()));
        assert!(aliases.contains(&"docs/advanced".to_string()));
        assert!(!aliases.contains(&"blog/post".to_string()));

        let getting_started = pages
            .iter()
            .find(|p| p.route_alias == "docs/getting-started")
            .expect("getting-started page");
        assert_eq!(getting_started.title.as_deref(), Some("Getting Started"));
    }
}
