// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::content_id_hex;
use crate::public::markdown::listing::{DirectoryItem, generate_tag_listing_html};
use crate::public::page_meta_cache::TagMatch;
use crate::public::shortcode::{Shortcode, ShortcodeContext};

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

    let mut objects = ctx.cache.list_by_tags(&tag_ids, match_rule);
    objects.retain(|object| object.is_markdown);
    objects.retain(|object| {
        let route_alias = object_route_alias(object);
        ctx.cache
            .user_has_access(&route_alias, ctx.user)
            .unwrap_or(false)
    });

    if let Some(limit) = shortcode.attributes.get("limit") {
        let limit_value = limit
            .trim()
            .parse::<usize>()
            .map_err(|_| "tag-list limit must be a positive integer".to_string())?;
        if limit_value == 0 {
            return Err("tag-list limit must be a positive integer".to_string());
        }
        if objects.len() > limit_value {
            objects.truncate(limit_value);
        }
    }

    let items: Vec<DirectoryItem> = objects
        .into_iter()
        .map(|object| {
            let route_alias = object_route_alias(&object);
            DirectoryItem {
                title: object.title.unwrap_or_else(|| humanize_alias(&route_alias)),
                path: format!("/{}", route_alias),
                is_directory: false,
            }
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

fn object_route_alias(object: &crate::public::page_meta_cache::CachedObject) -> String {
    if object.alias.trim().is_empty() {
        format!("id/{}", content_id_hex(object.key.id))
    } else {
        object.alias.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use crate::iam::User;
    use crate::public::page_meta_cache::PageMetaCache;
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::fs;
    use tokio::runtime::Builder;

    struct CacheHarness {
        _fixture: TestFixtureRoot,
        cache: PageMetaCache,
        user: User,
    }

    fn write_object(
        runtime_paths: &crate::runtime_paths::RuntimePaths,
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
            crate::content::reserved_paths::ReservedPaths::default(),
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
        };

        let html = handle_tag_list_shortcode(&shortcode, &ctx).expect("tag list html");
        let matches = html.matches("href=\"/docs/").count();
        assert_eq!(matches, 1);
    }
}
