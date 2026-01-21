// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::iam::User;
use crate::public::markdown::HtmlSanitizer;
use crate::public::page_meta_cache::PageMetaCache;
use crate::public::shortcode::{
    ShortcodeContext, ShortcodeRegistry, process_text_with_shortcodes,
    replace_shortcode_placeholders,
};
use crate::security;
use gray_matter;
use once_cell::sync::Lazy;
use pulldown_cmark::{CowStr, Event, Options, Parser, Tag, html};
use regex::Regex;

static EXTERNAL_LINK_REGEX: Lazy<Result<Regex, regex::Error>> =
    Lazy::new(|| Regex::new(r#"<a href="(https?://[^"]+)"([^>]*)>"#));

static LOCAL_LINK_REGEX: Lazy<Result<Regex, regex::Error>> =
    Lazy::new(|| Regex::new(r#"<a href="([^"]+)"([^>]*)>"#));

#[derive(Debug)]
pub(super) enum MarkdownRenderError {
    Regex(String),
}

impl std::fmt::Display for MarkdownRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarkdownRenderError::Regex(message) => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for MarkdownRenderError {}

pub(super) struct RenderedMarkdown {
    pub(super) html: String,
    pub(super) contains_dynamic_shortcodes: bool,
    pub(super) use_compact_width: bool,
}

pub(super) fn generate_html(
    result: &gray_matter::ParsedEntity,
    shortcode_registry: &ShortcodeRegistry,
    options: &Options,
    sanitizer: &HtmlSanitizer,
    cache: &PageMetaCache,
    md_path: &str,
    user: Option<&User>,
    short_paragraph_length: usize,
) -> Result<RenderedMarkdown, MarkdownRenderError> {
    // Process shortcodes to build mapping (original text unchanged)
    let shortcode_ctx = ShortcodeContext { cache, user };
    let shortcode_result =
        process_text_with_shortcodes(&result.content, shortcode_registry, &shortcode_ctx);

    let use_compact_width = should_use_compact_width(
        &shortcode_result.processed_text,
        options,
        short_paragraph_length,
    );

    // Parse the markdown content (shortcode strings will be treated as regular text)
    let parser = Parser::new_ext(&shortcode_result.processed_text, *options);

    // Process events with custom logic for images and links
    let events = parser.map(|event| process_event(event, md_path, cache));

    let mut html_output = String::new();
    html::push_html(&mut html_output, events);

    // Sanitize HTML output from Markdown conversion (shortcode strings are just text so they're safe)
    let sanitized_html = sanitizer.clean(&html_output);

    // Post-process HTML to add target="_blank" to external links (before shortcode replacement)
    let processed_html = post_process_html(sanitized_html, md_path, cache)?;

    // Replace shortcode strings with their rendered HTML as the final step

    let final_html =
        replace_shortcode_placeholders(&processed_html, &shortcode_result.hash_to_html_map);

    Ok(RenderedMarkdown {
        html: final_html,
        contains_dynamic_shortcodes: shortcode_result.contains_dynamic_shortcodes,
        use_compact_width,
    })
}

struct ParagraphLengthStats {
    total_paragraphs: usize,
    long_paragraphs: usize,
}

struct ItemLengthStats {
    current_len: usize,
    has_non_whitespace: bool,
    has_paragraph: bool,
}

fn should_use_compact_width(
    markdown: &str,
    options: &Options,
    short_paragraph_length: usize,
) -> bool {
    if short_paragraph_length == 0 {
        return false;
    }

    let stats = count_paragraph_lengths(markdown, options, short_paragraph_length);
    if stats.total_paragraphs == 0 {
        return true;
    }

    stats.long_paragraphs == 0
}

fn count_paragraph_lengths(
    markdown: &str,
    options: &Options,
    short_paragraph_length: usize,
) -> ParagraphLengthStats {
    let parser = Parser::new_ext(markdown, *options);
    let mut in_paragraph = false;
    let mut in_image = false;
    let mut current_len = 0usize;
    let mut has_non_whitespace = false;
    let mut item_stack: Vec<ItemLengthStats> = Vec::new();
    let mut stats = ParagraphLengthStats {
        total_paragraphs: 0,
        long_paragraphs: 0,
    };

    for event in parser {
        match event {
            Event::Start(Tag::Item) => {
                item_stack.push(ItemLengthStats {
                    current_len: 0,
                    has_non_whitespace: false,
                    has_paragraph: false,
                });
            }
            Event::End(Tag::Item) => {
                if let Some(item_stats) = item_stack.pop()
                    && !item_stats.has_paragraph
                    && item_stats.has_non_whitespace
                {
                    stats.total_paragraphs += 1;
                    if item_stats.current_len > short_paragraph_length {
                        stats.long_paragraphs += 1;
                    }
                }
            }
            Event::Start(Tag::Paragraph) => {
                in_paragraph = true;
                in_image = false;
                current_len = 0;
                has_non_whitespace = false;
                if let Some(item_stats) = item_stack.last_mut() {
                    item_stats.has_paragraph = true;
                }
            }
            Event::End(Tag::Paragraph) => {
                if in_paragraph && has_non_whitespace {
                    stats.total_paragraphs += 1;
                    if current_len > short_paragraph_length {
                        stats.long_paragraphs += 1;
                    }
                }
                in_paragraph = false;
                in_image = false;
            }
            Event::Start(Tag::Image(_, _, _)) if in_paragraph || !item_stack.is_empty() => {
                in_image = true;
            }
            Event::End(Tag::Image(_, _, _)) if in_paragraph || !item_stack.is_empty() => {
                in_image = false;
            }
            Event::Text(text) | Event::Html(text) if in_paragraph && !in_image => {
                let (len, has_text) = count_text_stats_excluding_placeholders(&text);
                current_len += len;
                if has_text {
                    has_non_whitespace = true;
                }
            }
            Event::Text(text) | Event::Html(text) if !in_paragraph && !in_image => {
                if let Some(item_stats) = item_stack.last_mut() {
                    let (len, has_text) = count_text_stats_excluding_placeholders(&text);
                    item_stats.current_len += len;
                    if has_text {
                        item_stats.has_non_whitespace = true;
                    }
                }
            }
            Event::Code(text) if in_paragraph && !in_image => {
                let len = text.chars().count();
                current_len += len;
                if text.chars().any(|ch| !ch.is_whitespace()) {
                    has_non_whitespace = true;
                }
            }
            Event::Code(text) if !in_paragraph && !in_image => {
                if let Some(item_stats) = item_stack.last_mut() {
                    let len = text.chars().count();
                    item_stats.current_len += len;
                    if text.chars().any(|ch| !ch.is_whitespace()) {
                        item_stats.has_non_whitespace = true;
                    }
                }
            }
            Event::FootnoteReference(text) if in_paragraph && !in_image => {
                let len = text.chars().count();
                current_len += len;
                if !text.is_empty() {
                    has_non_whitespace = true;
                }
            }
            Event::FootnoteReference(text) if !in_paragraph && !in_image => {
                if let Some(item_stats) = item_stack.last_mut() {
                    let len = text.chars().count();
                    item_stats.current_len += len;
                    if !text.is_empty() {
                        item_stats.has_non_whitespace = true;
                    }
                }
            }
            Event::SoftBreak | Event::HardBreak if in_paragraph => {
                current_len += 1;
            }
            Event::SoftBreak | Event::HardBreak if !in_paragraph => {
                if let Some(item_stats) = item_stack.last_mut() {
                    item_stats.current_len += 1;
                }
            }
            _ => {}
        }
    }

    stats
}

fn count_text_stats_excluding_placeholders(text: &str) -> (usize, bool) {
    const PREFIX: &str = "SHORTCODE_HASH_";
    const HASH_LEN: usize = 128;

    let bytes = text.as_bytes();
    let mut index = 0;
    let mut count = 0usize;
    let mut has_non_whitespace = false;

    while index < bytes.len() {
        if bytes[index..].starts_with(PREFIX.as_bytes()) {
            let after_prefix = index + PREFIX.len();
            if bytes.len() >= after_prefix + HASH_LEN
                && bytes[after_prefix..after_prefix + HASH_LEN]
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                index = after_prefix + HASH_LEN;
                continue;
            }
        }

        let ch = match text[index..].chars().next() {
            Some(ch) => ch,
            None => break,
        };
        count += 1;
        if !ch.is_whitespace() {
            has_non_whitespace = true;
        }
        index += ch.len_utf8();
    }

    (count, has_non_whitespace)
}

fn post_process_html(
    html: String,
    current_md_path: &str,
    cache: &PageMetaCache,
) -> Result<String, MarkdownRenderError> {
    let external_regex = match EXTERNAL_LINK_REGEX.as_ref() {
        Ok(regex) => regex,
        Err(err) => {
            return Err(MarkdownRenderError::Regex(format!(
                "External link regex failed to compile: {}",
                err
            )));
        }
    };

    // Add target="_blank" to external links, preserving other attributes
    let html = external_regex.replace_all(&html, |caps: &regex::Captures| {
        let href = &caps[1];
        let other_attrs = &caps[2];
        if other_attrs.contains("target=") {
            caps[0].to_string()
        } else {
            format!(r#"<a href="{}"{} target="_blank">"#, href, other_attrs)
        }
    });

    let local_regex = match LOCAL_LINK_REGEX.as_ref() {
        Ok(regex) => regex,
        Err(err) => {
            return Err(MarkdownRenderError::Regex(format!(
                "Local link regex failed to compile: {}",
                err
            )));
        }
    };

    // Convert local file links (non-markdown, non-image) to download links
    let html = local_regex.replace_all(&html, |caps: &regex::Captures| {
        let url = &caps[1];
        let other_attrs = &caps[2];

        // Skip external links (already processed above)
        if url.starts_with("http://") || url.starts_with("https://") {
            return caps[0].to_string();
        }

        // Security check: block path traversal in local links (legacy check without request context)
        if security::route_checks_legacy(url).is_some() {
            return caps[0].to_string(); // Keep original if invalid
        }

        let normalized = match security::normalize_relative_path(current_md_path, url) {
            Some(path) => path,
            None => return caps[0].to_string(),
        };

        let object = match cache.get_by_alias(&normalized) {
            Some(object) => object,
            None => return caps[0].to_string(),
        };

        if object.is_markdown || object.mime.starts_with("image/") {
            return caps[0].to_string();
        }

        if other_attrs.contains("target=") {
            caps[0].to_string()
        } else {
            format!(r#"<a href="{}"{} target="_blank">"#, url, other_attrs)
        }
    });

    Ok(html.to_string())
}

fn process_event<'a>(event: Event<'a>, current_md_path: &str, cache: &PageMetaCache) -> Event<'a> {
    match event {
        Event::Start(Tag::Image(link_type, dest_url, title)) => {
            // Handle image links
            let url_str = dest_url.as_ref();

            // Security check: block path traversal in image paths
            if security::route_checks_legacy(url_str).is_some() {
                return Event::Html("<div class=\"notification is-danger\">Error: Invalid image path detected</div>".into());
            }

            // Check if it's a /img path - show error instead
            if url_str.starts_with("/img") {
                return Event::Html("<div class=\"notification is-danger\">Error: /img path is invalid for images</div>".into());
            }

            // Check if it's an external URL
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                // External image - keep as is
                return Event::Start(Tag::Image(link_type, dest_url, title));
            }

            let normalized_path = match security::normalize_relative_path(current_md_path, url_str)
            {
                Some(path) => path,
                None => {
                    return Event::Html(
                        "<div class=\"notification is-danger\">Error: Invalid image path</div>"
                            .into(),
                    );
                }
            };

            let object = match cache.get_by_alias(&normalized_path) {
                Some(object) => object,
                None => {
                    return Event::Html(
                        "<div class=\"notification is-warning\">Error: Image not found</div>"
                            .into(),
                    );
                }
            };

            if !object.mime.starts_with("image/") {
                return Event::Html(
                    "<div class=\"notification is-warning\">Error: Image not found or invalid format</div>"
                        .into(),
                );
            }

            if let Some(versioned_url) =
                version_asset_url_if_needed(url_str, current_md_path, cache)
            {
                Event::Start(Tag::Image(
                    link_type,
                    CowStr::Boxed(versioned_url.into()),
                    title,
                ))
            } else {
                Event::Start(Tag::Image(link_type, dest_url, title))
            }
        }
        Event::Start(Tag::Link(link_type, dest_url, title)) => {
            // Handle links by modifying attributes
            let url_str = dest_url.as_ref();

            // Check if it's an external URL
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                // For external links, we'll handle this in a post-processing step
                Event::Start(Tag::Link(link_type, dest_url, title))
            } else {
                // For local links, validate using new routing-based logic

                // Basic security check: block path traversal in link paths
                if security::route_checks_legacy(url_str).is_some() {
                    return Event::Html("Invalid link".into());
                }

                // Normalize the relative path
                let normalized_path =
                    match security::normalize_relative_path(current_md_path, url_str) {
                        Some(path) => path,
                        None => {
                            return Event::Html("Invalid link".into());
                        }
                    };

                // Validate using cache and routing rules
                if !security::is_link_valid(&normalized_path, cache) {
                    return Event::Html("Invalid link".into());
                }

                if let Some(versioned_url) =
                    version_asset_url_if_needed(url_str, current_md_path, cache)
                {
                    Event::Start(Tag::Link(
                        link_type,
                        CowStr::Boxed(versioned_url.into()),
                        title,
                    ))
                } else {
                    Event::Start(Tag::Link(link_type, dest_url, title))
                }
            }
        }
        _ => event,
    }
}

fn version_asset_url_if_needed(
    original_url: &str,
    current_md_path: &str,
    cache: &PageMetaCache,
) -> Option<String> {
    let trimmed = original_url.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("data:")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
    {
        return None;
    }

    let (path_without_fragment, fragment) = split_fragment(trimmed);
    let (path_part, existing_query) = split_query(path_without_fragment);
    if path_part.is_empty() {
        return None;
    }

    let normalized = security::normalize_relative_path(current_md_path, path_part)?;
    let object = cache.get_by_alias(&normalized)?;
    if object.is_markdown {
        return None;
    }
    let version = object.key.version.0.to_string();

    let mut query_parts: Vec<String> = Vec::new();

    if let Some(existing_query) = existing_query {
        query_parts.extend(
            existing_query
                .split('&')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );
    }

    query_parts.push(format!("v={}", version));

    let mut new_url = String::from(path_part);
    new_url.push('?');
    new_url.push_str(&query_parts.join("&"));

    if let Some(fragment_value) = fragment {
        new_url.push('#');
        new_url.push_str(fragment_value);
    }

    Some(new_url)
}

fn split_fragment(url: &str) -> (&str, Option<&str>) {
    if let Some(idx) = url.find('#') {
        (&url[..idx], Some(&url[idx + 1..]))
    } else {
        (url, None)
    }
}

fn split_query(url: &str) -> (&str, Option<&str>) {
    if let Some(idx) = url.find('?') {
        (&url[..idx], Some(&url[idx + 1..]))
    } else {
        (url, None)
    }
}

#[cfg(test)]
mod tests {
    use super::super::render::generate_html_page_with_user;
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config,
    };
    use crate::content::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use crate::public::PageRenderContext;
    use crate::public::nav::generate_navigation_with_user;
    use crate::public::shortcode::{ShortcodeRegistry, link_card, video};
    use crate::runtime_paths::RuntimePaths;
    use crate::templates::MiniJinjaEngine;
    use crate::util::ReleaseTracker;
    use crate::util::test_fixtures::TestFixtureRoot;
    use gray_matter::{Matter, engine::YAML};
    use pulldown_cmark::Options;
    use std::fs;
    use std::sync::Arc;
    use tokio::runtime::Builder;

    /// Create a default shortcode registry with built-in handlers (for tests only)
    fn create_default_registry() -> ShortcodeRegistry {
        let mut registry = ShortcodeRegistry::new();

        // Register the basic shortcode handlers
        let templates = Arc::new(MiniJinjaEngine::new());
        let video_engine = templates.clone();
        registry.register(
            "video",
            move |shortcode, _ctx| video::handle_video_shortcode(shortcode, video_engine.as_ref()),
            false,
        );
        let link_card_engine = templates.clone();
        registry.register(
            "link-card",
            move |shortcode, _ctx| {
                link_card::handle_link_card_shortcode(shortcode, link_card_engine.as_ref())
            },
            false,
        );

        registry
    }

    // Helper function to create a test config
    fn create_test_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: crate::config::test_server_list(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
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
                allowed_extensions: vec!["jpg".to_string(), "mp4".to_string()],
            },
            streaming: StreamingConfig { enabled: true },
            shortcodes: ShortcodeConfig {
                start_unibox: "https://duckduckgo.com?q=<QUERY>".to_string(),
            },
            rendering: RenderingConfig::default(),
            dev_mode: None,
        }
    }

    fn create_fixture_paths(prefix: &str) -> (TestFixtureRoot, RuntimePaths) {
        let fixture = TestFixtureRoot::new_unique(prefix).expect("fixture root");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        (fixture, runtime_paths)
    }

    // Helper function to create test markdown content with front matter
    fn create_test_markdown(content: &str) -> gray_matter::ParsedEntity {
        let matter = Matter::<YAML>::new();
        let full_content = format!("---\ntitle: Test Page\n---\n{}", content);
        matter.parse(&full_content)
    }

    // Helper function to create a test cache for tests
    fn create_test_cache(runtime_paths: &RuntimePaths) -> PageMetaCache {
        PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            crate::content::reserved_paths::ReservedPaths::default(),
        )
    }

    fn create_test_sanitizer() -> HtmlSanitizer {
        HtmlSanitizer::new()
    }

    #[test]
    fn test_generate_html_pure_markdown() {
        // Test pure markdown rendering without any shortcodes
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-basic");
        let registry = create_default_registry();
        let mut options = Options::empty();
        options.insert(Options::ENABLE_STRIKETHROUGH);
        options.insert(Options::ENABLE_TABLES);
        options.insert(Options::ENABLE_FOOTNOTES);
        options.insert(Options::ENABLE_TASKLISTS);

        let markdown_content = r#"# Test Heading

This is a **bold** text and *italic* text.

- List item 1
- List item 2

```rust
fn hello() {
    println!("Hello, world!");
}
```

| Column 1 | Column 2 |
|----------|----------|
| Data 1   | Data 2   |
| Data 3   | Data 4   |

Here's a [link to example](https://example.com).

~~Strikethrough text~~

- [x] Task completed
- [ ] Task pending
"#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check basic markdown elements are rendered
        assert!(html.contains("<h1>Test Heading</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<em>italic</em>"));
        assert!(html.contains("<ul>"));
        assert!(html.contains("<li>List item 1</li>"));
        assert!(html.contains("<li>List item 2</li>"));
        assert!(html.contains("<pre><code>"));
        assert!(html.contains("fn hello()"));
        assert!(html.contains("<table>"));
        assert!(html.contains("<th>Column 1</th>"));
        assert!(html.contains("<td>Data 1</td>"));
        assert!(html.contains(r#"<a href="https://example.com""#));
        assert!(html.contains("<del>Strikethrough text</del>"));
        assert!(html.contains("Task completed"));
        assert!(html.contains("Task pending"));

        // Check that no shortcode processing occurred
        assert!(!html.contains("SHORTCODE_PLACEHOLDER"));
        assert!(!html.contains("<!--SHORTCODE_START"));

        // Check external links get target="_blank" (from post-processing)
        assert!(html.contains(
            r#"<a href="https://example.com" rel="noopener noreferrer" target="_blank""#
        ));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_video_shortcode() {
        // Test video shortcode rendering
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-video");
        let registry = create_default_registry();
        let mut options = Options::empty();
        options.insert(Options::ENABLE_STRIKETHROUGH);

        let markdown_content = r#"# Video Test

Here's a video:

((video src="test.mp4" width="640" height="480"))

And another video with controls disabled:

((video src="test2.mp4" controls="false"))

Some text after the videos."#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check that shortcode placeholders are not present in final output
        assert!(!html.contains("SHORTCODE_PLACEHOLDER"));
        assert!(!html.contains("<!--SHORTCODE_START"));
        assert!(!html.contains("((video"));

        // Check that video elements are present with correct attributes
        assert!(html.contains(r#"<video src="test.mp4""#));
        assert!(html.contains(r#"width="640""#));
        assert!(html.contains(r#"height="480""#));
        assert!(html.contains("controls"));

        // Check second video
        assert!(html.contains(r#"<video src="test2.mp4""#));
        // Second video should not have controls attribute since it was set to false
        let test2_video_start = html.find(r#"<video src="test2.mp4""#).unwrap();
        let test2_video_end =
            html[test2_video_start..].find("</video>").unwrap() + test2_video_start + 8;
        let test2_video_html = &html[test2_video_start..test2_video_end];
        assert!(!test2_video_html.contains(" controls"));

        // Check that video fallback text is present (allow for whitespace variations)
        assert!(html.contains("Your browser does not support the video") && html.contains("tag."));

        // Check that regular markdown is still processed
        assert!(html.contains("<h1>Video Test</h1>"));
        assert!(html.contains("Some text after the videos."));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_video_shortcode_missing_src() {
        // Test video shortcode error handling when src is missing
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-video-missing-src");
        let registry = create_default_registry();
        let options = Options::empty();

        let markdown_content = r#"# Video Error Test

Here's a video without src:

((video width="640"))

Some text after."#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check that original shortcode is left in place when there's an error
        assert!(html.contains("((video width=\"640\"))"));

        // Check that no video element is present
        assert!(!html.contains("<video"));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_link_card_shortcode() {
        // Test link-card shortcode rendering
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-link-card");
        let registry = create_default_registry();
        let options = Options::empty();

        let markdown_content = r#"# Link Card Test

Here's a link card:

((link-card title="Example Site" link="https://example.com"))

And another one:

((link-card title="GitHub" link="https://github.com"))

Some text after the cards."#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check that shortcode strings are not present in final output (they should be replaced)
        assert!(!html.contains("((link-card"));
        assert!(!html.contains("SHORTCODE_PLACEHOLDER"));
        assert!(!html.contains("<!--SHORTCODE_START"));

        // Check that link cards are present with correct structure
        assert!(html.contains(r#"<a href="https://example.com""#));
        assert!(html.contains(r#"target="_blank""#));
        assert!(html.contains(r#"rel="noopener noreferrer""#));
        assert!(html.contains(r#"<p class="title">Example Site</p>"#));

        // Check second link card
        assert!(html.contains(r#"<a href="https://github.com""#));
        assert!(html.contains(r#"<p class="title">GitHub</p>"#));

        // Check that CSS styles are included
        assert!(html.contains("<style>"));
        assert!(html.contains(".link-card-"));
        assert!(html.contains("background-color:"));
        assert!(html.contains("@media (prefers-color-scheme: dark)"));
        assert!(html.contains("@media (max-width: 768px)"));

        // Check that regular markdown is still processed
        assert!(html.contains("<h1>Link Card Test</h1>"));
        assert!(html.contains("Some text after the cards."));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_link_card_shortcode_missing_attributes() {
        // Test link-card shortcode error handling when required attributes are missing
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-link-card-missing");
        let registry = create_default_registry();
        let options = Options::empty();

        let markdown_content = r#"# Link Card Error Test

Missing title:
((link-card link="https://example.com"))

Missing link:
((link-card title="Example"))

Missing both:
((link-card))

Some text after."#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check that original shortcodes are left in place when there are errors
        assert!(html.contains(r#"((link-card link="https://example.com"))"#));
        assert!(html.contains(r#"((link-card title="Example"))"#));
        assert!(html.contains("((link-card))"));

        // Check that no actual link elements are present
        assert!(!html.contains(r#"<a href=""#));
        assert!(!html.contains(r#"<p class="title">"#));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_mixed_content() {
        // Test markdown with both video and link-card shortcodes plus regular content
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-mixed");
        let registry = create_default_registry();
        let mut options = Options::empty();
        options.insert(Options::ENABLE_STRIKETHROUGH);
        options.insert(Options::ENABLE_TABLES);

        let markdown_content = r#"# Mixed Content Test

Some **bold text** before shortcodes.

## Video Section

((video src="demo.mp4" width="800" height="600"))

## Link Cards Section

((link-card title="First Link" link="https://first.com"))

| Feature | Status |
|---------|--------|
| Videos  | ✅     |
| Cards   | ✅     |

((link-card title="Second Link" link="https://second.com"))

## More Content

Another video:

((video src="outro.mp4" controls="false"))

End of content with ~~strikethrough~~."#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check that all shortcodes were processed
        assert!(!html.contains("((video"));
        assert!(!html.contains("((link-card"));
        assert!(!html.contains("SHORTCODE_PLACEHOLDER"));

        // Check video elements
        assert!(html.contains(r#"<video src="demo.mp4""#));
        assert!(html.contains(r#"width="800""#));
        assert!(html.contains(r#"<video src="outro.mp4""#));

        // Check link cards
        assert!(html.contains(r#"<a href="https://first.com""#));
        assert!(html.contains(r#"<p class="title">First Link</p>"#));
        assert!(html.contains(r#"<a href="https://second.com""#));
        assert!(html.contains(r#"<p class="title">Second Link</p>"#));

        // Check regular markdown
        assert!(html.contains("<h1>Mixed Content Test</h1>"));
        assert!(html.contains("<h2>Video Section</h2>"));
        assert!(html.contains("<strong>bold text</strong>"));
        assert!(html.contains("<table>"));
        assert!(html.contains("<th>Feature</th>"));
        assert!(html.contains("<td>Videos</td>"));
        assert!(html.contains("<del>strikethrough</del>"));

        // Check that content order is preserved
        let bold_pos = html.find("<strong>bold text</strong>").unwrap();
        let first_video_pos = html.find(r#"<video src="demo.mp4""#).unwrap();
        let first_card_pos = html.find(r#"<a href="https://first.com""#).unwrap();
        let table_pos = html.find("<table>").unwrap();
        let second_card_pos = html.find(r#"<a href="https://second.com""#).unwrap();
        let second_video_pos = html.find(r#"<video src="outro.mp4""#).unwrap();

        assert!(bold_pos < first_video_pos);
        assert!(first_video_pos < first_card_pos);
        assert!(first_card_pos < table_pos);
        assert!(table_pos < second_card_pos);
        assert!(second_card_pos < second_video_pos);
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_html_sanitization() {
        // Test that HTML sanitization works correctly - user content should be sanitized,
        // but shortcode content should be preserved
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-sanitize");
        let registry = create_default_registry();
        let options = Options::empty();

        let markdown_content = r#"# Security Test

User content with dangerous HTML: <script>alert('xss')</script>

Also dangerous: <iframe src="evil.com"></iframe>

Video shortcode: ((video src="safe.mp4" width="640"))

More user content: <object data="bad.swf"></object>

Link card: ((link-card title="Safe Link" link="https://safe.com"))

JavaScript in user content: <a href="javascript:alert('bad')">bad link</a>"#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check that dangerous HTML from user content is removed
        assert!(!html.contains("<script>"));
        assert!(!html.contains("alert('xss')"));
        assert!(!html.contains("<iframe"));
        assert!(!html.contains("evil.com"));
        assert!(!html.contains("<object"));
        assert!(!html.contains("bad.swf"));
        assert!(!html.contains("javascript:alert"));

        // Check that shortcode-generated HTML is preserved
        assert!(html.contains(r#"<video src="safe.mp4""#));
        assert!(html.contains(r#"width="640""#));
        assert!(html.contains(r#"<a href="https://safe.com""#));
        assert!(html.contains(r#"<p class="title">Safe Link</p>"#));

        // Check that safe user content is preserved
        assert!(html.contains("<h1>Security Test</h1>"));
        assert!(html.contains("User content with dangerous HTML"));
        assert!(html.contains("More user content"));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_no_shortcodes() {
        // Test that content without shortcodes is processed normally
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-no-shortcodes");
        let registry = create_default_registry();
        let options = Options::empty();

        let markdown_content = r#"# No Shortcodes

This content has no shortcodes at all.

Just regular **markdown** content.

- Item 1
- Item 2

[External link](https://example.com)"#;

        let parsed_entity = create_test_markdown(markdown_content);
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed_entity,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            None,
            256,
        )
        .expect("render markdown");
        let html = rendered.html;

        // Check that regular markdown is processed
        assert!(html.contains("<h1>No Shortcodes</h1>"));
        assert!(html.contains("<strong>markdown</strong>"));
        assert!(html.contains("<ul>"));
        assert!(html.contains("<li>Item 1</li>"));

        // Check that external link gets target="_blank"
        assert!(html.contains(
            r#"<a href="https://example.com" rel="noopener noreferrer" target="_blank""#
        ));

        // Check that no shortcode processing artifacts are present
        assert!(!html.contains("SHORTCODE_PLACEHOLDER"));
        assert!(!html.contains("<!--SHORTCODE_START"));
        assert!(!html.contains("<video"));
        assert!(!html.contains("link-card"));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_full_page_with_theme_and_markdown() {
        let fixture = TestFixtureRoot::new_unique("markdown-full-page").expect("fixture root");
        fixture.init_runtime_layout().expect("layout init");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        let blue_theme = r#"<style>
/* Blue Theme - Cool and professional */
.test-theme { color: #3366ff; }
</style>"#;
        fs::write(runtime_paths.themes_dir.join("blue.html"), blue_theme)
            .expect("write blue theme");
        let markdown_content = "# About NoPressure\n\nFlat storage content test.";
        let content_id = ContentId(1);
        let content_version = ContentVersion(1);
        let blob_path = blob_path(&runtime_paths.content_dir, content_id, content_version);
        if let Some(parent) = blob_path.parent() {
            fs::create_dir_all(parent).expect("create shard dir");
        }
        fs::write(&blob_path, markdown_content.as_bytes()).expect("write blob");
        let sidecar = ContentSidecar {
            alias: "about".to_string(),
            title: Some("About NoPressure".to_string()),
            mime: "text/markdown".to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: Some("about.md".to_string()),
            theme: Some("blue".to_string()),
        };
        let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, content_version);
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");

        let config = create_test_config();
        let registry = create_default_registry();

        let mut options = Options::empty();
        options.insert(Options::ENABLE_STRIKETHROUGH);
        options.insert(Options::ENABLE_TABLES);
        options.insert(Options::ENABLE_FOOTNOTES);
        options.insert(Options::ENABLE_TASKLISTS);

        let cache = PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            crate::content::reserved_paths::ReservedPaths::default(),
        );
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime
            .block_on(cache.rebuild_cache(true))
            .expect("cache rebuild");

        let parsed = Matter::<YAML>::new().parse(markdown_content);
        let title = sidecar.title.as_deref().expect("sidecar title");
        let theme = sidecar.theme.as_deref();

        let sanitizer = create_test_sanitizer();
        let rendered = generate_html(
            &parsed, &registry, &options, &sanitizer, &cache, "about", None, 256,
        )
        .expect("render markdown");
        let navigation = generate_navigation_with_user(&cache, None);
        let release_tracker = ReleaseTracker::new();
        let templates = MiniJinjaEngine::new();

        let render_ctx = PageRenderContext {
            config: &config,
            runtime_paths: &runtime_paths,
            theme,
            user: None,
            release_tracker: &release_tracker,
            template_engine: &templates,
        };
        let html_page = runtime.block_on(generate_html_page_with_user(
            title,
            &rendered.html,
            &navigation,
            rendered.use_compact_width,
            &render_ctx,
        ));

        assert!(html_page.contains("<title>About NoPressure</title>"));
        assert!(html_page.contains("<h1>About NoPressure</h1>"));
        assert!(html_page.contains("Blue Theme - Cool and professional"));
        assert!(html_page.contains("Test App"));
        assert!(html_page.contains("/builtin/bulma.min.css?v="));
        assert!(!html_page.contains("{title}"));
        assert!(!html_page.contains("{content}"));
        assert!(!html_page.contains("{nav_html}"));
        assert!(!html_page.contains("{user_nav_html}"));
    }

    fn make_paragraph(len: usize) -> String {
        "a".repeat(len)
    }

    #[test]
    fn compact_width_defaults_when_all_short() {
        let short = make_paragraph(10);
        let markdown = format!("{short}\n\n{short}");
        let options = Options::empty();
        assert!(should_use_compact_width(&markdown, &options, 256));
    }

    #[test]
    fn compact_width_skips_when_any_long() {
        let short = make_paragraph(10);
        let long = make_paragraph(300);
        let markdown = format!("{short}\n\n{long}");
        let options = Options::empty();
        assert!(!should_use_compact_width(&markdown, &options, 256));
    }

    #[test]
    fn compact_width_disabled_when_threshold_zero() {
        let short = make_paragraph(10);
        let markdown = format!("{short}\n\n{short}");
        let options = Options::empty();
        assert!(!should_use_compact_width(&markdown, &options, 0));
    }

    #[test]
    fn compact_width_counts_tight_list_items() {
        let short = make_paragraph(10);
        let markdown = format!("- {short}\n- {short}");
        let options = Options::empty();
        assert!(should_use_compact_width(&markdown, &options, 256));
    }

    #[test]
    fn compact_width_skips_tight_list_items_when_any_long() {
        let short = make_paragraph(10);
        let long = make_paragraph(300);
        let markdown = format!("- {short}\n- {long}\n- {long}");
        let options = Options::empty();
        assert!(!should_use_compact_width(&markdown, &options, 256));
    }

    #[test]
    fn compact_width_ignores_shortcode_placeholders() {
        let placeholder = format!("SHORTCODE_HASH_{}", "a".repeat(128));
        let markdown = format!("{placeholder} {placeholder} {placeholder}");
        let options = Options::empty();
        assert!(should_use_compact_width(&markdown, &options, 256));
    }

    #[test]
    fn compact_width_ignores_image_only_paragraphs() {
        let short = make_paragraph(10);
        let markdown = format!("![alt](/id/abcdef)\n\n{short}\n\n{short}");
        let options = Options::empty();
        assert!(should_use_compact_width(&markdown, &options, 256));
    }
}
