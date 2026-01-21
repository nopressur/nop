// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::iam::User;
use crate::public::page_meta_cache::PageMetaCache;
use crate::util::ReleaseTracker;
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, take_until, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0, multispace1},
    combinator::{map, recognize},
    multi::many0,
    sequence::{delimited, pair, preceded, separated_pair, tuple},
};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Arc;

use crate::templates::TemplateEngine;

pub mod link_card;
pub mod tag_list;
pub mod unibox;
pub mod video;

// Type alias for complex shortcode handler function
type ShortcodeHandler =
    Box<dyn Fn(&Shortcode, &ShortcodeContext<'_>) -> Result<String, String> + Send + Sync>;

struct ShortcodeMetadata {
    handler: ShortcodeHandler,
    is_dynamic: bool,
}

/// Represents a parsed shortcode with its name and attributes
#[derive(Debug, Clone)]
pub struct Shortcode {
    pub name: String,
    pub attributes: HashMap<String, String>,
}

pub struct ShortcodeContext<'a> {
    pub cache: &'a PageMetaCache,
    pub user: Option<&'a User>,
}

/// Produce a canonical string for a shortcode to support stable hashing/caching
fn normalize_shortcode(shortcode: &Shortcode) -> String {
    let mut sorted_attrs: Vec<_> = shortcode.attributes.iter().collect();
    sorted_attrs.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let mut result = format!("(({}", shortcode.name);
    for (key, value) in sorted_attrs {
        if value.is_empty() {
            result.push_str(&format!(" {}", key));
        } else {
            result.push_str(&format!(r#" {}="{}""#, key, value));
        }
    }
    result.push_str("))");
    result
}

/// Registry for storing and managing shortcode handlers
pub struct ShortcodeRegistry {
    handlers: HashMap<String, ShortcodeMetadata>,
    release_tracker: Option<ReleaseTracker>,
}

impl ShortcodeRegistry {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_tracker(None)
    }

    pub fn with_tracker(tracker: Option<ReleaseTracker>) -> Self {
        ShortcodeRegistry {
            handlers: HashMap::new(),
            release_tracker: tracker,
        }
    }

    /// Register a new shortcode handler
    pub fn register<F>(&mut self, name: &str, handler: F, is_dynamic: bool)
    where
        F: Fn(&Shortcode, &ShortcodeContext<'_>) -> Result<String, String> + Send + Sync + 'static,
    {
        self.handlers.insert(
            name.to_string(),
            ShortcodeMetadata {
                handler: Box::new(handler),
                is_dynamic,
            },
        );
        if let Some(tracker) = &self.release_tracker {
            tracker.bump(&format!("shortcode registry mutation ({})", name));
        }
    }

    /// Process a shortcode using its registered handler
    /// Returns Some(Ok(html)) for success, Some(Err(error)) for handler errors, None for unknown shortcodes
    pub fn process(
        &self,
        shortcode: &Shortcode,
        ctx: &ShortcodeContext<'_>,
    ) -> Option<Result<String, String>> {
        self.handlers
            .get(&shortcode.name)
            .map(|metadata| (metadata.handler)(shortcode, ctx))
    }

    /// Check whether a shortcode is registered as dynamic
    pub fn is_dynamic(&self, name: &str) -> Option<bool> {
        self.handlers.get(name).map(|metadata| metadata.is_dynamic)
    }

    /// Return a sorted list of registered shortcode names.
    pub fn registered_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.handlers.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Generate a SHA-512 hash for a shortcode using its normalized representation
fn generate_shortcode_hash(shortcode: &Shortcode) -> String {
    let normalized = normalize_shortcode(shortcode);
    let mut hasher = Sha512::new();
    hasher.update(normalized.as_bytes());
    let result = hasher.finalize();
    format!("SHORTCODE_HASH_{:x}", result)
}

pub struct ShortcodeProcessingResult {
    pub processed_text: String,
    pub hash_to_html_map: HashMap<String, String>,
    pub contains_dynamic_shortcodes: bool,
}

/// Process text content looking for shortcodes and replace them with hash placeholders
/// Returns metadata used by the renderer to determine cacheability.
pub fn process_text_with_shortcodes(
    text: &str,
    registry: &ShortcodeRegistry,
    ctx: &ShortcodeContext<'_>,
) -> ShortcodeProcessingResult {
    // If there are no shortcode markers, no processing is needed.
    if !text.contains("((") {
        return ShortcodeProcessingResult {
            processed_text: text.to_string(),
            hash_to_html_map: HashMap::new(),
            contains_dynamic_shortcodes: false,
        };
    }

    let mut hash_to_html_map = HashMap::new();
    let mut processed_shortcodes: HashMap<String, String> = HashMap::new(); // Cache for already processed shortcodes keyed by normalized form
    let mut result_text = String::new();
    let mut last_end = 0;
    let mut contains_dynamic_shortcodes = false;

    while last_end < text.len() {
        // Look for the next shortcode starting from last_end
        if let Some(start_pos) = text[last_end..].find("((") {
            let actual_start = last_end + start_pos;

            // Add text before shortcode to result
            result_text.push_str(&text[last_end..actual_start]);

            // Try to parse shortcode from this position
            if let Some((shortcode, consumed)) = parse_shortcode(&text[actual_start..]) {
                // Get the original shortcode string
                let shortcode_string = &text[actual_start..actual_start + consumed];

                let is_dynamic = registry.is_dynamic(&shortcode.name).unwrap_or(false);
                if is_dynamic {
                    contains_dynamic_shortcodes = true;
                }
                let normalized_shortcode = normalize_shortcode(&shortcode);
                let hash_placeholder = generate_shortcode_hash(&shortcode);

                // Check if we've already processed this normalized shortcode (if cacheable)
                log::trace!(
                    "Rendering shortcode '{}' (dynamic={})",
                    shortcode.name,
                    is_dynamic
                );
                let rendered_result = if !is_dynamic {
                    if let Some(cached_html) = processed_shortcodes.get(&normalized_shortcode) {
                        log::debug!(
                            "Using cached shortcode rendering for normalized form: {}",
                            normalized_shortcode
                        );
                        Some(Ok(cached_html.clone()))
                    } else {
                        // Try to render the shortcode
                        registry.process(&shortcode, ctx)
                    }
                } else {
                    registry.process(&shortcode, ctx)
                };

                match rendered_result {
                    Some(Ok(html)) => {
                        // Cache the successful rendering
                        if !is_dynamic {
                            processed_shortcodes.insert(normalized_shortcode.clone(), html.clone());
                        }

                        // Store the mapping from hash to rendered HTML
                        hash_to_html_map.insert(hash_placeholder.clone(), html);

                        // Add hash placeholder to result text
                        result_text.push_str(&hash_placeholder);

                        // Move past processed shortcode
                        last_end = actual_start + consumed;
                    }
                    Some(Err(_error)) => {
                        // Shortcode handler error - leave original shortcode in place
                        log::debug!(
                            "Shortcode '{}' failed to render - leaving original shortcode in place",
                            shortcode.name
                        );
                        result_text.push_str(shortcode_string);
                        last_end = actual_start + consumed;
                    }
                    None => {
                        // Unknown shortcode - leave it unaltered for user correction
                        log::trace!("Unknown shortcode '{}' - leaving unaltered", shortcode.name);
                        result_text.push_str("((");
                        last_end = actual_start + 2;
                    }
                }
            } else {
                // Not a valid shortcode, add the "((" and move past it
                result_text.push_str("((");
                last_end = actual_start + 2;
            }
        } else {
            // No more shortcodes found, add remaining text
            result_text.push_str(&text[last_end..]);
            break;
        }
    }

    ShortcodeProcessingResult {
        processed_text: result_text,
        hash_to_html_map,
        contains_dynamic_shortcodes,
    }
}

/// Replace hash placeholders in text with their corresponding rendered HTML
pub fn replace_shortcode_placeholders(
    text: &str,
    hash_to_html_map: &HashMap<String, String>,
) -> String {
    let mut result = text.to_string();

    for (hash_placeholder, html) in hash_to_html_map {
        log::trace!(
            "Replacing hash placeholder '{}' with HTML: '{}'",
            hash_placeholder,
            html
        );
        result = result.replace(hash_placeholder, html);
    }

    result
}

// Nom parser implementation for shortcodes
// Parse shortcode name: alphanumeric with hyphens and underscores
fn shortcode_name(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"), tag("-"))),
        many0(alt((alphanumeric1, tag("-"), tag("_")))),
    ))(input)
}

// Parse quoted string value
fn quoted_value(input: &str) -> IResult<&str, &str> {
    delimited(char('"'), take_until("\""), char('"'))(input)
}

// Parse unquoted value (numbers, booleans, or simple strings without spaces)
fn unquoted_value(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| !c.is_whitespace() && c != ')')(input)
}

// Parse attribute value (quoted or unquoted)
fn attribute_value(input: &str) -> IResult<&str, &str> {
    alt((quoted_value, unquoted_value))(input)
}

// Parse single attribute
fn attribute(input: &str) -> IResult<&str, (String, String)> {
    alt((
        // key="value" or key=value
        map(
            separated_pair(
                shortcode_name,
                delimited(multispace0, char('='), multispace0),
                attribute_value,
            ),
            |(k, v)| (k.to_string(), v.to_string()),
        ),
        // standalone flag (e.g., "controls", "noblank")
        map(shortcode_name, |k| (k.to_string(), String::new())),
    ))(input)
}

// Parse shortcode content inside ((  ))
fn shortcode_content(input: &str) -> IResult<&str, Shortcode> {
    map(
        tuple((
            preceded(multispace0, shortcode_name),
            many0(preceded(multispace1, attribute)),
            multispace0,
        )),
        |(name, attrs, _)| Shortcode {
            name: name.to_string(),
            attributes: attrs.into_iter().collect(),
        },
    )(input)
}

// Parse complete shortcode with (( )) delimiters
fn nom_parse_shortcode(input: &str) -> IResult<&str, Shortcode> {
    delimited(tag("(("), shortcode_content, tag("))"))(input)
}

/// Parse a shortcode from text starting at the beginning using nom
/// Returns (Shortcode, consumed_bytes) if successful
fn parse_shortcode(text: &str) -> Option<(Shortcode, usize)> {
    match nom_parse_shortcode(text) {
        Ok((remaining, shortcode)) => {
            let consumed = text.len() - remaining.len();
            Some((shortcode, consumed))
        }
        Err(_) => None,
    }
}

/// Create a default shortcode registry with built-in handlers, including config-aware handlers
pub fn create_default_registry_with_config(
    config: &crate::config::ValidatedConfig,
    release_tracker: &ReleaseTracker,
    template_engine: Arc<dyn TemplateEngine>,
) -> ShortcodeRegistry {
    let mut registry = ShortcodeRegistry::with_tracker(Some(release_tracker.clone()));

    // Register the basic shortcode handlers
    let video_engine = template_engine.clone();
    registry.register(
        "video",
        move |shortcode, _ctx| video::handle_video_shortcode(shortcode, video_engine.as_ref()),
        false,
    );
    let link_card_engine = template_engine.clone();
    registry.register(
        "link-card",
        move |shortcode, _ctx| {
            link_card::handle_link_card_shortcode(shortcode, link_card_engine.as_ref())
        },
        false,
    );

    // Register config-aware handlers using closures to capture config
    let config_clone = config.clone();
    let unibox_engine = template_engine.clone();
    registry.register(
        "start-unibox",
        move |shortcode, _ctx| {
            unibox::handle_start_unibox_shortcode(shortcode, &config_clone, unibox_engine.as_ref())
        },
        false,
    );

    registry.register("tag-list", tag_list::handle_tag_list_shortcode, true);

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public::page_meta_cache::PageMetaCache;
    use std::path::PathBuf;

    /// Create a default shortcode registry with built-in handlers (for tests only)
    fn create_default_registry() -> ShortcodeRegistry {
        let mut registry = ShortcodeRegistry::new();

        // Register the basic shortcode handlers
        let templates = Arc::new(crate::templates::MiniJinjaEngine::new());
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

    fn build_test_cache() -> PageMetaCache {
        PageMetaCache::new(
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            crate::content::reserved_paths::ReservedPaths::default(),
        )
    }

    fn build_shortcode_context<'a>(cache: &'a PageMetaCache) -> ShortcodeContext<'a> {
        ShortcodeContext { cache, user: None }
    }

    #[test]
    fn test_shortcode_normalization_spacing() {
        let sc1 = parse_shortcode("((video src=\"test.mp4\" width=\"640\"))")
            .expect("parse sc1")
            .0;
        let sc2 = parse_shortcode("((video  src=\"test.mp4\"  width=\"640\"))")
            .expect("parse sc2")
            .0;
        let sc3 = parse_shortcode("((video src = \"test.mp4\" width = \"640\"))")
            .expect("parse sc3")
            .0;

        assert_eq!(generate_shortcode_hash(&sc1), generate_shortcode_hash(&sc2));
        assert_eq!(generate_shortcode_hash(&sc1), generate_shortcode_hash(&sc3));
    }

    #[test]
    fn test_shortcode_normalization_parameter_order() {
        let sc1 = parse_shortcode("((video src=\"test.mp4\" width=\"640\"))")
            .expect("parse sc1")
            .0;
        let sc2 = parse_shortcode("((video width=\"640\" src=\"test.mp4\"))")
            .expect("parse sc2")
            .0;

        assert_eq!(generate_shortcode_hash(&sc1), generate_shortcode_hash(&sc2));
    }

    #[test]
    fn test_shortcode_normalization_standalone_attributes() {
        let sc1 = parse_shortcode("((video src=\"test.mp4\" controls))")
            .expect("parse sc1")
            .0;
        let sc2 = parse_shortcode("((video controls src=\"test.mp4\"))")
            .expect("parse sc2")
            .0;

        assert_eq!(generate_shortcode_hash(&sc1), generate_shortcode_hash(&sc2));
    }

    #[test]
    fn test_parse_shortcode_simple() {
        let result = parse_shortcode("((video))");
        assert!(result.is_some());
        let (shortcode, consumed) = result.unwrap();
        assert_eq!(shortcode.name, "video");
        assert_eq!(consumed, 9);
        assert!(shortcode.attributes.is_empty());
    }

    #[test]
    fn test_parse_shortcode_with_attributes() {
        let result = parse_shortcode(r#"((video src="video.mp4" width="640"))"#);
        assert!(result.is_some());
        let (shortcode, consumed) = result.unwrap();
        assert_eq!(shortcode.name, "video");
        assert_eq!(consumed, 37);
        assert_eq!(shortcode.attributes.get("src").unwrap(), "video.mp4");
        assert_eq!(shortcode.attributes.get("width").unwrap(), "640");
    }

    #[test]
    fn test_parse_shortcode_with_hyphen() {
        let result = parse_shortcode("((link-card))");
        assert!(result.is_some());
        let (shortcode, consumed) = result.unwrap();
        assert_eq!(shortcode.name, "link-card");
        assert_eq!(consumed, 13);
        assert!(shortcode.attributes.is_empty());
    }

    #[test]
    fn test_process_text_with_shortcodes() {
        let registry = create_default_registry();
        let cache = build_test_cache();
        let ctx = build_shortcode_context(&cache);
        let text = r#"Before ((video src="test.mp4")) after"#;
        let result = process_text_with_shortcodes(text, &registry, &ctx);

        // Text should have shortcode replaced with hash placeholder
        assert!(result.processed_text.starts_with("Before SHORTCODE_HASH_"));
        assert!(result.processed_text.ends_with(" after"));

        // Should have one entry in the hash map
        assert_eq!(result.hash_to_html_map.len(), 1);

        // The mapped HTML should contain the video tag
        let video_html = result.hash_to_html_map.values().next().unwrap();
        assert!(video_html.contains(r#"<video src="test.mp4""#));
        assert!(!result.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_video_shortcode_missing_src() {
        let registry = create_default_registry();
        let cache = build_test_cache();
        let ctx = build_shortcode_context(&cache);
        let text = r#"((video width="800"))"#;
        let result = process_text_with_shortcodes(text, &registry, &ctx);

        // Text should have original shortcode left in place when there's an error
        assert_eq!(result.processed_text, r#"((video width="800"))"#);

        // Should have no entries in the hash map since shortcode failed
        assert_eq!(result.hash_to_html_map.len(), 0);
    }

    #[test]
    fn test_link_card_shortcode() {
        let registry = create_default_registry();
        let cache = build_test_cache();
        let ctx = build_shortcode_context(&cache);
        let text = r#"((link-card title="Hello" link="https://example.com"))"#;
        let result = process_text_with_shortcodes(text, &registry, &ctx);

        // Text should have shortcode replaced with hash placeholder
        assert!(result.processed_text.starts_with("SHORTCODE_HASH_"));

        // Should have one entry in the hash map
        assert_eq!(result.hash_to_html_map.len(), 1);

        // The mapped HTML should contain the link card
        let card_html = result.hash_to_html_map.values().next().unwrap();
        assert!(card_html.contains(r#"<a href="https://example.com""#));
        assert!(card_html.contains(r#"<p class="title">Hello</p>"#));
    }

    #[test]
    fn test_parse_shortcode_unquoted_values() {
        let result = parse_shortcode("((video src=video.mp4 width=640 height=480))");
        assert!(result.is_some());
        let (shortcode, consumed) = result.unwrap();
        assert_eq!(shortcode.name, "video");
        assert_eq!(consumed, 44);
        assert_eq!(shortcode.attributes.get("src").unwrap(), "video.mp4");
        assert_eq!(shortcode.attributes.get("width").unwrap(), "640");
        assert_eq!(shortcode.attributes.get("height").unwrap(), "480");
    }

    #[test]
    fn test_parse_shortcode_mixed_quoted_unquoted() {
        let result =
            parse_shortcode(r#"((video src="video with spaces.mp4" width=640 controls=true))"#);
        assert!(result.is_some());
        let (shortcode, consumed) = result.unwrap();
        assert_eq!(shortcode.name, "video");
        assert_eq!(consumed, 61);
        assert_eq!(
            shortcode.attributes.get("src").unwrap(),
            "video with spaces.mp4"
        );
        assert_eq!(shortcode.attributes.get("width").unwrap(), "640");
        assert_eq!(shortcode.attributes.get("controls").unwrap(), "true");
    }

    #[test]
    fn test_parse_shortcode_numerical_values() {
        let result = parse_shortcode("((test number=123 float=45.6 negative=-7))");
        assert!(result.is_some());
        let (shortcode, consumed) = result.unwrap();
        assert_eq!(shortcode.name, "test");
        assert_eq!(consumed, 42);
        assert_eq!(shortcode.attributes.get("number").unwrap(), "123");
        assert_eq!(shortcode.attributes.get("float").unwrap(), "45.6");
        assert_eq!(shortcode.attributes.get("negative").unwrap(), "-7");
    }

    #[test]
    fn test_process_text_with_unquoted_shortcodes() {
        let registry = create_default_registry();
        let cache = build_test_cache();
        let ctx = build_shortcode_context(&cache);
        let text = "Before ((video src=test.mp4 width=640)) after";
        let result = process_text_with_shortcodes(text, &registry, &ctx);

        // Text should have shortcode replaced with hash placeholder
        assert!(result.processed_text.starts_with("Before SHORTCODE_HASH_"));
        assert!(result.processed_text.ends_with(" after"));

        // Should have one entry in the hash map
        assert_eq!(result.hash_to_html_map.len(), 1);

        // The mapped HTML should contain the video tag
        let video_html = result.hash_to_html_map.values().next().unwrap();
        assert!(video_html.contains(r#"<video src="test.mp4""#));
        assert!(video_html.contains(r#"width="640""#));
    }

    #[test]
    fn test_link_card_with_query_parameters() {
        let registry = create_default_registry();
        let cache = build_test_cache();
        let ctx = build_shortcode_context(&cache);
        let text = r#"((link-card title="Mail Filters" link="https://roundcube.i.zivatar.net/?_task=settings&_action=plugin.managesieve"))"#;
        let result = process_text_with_shortcodes(text, &registry, &ctx);

        // Text should have shortcode replaced with hash placeholder
        assert!(result.processed_text.starts_with("SHORTCODE_HASH_"));

        // Should have one entry in the hash map
        assert_eq!(result.hash_to_html_map.len(), 1);

        // The mapped HTML should contain the link card
        let card_html = result.hash_to_html_map.values().next().unwrap();
        assert!(card_html.contains(r#"<a href="https://roundcube.i.zivatar.net/?_task=settings&_action=plugin.managesieve""#));
        assert!(card_html.contains(r#"<p class="title">Mail Filters</p>"#));
    }

    #[test]
    fn test_parse_shortcode_with_query_parameters() {
        let shortcode_text = r#"((link-card title="Mail Filters" link="https://roundcube.i.zivatar.net/?_task=settings&_action=plugin.managesieve"))"#;
        let result = parse_shortcode(shortcode_text);

        assert!(
            result.is_some(),
            "Should successfully parse shortcode with query parameters"
        );
        let (shortcode, consumed) = result.unwrap();
        assert_eq!(shortcode.name, "link-card");
        assert_eq!(shortcode.attributes.get("title").unwrap(), "Mail Filters");
        assert_eq!(
            shortcode.attributes.get("link").unwrap(),
            "https://roundcube.i.zivatar.net/?_task=settings&_action=plugin.managesieve"
        );
        assert_eq!(consumed, shortcode_text.len());
    }

    #[test]
    fn test_shortcode_caching() {
        let registry = create_default_registry();
        let cache = build_test_cache();
        let ctx = build_shortcode_context(&cache);
        let text = r#"((video src="test.mp4")) and ((video src="test.mp4"))"#;
        let result = process_text_with_shortcodes(text, &registry, &ctx);

        // Both shortcodes should be replaced with the same hash (cached)
        let hash_count = result.hash_to_html_map.len();
        assert_eq!(hash_count, 1);

        // The processed text should contain the same hash twice
        let hash_placeholders: Vec<&str> = result
            .processed_text
            .split_whitespace()
            .filter(|s| s.starts_with("SHORTCODE_HASH_"))
            .collect();
        assert_eq!(hash_placeholders.len(), 2);
        assert_eq!(hash_placeholders[0], hash_placeholders[1]);
    }

    #[test]
    fn test_shortcode_cache_with_formatting_variations() {
        let registry = create_default_registry();
        let cache = build_test_cache();
        let ctx = build_shortcode_context(&cache);
        let text = r#"((video src="test.mp4")) and ((video  src="test.mp4"))"#;
        let result = process_text_with_shortcodes(text, &registry, &ctx);

        assert_eq!(result.hash_to_html_map.len(), 1);

        let hash_placeholders: Vec<&str> = result
            .processed_text
            .split_whitespace()
            .filter(|s| s.starts_with("SHORTCODE_HASH_"))
            .collect();
        assert_eq!(hash_placeholders.len(), 2);
        assert_eq!(hash_placeholders[0], hash_placeholders[1]);
    }

    #[test]
    fn test_parse_shortcode_attribute_without_value() {
        let result = parse_shortcode("((link-card title=\"Test\" noblank))");
        assert!(result.is_some());
        let (shortcode, _consumed) = result.unwrap();
        assert_eq!(shortcode.name, "link-card");
        assert_eq!(shortcode.attributes.get("title").unwrap(), "Test");
        assert_eq!(shortcode.attributes.get("noblank").unwrap(), ""); // Should be empty string
        assert!(shortcode.attributes.contains_key("noblank"));
    }

    #[test]
    fn test_register_dynamic_flag() {
        let mut registry = ShortcodeRegistry::new();
        registry.register("static", |_shortcode, _ctx| Ok("static".to_string()), false);
        registry.register(
            "dynamic",
            |_shortcode, _ctx| Ok("dynamic".to_string()),
            true,
        );

        assert_eq!(registry.is_dynamic("static"), Some(false));
        assert_eq!(registry.is_dynamic("dynamic"), Some(true));
        assert_eq!(registry.is_dynamic("missing"), None);
    }
}
