// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0, multispace1},
    combinator::{map, recognize},
    multi::many0,
    sequence::{delimited, pair, preceded, separated_pair},
};
use nop_content_store::flat_storage::content_id_hex;
use nop_rt_iam::types::User;
use nop_rt_page_cache::PageMetaCache;
use nop_rt_release::ReleaseTracker;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Arc;

use nop_rt_templates::TemplateEngine;

mod color_hsv;
pub mod hero_img;
pub mod link_card;
pub mod tag_list;
pub mod unibox;
pub mod video;

// Type alias for complex shortcode handler function
type ShortcodeHandler =
    Box<dyn Fn(&Shortcode, &ShortcodeContext<'_>) -> Result<String, String> + Send + Sync>;

/// Describes the special treatment a shortcode handler requires from the render pipeline.
///
/// `dynamic` flags handlers whose output depends on data beyond Markdown plus startup-time
/// configuration; the within-page identical-shortcode cache is bypassed for these.
///
/// `container_escape` declares that the shortcode's output is intended to escape the page's
/// content container. Standalone paragraph placeholders for these shortcodes are wrapped with
/// render-pipeline support hooks during substitution; inline occurrences are substituted
/// literally because they cannot break out from inside surrounding text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShortcodeType {
    pub dynamic: bool,
    pub container_escape: bool,
}

struct ShortcodeMetadata {
    handler: ShortcodeHandler,
    shortcode_type: ShortcodeType,
}

/// Represents a parsed shortcode with its name and attributes
#[derive(Debug, Clone)]
pub struct Shortcode {
    pub name: String,
    pub attributes: HashMap<String, String>,
}

/// Re-export so shortcode handlers can refer to the tag matching rule via
/// `crate::shortcode::TagMatch` without reaching into `nop_rt_page_cache`.
pub use nop_rt_page_cache::TagMatch;

/// Re-export so shortcode handlers receive image-source resolution outcomes
/// without reaching into the markdown module's internals.
pub use crate::markdown::image_source::{ImageSourceError, ResolvedImage};

/// Information about a markdown page surfaced to shortcode handlers when
/// they ask the context for tag-based listings.
///
/// Only fields handlers legitimately need are exposed; cache-internal types
/// are not part of the API.
#[derive(Debug, Clone)]
pub struct PageSummary {
    /// Page title from the sidecar; `None` when no title is recorded.
    pub title: Option<String>,
    /// Routable alias for the page (no leading slash).
    pub route_alias: String,
}

/// Render-time context handed to every shortcode handler.
///
/// `ShortcodeContext` is the *only* data-access surface available to a
/// handler. Internal handles (the page-meta cache, the path of the markdown
/// being rendered, …) live as private fields and are reached only through
/// the capability methods on this type. This keeps handlers decoupled from
/// storage and routing details.
pub struct ShortcodeContext<'a> {
    pub user: Option<&'a User>,
    pub(crate) cache: &'a PageMetaCache,
    pub(crate) md_path: &'a str,
}

impl<'a> ShortcodeContext<'a> {
    /// Return markdown pages matching the tag criteria that the current user
    /// is allowed to see. Order is the cache's natural order.
    pub fn list_accessible_pages_by_tags(
        &self,
        tags: &[String],
        rule: TagMatch,
    ) -> Vec<PageSummary> {
        let mut objects = self.cache.list_by_tags(tags, rule);
        objects.retain(|object| object.is_markdown);
        objects.retain(|object| {
            let route_alias = object_route_alias(object);
            let user_roles = self.user.map(|user| user.roles.as_slice());
            self.cache
                .user_has_access(&route_alias, user_roles)
                .unwrap_or(false)
        });
        objects
            .into_iter()
            .map(|object| PageSummary {
                route_alias: object_route_alias(&object),
                title: object.title,
            })
            .collect()
    }

    /// Resolve a candidate image source URL to either an external URL passed
    /// through unchanged or a versioned local URL with the per-asset
    /// `?v=<version>` suffix. Local paths are resolved relative to the
    /// markdown page that produced this context.
    pub fn resolve_image_source(&self, url: &str) -> Result<ResolvedImage, ImageSourceError> {
        crate::markdown::image_source::resolve(url, self.md_path, self.cache)
    }
}

fn object_route_alias(object: &nop_rt_page_cache::CachedObject) -> String {
    if object.alias.trim().is_empty() {
        format!("id/{}", content_id_hex(object.key.id))
    } else {
        object.alias.clone()
    }
}

/// Produce a canonical string for a shortcode to support stable hashing/caching.
///
/// Attribute values are re-escaped per the parser's quoted-value grammar
/// (`\` doubled, `"` prefixed with `\`) so two source forms that decode to the
/// same value produce the same canonical string.
fn normalize_shortcode(shortcode: &Shortcode) -> String {
    let mut sorted_attrs: Vec<_> = shortcode.attributes.iter().collect();
    sorted_attrs.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let mut result = format!("(({}", shortcode.name);
    for (key, value) in sorted_attrs {
        if value.is_empty() {
            result.push_str(&format!(" {}", key));
        } else {
            result.push_str(&format!(r#" {}="{}""#, key, escape_quoted_attr(value)));
        }
    }
    result.push_str("))");
    result
}

/// Escape an attribute value for the canonical quoted form: doubles `\`,
/// then prefixes `\` to `"`. Order matters so an existing `\` doesn't end up
/// escaping a freshly-inserted `\` ahead of a `"`.
fn escape_quoted_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            other => out.push(other),
        }
    }
    out
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
    pub fn register<F>(&mut self, name: &str, handler: F, shortcode_type: ShortcodeType)
    where
        F: Fn(&Shortcode, &ShortcodeContext<'_>) -> Result<String, String> + Send + Sync + 'static,
    {
        self.handlers.insert(
            name.to_string(),
            ShortcodeMetadata {
                handler: Box::new(handler),
                shortcode_type,
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

    /// Look up the registered `ShortcodeType` for a shortcode name.
    pub fn shortcode_type(&self, name: &str) -> Option<&ShortcodeType> {
        self.handlers
            .get(name)
            .map(|metadata| &metadata.shortcode_type)
    }

    /// Return a sorted list of registered shortcode names.
    pub fn registered_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.handlers.keys().cloned().collect();
        names.sort();
        names
    }
}

#[cfg(test)]
impl Default for ShortcodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a SHA-512 hash for a shortcode using its normalized representation
fn generate_shortcode_hash(shortcode: &Shortcode) -> String {
    let normalized = normalize_shortcode(shortcode);
    let mut hasher = Sha512::new();
    hasher.update(normalized.as_bytes());
    let result = hasher.finalize();
    let hash_hex = result
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("SHORTCODE_HASH_{hash_hex}")
}

pub struct ShortcodeProcessingResult {
    pub processed_text: String,
    pub hash_to_html_map: HashMap<String, String>,
    pub hash_to_type_map: HashMap<String, ShortcodeType>,
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
            hash_to_type_map: HashMap::new(),
            contains_dynamic_shortcodes: false,
        };
    }

    let mut hash_to_html_map = HashMap::new();
    let mut hash_to_type_map: HashMap<String, ShortcodeType> = HashMap::new();
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

                let resolved_type = registry
                    .shortcode_type(&shortcode.name)
                    .copied()
                    .unwrap_or_default();
                let is_dynamic = resolved_type.dynamic;
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

                        // Store the mapping from hash to rendered HTML and to its declared type.
                        hash_to_html_map.insert(hash_placeholder.clone(), html);
                        hash_to_type_map.insert(hash_placeholder.clone(), resolved_type);

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
        hash_to_type_map,
        contains_dynamic_shortcodes,
    }
}

/// Replace hash placeholders in text with their corresponding rendered HTML.
///
/// A `<p>...</p>` whose non-whitespace content is only hash placeholders (one
/// or more, separated by whitespace including the soft-break newlines
/// pulldown-cmark emits between consecutive shortcode lines) is replaced as a
/// whole span: each hash is rendered in place — wrapped with
/// `escape_container(ctx)` / `return_to_container(ctx)` for shortcodes
/// registered with `container_escape: true`, plain HTML otherwise — and the
/// surrounding `<p>` and `</p>` are dropped. Whitespace between placeholders is
/// preserved.
///
/// Mixed paragraphs (placeholder + real text) and any text outside `<p>` are
/// substituted literally hash → html.
pub fn replace_shortcode_placeholders(
    text: &str,
    hash_to_html_map: &HashMap<String, String>,
    hash_to_type_map: &HashMap<String, ShortcodeType>,
    hooks: &dyn crate::markdown::RenderPipelineSupportHooks,
    hook_context: &crate::markdown::PageRenderHookContext,
) -> String {
    if hash_to_html_map.is_empty() {
        return text.to_string();
    }

    const P_OPEN: &str = "<p>";
    const P_CLOSE: &str = "</p>";

    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;

    while cursor < text.len() {
        let remainder = &text[cursor..];
        let Some(open_off) = remainder.find(P_OPEN) else {
            // No more `<p>` ahead — substitute hashes in the rest literally.
            result.push_str(&literal_replace(remainder, hash_to_html_map));
            break;
        };

        // Everything before the `<p>` gets literal hash → html substitution.
        if open_off > 0 {
            result.push_str(&literal_replace(&remainder[..open_off], hash_to_html_map));
        }

        let inside_start = cursor + open_off + P_OPEN.len();
        let Some(close_off) = text[inside_start..].find(P_CLOSE) else {
            // Unclosed `<p>` — best-effort: keep the `<p>` and substitute the rest literally.
            result.push_str(P_OPEN);
            result.push_str(&literal_replace(&text[inside_start..], hash_to_html_map));
            return result;
        };
        let inside_end = inside_start + close_off;
        let inside = &text[inside_start..inside_end];

        match try_render_hash_only_paragraph(
            inside,
            hash_to_html_map,
            hash_to_type_map,
            hooks,
            hook_context,
        ) {
            Some(rendered) => {
                // Hash-only paragraph: drop the `<p>` and `</p>` and emit the rendered HTML.
                result.push_str(&rendered);
            }
            None => {
                // Mixed paragraph: keep the wrapping `<p>...</p>` and replace any hashes inside literally.
                result.push_str(P_OPEN);
                result.push_str(&literal_replace(inside, hash_to_html_map));
                result.push_str(P_CLOSE);
            }
        }

        cursor = inside_end + P_CLOSE.len();
    }

    result
}

/// If `s` starts with `SHORTCODE_HASH_<128 ascii hex>`, return the byte length of the
/// matched token. Returns `None` otherwise.
fn consume_hash_token(s: &str) -> Option<usize> {
    const PREFIX: &str = "SHORTCODE_HASH_";
    const HASH_LEN: usize = 128;
    let bytes = s.as_bytes();
    if bytes.len() >= PREFIX.len() + HASH_LEN
        && &bytes[..PREFIX.len()] == PREFIX.as_bytes()
        && bytes[PREFIX.len()..PREFIX.len() + HASH_LEN]
            .iter()
            .all(|b| b.is_ascii_hexdigit())
    {
        Some(PREFIX.len() + HASH_LEN)
    } else {
        None
    }
}

/// If `inside` consists only of whitespace and one or more recognised hash tokens,
/// return the rendered HTML (each hash replaced in place, with whitespace between
/// hashes preserved as-is). Returns `None` if any non-whitespace, non-hash byte is
/// encountered, or if a hash is missing from `hash_to_html_map`.
fn try_render_hash_only_paragraph(
    inside: &str,
    hash_to_html_map: &HashMap<String, String>,
    hash_to_type_map: &HashMap<String, ShortcodeType>,
    hooks: &dyn crate::markdown::RenderPipelineSupportHooks,
    hook_context: &crate::markdown::PageRenderHookContext,
) -> Option<String> {
    let bytes = inside.as_bytes();
    let mut idx = 0;
    let mut output = String::with_capacity(inside.len());
    let mut found_hash = false;

    while idx < bytes.len() {
        if bytes[idx].is_ascii_whitespace() {
            output.push(bytes[idx] as char);
            idx += 1;
            continue;
        }

        let consumed = consume_hash_token(&inside[idx..])?;
        let hash = &inside[idx..idx + consumed];
        let html = hash_to_html_map.get(hash)?;
        let shortcode_type = hash_to_type_map.get(hash).copied().unwrap_or_default();

        if shortcode_type.container_escape {
            output.push_str(&hooks.escape_container(hook_context));
            output.push_str(html);
            output.push_str(&hooks.return_to_container(hook_context));
        } else {
            output.push_str(html);
        }

        idx += consumed;
        found_hash = true;
    }

    if found_hash { Some(output) } else { None }
}

/// Literal hash → html substitution: scans every entry in `hash_to_html_map` and
/// applies `String::replace` for each hash that appears in `s`.
fn literal_replace(s: &str, hash_to_html_map: &HashMap<String, String>) -> String {
    let mut result = s.to_string();
    for (hash, html) in hash_to_html_map {
        if result.contains(hash) {
            log::trace!(
                "Replacing hash placeholder '{}' with HTML: '{}'",
                hash,
                html
            );
            result = result.replace(hash, html);
        }
    }
    result
}

// Nom parser implementation for shortcodes
// Parse shortcode name: alphanumeric with hyphens and underscores
fn shortcode_name(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"), tag("-"))),
        many0(alt((alphanumeric1, tag("-"), tag("_")))),
    ))
    .parse(input)
}

/// Parse a quoted string value, decoding backslash escapes.
///
/// `\"` decodes to a literal `"`, `\\` decodes to a literal `\`, and any other
/// `\X` decodes to the literal character `X` (lenient — forward-compatible
/// with frontends that emit JSON-style escapes such as `\n`, `\t`, `\uXXXX`).
fn quoted_value(input: &str) -> IResult<&str, String> {
    delimited(char('"'), quoted_value_body, char('"')).parse(input)
}

fn quoted_value_body(input: &str) -> IResult<&str, String> {
    let mut out = String::new();
    let mut remaining = input;
    loop {
        // Consume any run of characters that are neither `\` nor `"`.
        match is_not::<&str, &str, nom::error::Error<&str>>("\\\"").parse(remaining) {
            Ok((rest, chunk)) => {
                out.push_str(chunk);
                remaining = rest;
            }
            Err(nom::Err::Error(_)) => {
                // No plain run at this position — fall through to escape / terminator handling.
            }
            Err(err) => return Err(err),
        }

        if remaining.starts_with('"') {
            return Ok((remaining, out));
        }
        if let Some(rest) = remaining.strip_prefix('\\') {
            // Decode the next character: `\X` → `X` for any X (covers `\"`, `\\`, and the
            // lenient fallback for any other letter).
            let mut chars = rest.chars();
            match chars.next() {
                Some(c) => {
                    out.push(c);
                    remaining = chars.as_str();
                }
                None => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        remaining,
                        nom::error::ErrorKind::Escaped,
                    )));
                }
            }
        } else {
            // Empty input or unexpected byte before the closing `"`.
            return Err(nom::Err::Error(nom::error::Error::new(
                remaining,
                nom::error::ErrorKind::TakeUntil,
            )));
        }
    }
}

// Parse unquoted value (numbers, booleans, or simple strings without spaces)
fn unquoted_value(input: &str) -> IResult<&str, String> {
    map(
        take_while1(|c: char| !c.is_whitespace() && c != ')'),
        |s: &str| s.to_string(),
    )
    .parse(input)
}

// Parse attribute value (quoted or unquoted)
fn attribute_value(input: &str) -> IResult<&str, String> {
    alt((quoted_value, unquoted_value)).parse(input)
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
            |(k, v)| (k.to_string(), v),
        ),
        // standalone flag (e.g., "controls", "noblank")
        map(shortcode_name, |k| (k.to_string(), String::new())),
    ))
    .parse(input)
}

// Parse shortcode content inside ((  ))
fn shortcode_content(input: &str) -> IResult<&str, Shortcode> {
    map(
        (
            preceded(multispace0, shortcode_name),
            many0(preceded(multispace1, attribute)),
            multispace0,
        ),
        |(name, attrs, _)| Shortcode {
            name: name.to_string(),
            attributes: attrs.into_iter().collect(),
        },
    )
    .parse(input)
}

// Parse complete shortcode with (( )) delimiters
fn nom_parse_shortcode(input: &str) -> IResult<&str, Shortcode> {
    delimited(tag("(("), shortcode_content, tag("))")).parse(input)
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
    config: &nop_config::ValidatedConfig,
    release_tracker: &ReleaseTracker,
    template_engine: Arc<dyn TemplateEngine>,
) -> ShortcodeRegistry {
    let mut registry = ShortcodeRegistry::with_tracker(Some(release_tracker.clone()));

    // Register the basic shortcode handlers
    let video_engine = template_engine.clone();
    registry.register(
        "video",
        move |shortcode, _ctx| video::handle_video_shortcode(shortcode, video_engine.as_ref()),
        ShortcodeType::default(),
    );
    let link_card_engine = template_engine.clone();
    registry.register(
        "link-card",
        move |shortcode, _ctx| {
            link_card::handle_link_card_shortcode(shortcode, link_card_engine.as_ref())
        },
        ShortcodeType::default(),
    );

    // Register config-aware handlers using closures to capture config
    let config_clone = config.clone();
    let unibox_engine = template_engine.clone();
    registry.register(
        "start-unibox",
        move |shortcode, _ctx| {
            unibox::handle_start_unibox_shortcode(shortcode, &config_clone, unibox_engine.as_ref())
        },
        ShortcodeType::default(),
    );

    registry.register(
        "tag-list",
        tag_list::handle_tag_list_shortcode,
        ShortcodeType {
            dynamic: true,
            container_escape: false,
        },
    );

    let hero_img_engine = template_engine.clone();
    registry.register(
        "hero-img",
        move |shortcode, ctx| {
            hero_img::handle_hero_img_shortcode(shortcode, ctx, hero_img_engine.as_ref())
        },
        ShortcodeType {
            dynamic: false,
            container_escape: true,
        },
    );

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_rt_page_cache::PageMetaCache;
    use std::path::PathBuf;

    /// Create a default shortcode registry with built-in handlers (for tests only)
    fn create_default_registry() -> ShortcodeRegistry {
        let mut registry = ShortcodeRegistry::new();

        // Register the basic shortcode handlers
        let templates = Arc::new(nop_rt_templates::MiniJinjaEngine::new());
        let video_engine = templates.clone();
        registry.register(
            "video",
            move |shortcode, _ctx| video::handle_video_shortcode(shortcode, video_engine.as_ref()),
            ShortcodeType::default(),
        );
        let link_card_engine = templates.clone();
        registry.register(
            "link-card",
            move |shortcode, _ctx| {
                link_card::handle_link_card_shortcode(shortcode, link_card_engine.as_ref())
            },
            ShortcodeType::default(),
        );

        registry
    }

    fn build_test_cache() -> PageMetaCache {
        PageMetaCache::new(
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            nop_content_store::reserved_paths::ReservedPaths::default(),
        )
    }

    fn build_shortcode_context<'a>(cache: &'a PageMetaCache) -> ShortcodeContext<'a> {
        ShortcodeContext {
            cache,
            user: None,
            md_path: "test.md",
        }
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
    fn test_parse_shortcode_with_escaped_quote_in_value() {
        let source = r#"((video src="x" title="She said \"hi\""))"#;
        let result = parse_shortcode(source).expect("parse with escaped quote");
        let (shortcode, _consumed) = result;
        assert_eq!(shortcode.attributes.get("src").unwrap(), "x");
        assert_eq!(
            shortcode.attributes.get("title").unwrap(),
            "She said \"hi\""
        );
    }

    #[test]
    fn test_parse_shortcode_with_escaped_backslash_in_value() {
        // Source contains four backslashes between the quotes; each pair `\\`
        // decodes to a single `\`, so the decoded value is `\\` (two literal
        // backslashes).
        let source = r#"((video src="x" title="\\\\"))"#;
        let result = parse_shortcode(source).expect("parse with escaped backslash");
        let (shortcode, _consumed) = result;
        assert_eq!(shortcode.attributes.get("title").unwrap(), "\\\\");
    }

    #[test]
    fn test_parse_shortcode_lenient_unknown_escape() {
        // `\n` inside a quoted shortcode value is not a newline — the parser
        // is deliberately lenient: any `\X` decodes to the literal character
        // `X`, so JSON-style escapes the admin UI may emit are read
        // harmlessly without rejecting the shortcode.
        let source = r#"((video src="x" title="a\nb"))"#;
        let result = parse_shortcode(source).expect("parse with unknown escape");
        let (shortcode, _consumed) = result;
        assert_eq!(shortcode.attributes.get("title").unwrap(), "anb");
    }

    #[test]
    fn test_normalize_shortcode_round_trip_with_quotes_and_backslashes() {
        // Both source forms decode to the same `Shortcode` and must produce
        // the same canonical hash.
        let with_escapes = r#"((video src="x" title="She said \"hi\" \\ now"))"#;
        let with_explicit_chars = parse_shortcode(with_escapes)
            .expect("parse explicit form")
            .0;

        // Build a Shortcode by hand with the decoded characters.
        let mut attributes = HashMap::new();
        attributes.insert("src".to_string(), "x".to_string());
        attributes.insert("title".to_string(), "She said \"hi\" \\ now".to_string());
        let direct = Shortcode {
            name: "video".to_string(),
            attributes,
        };

        assert_eq!(
            generate_shortcode_hash(&with_explicit_chars),
            generate_shortcode_hash(&direct)
        );
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
    fn test_register_shortcode_type() {
        let mut registry = ShortcodeRegistry::new();
        registry.register(
            "static",
            |_shortcode, _ctx| Ok("static".to_string()),
            ShortcodeType::default(),
        );
        registry.register(
            "dynamic",
            |_shortcode, _ctx| Ok("dynamic".to_string()),
            ShortcodeType {
                dynamic: true,
                container_escape: false,
            },
        );

        assert_eq!(
            registry.shortcode_type("static"),
            Some(&ShortcodeType {
                dynamic: false,
                container_escape: false,
            })
        );
        assert_eq!(
            registry.shortcode_type("dynamic"),
            Some(&ShortcodeType {
                dynamic: true,
                container_escape: false,
            })
        );
        assert_eq!(registry.shortcode_type("missing"), None);
    }

    #[test]
    fn test_register_container_escape_flag() {
        let mut registry = ShortcodeRegistry::new();
        registry.register(
            "escape",
            |_shortcode, _ctx| Ok("escape".to_string()),
            ShortcodeType {
                dynamic: false,
                container_escape: true,
            },
        );

        assert_eq!(
            registry.shortcode_type("escape"),
            Some(&ShortcodeType {
                dynamic: false,
                container_escape: true,
            })
        );
    }

    struct StubHooks;

    impl crate::markdown::RenderPipelineSupportHooks for StubHooks {
        fn escape_container(&self, _ctx: &crate::markdown::PageRenderHookContext) -> String {
            "<<ESC>>".to_string()
        }
        fn return_to_container(&self, _ctx: &crate::markdown::PageRenderHookContext) -> String {
            "<<RET>>".to_string()
        }
    }

    /// 128 hex chars = the exact length of a SHA-512 hex digest, matching the
    /// shape `generate_shortcode_hash` produces.
    fn substitution_test_hash() -> String {
        let mut s = String::from("SHORTCODE_HASH_");
        s.extend(std::iter::repeat_n('a', 128));
        s
    }

    fn substitution_test_hash_b() -> String {
        let mut s = String::from("SHORTCODE_HASH_");
        s.extend(std::iter::repeat_n('b', 128));
        s
    }

    #[test]
    fn replace_drops_paragraph_for_non_escape_shortcode_alone_in_paragraph() {
        let hash = substitution_test_hash();
        let html = "<video src=\"x.mp4\"></video>".to_string();
        let mut html_map = HashMap::new();
        html_map.insert(hash.clone(), html);
        let mut type_map = HashMap::new();
        type_map.insert(hash.clone(), ShortcodeType::default());

        let input = format!("Before <p>{}</p> after", hash);
        let result = replace_shortcode_placeholders(
            &input,
            &html_map,
            &type_map,
            &StubHooks,
            &crate::markdown::PageRenderHookContext {
                use_compact_width: false,
            },
        );

        assert_eq!(result, "Before <video src=\"x.mp4\"></video> after");
        assert!(!result.contains("SHORTCODE_HASH_"));
        assert!(!result.contains("<<ESC>>"));
        assert!(!result.contains("<<RET>>"));
    }

    #[test]
    fn replace_wraps_with_escape_and_return_for_container_escape_alone_in_paragraph() {
        let hash = substitution_test_hash();
        let html = "<figure>hero</figure>".to_string();
        let mut html_map = HashMap::new();
        html_map.insert(hash.clone(), html);
        let mut type_map = HashMap::new();
        type_map.insert(
            hash.clone(),
            ShortcodeType {
                dynamic: false,
                container_escape: true,
            },
        );

        let input = format!("intro\n<p>{}</p>\noutro", hash);
        let result = replace_shortcode_placeholders(
            &input,
            &html_map,
            &type_map,
            &StubHooks,
            &crate::markdown::PageRenderHookContext {
                use_compact_width: false,
            },
        );

        let expected = "intro\n<<ESC>><figure>hero</figure><<RET>>\noutro";
        assert_eq!(result, expected);
    }

    #[test]
    fn replace_preserves_paragraph_for_inline_non_escape_shortcode() {
        let hash = substitution_test_hash();
        let html = "<video src=\"x.mp4\"></video>".to_string();
        let mut html_map = HashMap::new();
        html_map.insert(hash.clone(), html);
        let mut type_map = HashMap::new();
        type_map.insert(hash.clone(), ShortcodeType::default());

        let input = format!("<p>before {} after</p>", hash);
        let result = replace_shortcode_placeholders(
            &input,
            &html_map,
            &type_map,
            &StubHooks,
            &crate::markdown::PageRenderHookContext {
                use_compact_width: false,
            },
        );

        assert_eq!(result, "<p>before <video src=\"x.mp4\"></video> after</p>");
    }

    #[test]
    fn replace_inline_container_escape_falls_back_to_literal_substitution() {
        let hash = substitution_test_hash();
        let html = "<figure>hero</figure>".to_string();
        let mut html_map = HashMap::new();
        html_map.insert(hash.clone(), html);
        let mut type_map = HashMap::new();
        type_map.insert(
            hash.clone(),
            ShortcodeType {
                dynamic: false,
                container_escape: true,
            },
        );

        let input = format!("<p>before {} after</p>", hash);
        let result = replace_shortcode_placeholders(
            &input,
            &html_map,
            &type_map,
            &StubHooks,
            &crate::markdown::PageRenderHookContext {
                use_compact_width: false,
            },
        );

        // Inline placement cannot break out of the surrounding container, so
        // no escape/return wrapping is applied. The literal hash is replaced.
        assert_eq!(result, "<p>before <figure>hero</figure> after</p>");
        assert!(!result.contains("<<ESC>>"));
        assert!(!result.contains("<<RET>>"));
    }

    #[test]
    fn replace_strips_paragraph_for_multiple_non_escape_shortcodes() {
        let hash_a = substitution_test_hash();
        let hash_b = substitution_test_hash_b();
        let mut html_map = HashMap::new();
        html_map.insert(hash_a.clone(), "<a>A</a>".to_string());
        html_map.insert(hash_b.clone(), "<b>B</b>".to_string());
        let mut type_map = HashMap::new();
        type_map.insert(hash_a.clone(), ShortcodeType::default());
        type_map.insert(hash_b.clone(), ShortcodeType::default());

        let input = format!("<p>{}\n{}</p>", hash_a, hash_b);
        let result = replace_shortcode_placeholders(
            &input,
            &html_map,
            &type_map,
            &StubHooks,
            &crate::markdown::PageRenderHookContext {
                use_compact_width: false,
            },
        );

        assert_eq!(result, "<a>A</a>\n<b>B</b>");
        assert!(!result.contains("<p>"));
        assert!(!result.contains("</p>"));
    }

    #[test]
    fn replace_strips_paragraph_for_mixed_escape_status_in_one_paragraph() {
        let hash_a = substitution_test_hash();
        let hash_b = substitution_test_hash_b();
        let mut html_map = HashMap::new();
        html_map.insert(hash_a.clone(), "<figure>hero</figure>".to_string());
        html_map.insert(hash_b.clone(), "<a>card</a>".to_string());
        let mut type_map = HashMap::new();
        type_map.insert(
            hash_a.clone(),
            ShortcodeType {
                dynamic: false,
                container_escape: true,
            },
        );
        type_map.insert(hash_b.clone(), ShortcodeType::default());

        let input = format!("intro\n<p>{}\n{}</p>\noutro", hash_a, hash_b);
        let result = replace_shortcode_placeholders(
            &input,
            &html_map,
            &type_map,
            &StubHooks,
            &crate::markdown::PageRenderHookContext {
                use_compact_width: false,
            },
        );

        assert_eq!(
            result,
            "intro\n<<ESC>><figure>hero</figure><<RET>>\n<a>card</a>\noutro"
        );
    }

    #[test]
    fn replace_keeps_paragraph_when_hashes_mixed_with_text() {
        let hash_a = substitution_test_hash();
        let hash_b = substitution_test_hash_b();
        let mut html_map = HashMap::new();
        html_map.insert(hash_a.clone(), "<a>A</a>".to_string());
        html_map.insert(hash_b.clone(), "<b>B</b>".to_string());
        let mut type_map = HashMap::new();
        type_map.insert(hash_a.clone(), ShortcodeType::default());
        type_map.insert(hash_b.clone(), ShortcodeType::default());

        let input = format!("<p>{} and {}</p>", hash_a, hash_b);
        let result = replace_shortcode_placeholders(
            &input,
            &html_map,
            &type_map,
            &StubHooks,
            &crate::markdown::PageRenderHookContext {
                use_compact_width: false,
            },
        );

        assert_eq!(result, "<p><a>A</a> and <b>B</b></p>");
    }
}
