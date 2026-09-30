// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::markdown::HtmlSanitizer;
use crate::markdown::document_structure::{
    HeadingDraft, MarkdownHeading, assign_heading_anchor_ids, select_document_structure,
};
use crate::markdown::render_pipeline_support_hooks::{PageRenderState, RenderPipelineSupportHooks};
use crate::shortcode::{
    ShortcodeContext, ShortcodeRegistry, process_text_with_shortcodes,
    replace_shortcode_placeholders,
};
use getrandom::fill;
use log::error;
use nop_content_store::flat_storage::ContentWidthMode;
use nop_rt_iam::types::User;
use nop_rt_page_cache::PageMetaCache;
use nop_rt_security as security;
use once_cell::sync::Lazy;
use pulldown_cmark::{
    CodeBlockKind, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html,
};
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
    pub(super) render_state: PageRenderState,
}

pub(super) struct RenderRequest<'a> {
    pub(super) markdown: &'a str,
    pub(super) shortcode_registry: &'a ShortcodeRegistry,
    pub(super) options: &'a Options,
    pub(super) sanitizer: &'a HtmlSanitizer,
    pub(super) cache: &'a PageMetaCache,
    pub(super) md_path: &'a str,
    pub(super) user: Option<&'a User>,
    pub(super) hooks: &'a dyn RenderPipelineSupportHooks,
    pub(super) render_state: PageRenderState,
}

pub(super) fn generate_html(
    request: &RenderRequest<'_>,
) -> Result<RenderedMarkdown, MarkdownRenderError> {
    // Process shortcodes to build mapping (original text unchanged)
    let shortcode_ctx = ShortcodeContext {
        cache: request.cache,
        user: request.user,
        md_path: request.md_path,
    };
    let shortcode_result =
        process_text_with_shortcodes(request.markdown, request.shortcode_registry, &shortcode_ctx);

    let mut render_state = request.render_state.clone();
    // `Auto` always renders the normal compact width; only an explicit `Wide` sidecar
    // value opts a page into the wide rendering. Paragraph length never affects width.
    render_state.use_compact_width = match render_state.content_width {
        ContentWidthMode::Auto => true,
        ContentWidthMode::Wide => false,
        ContentWidthMode::Narrow => true,
    };

    // Parse the markdown content (shortcode strings will be treated as regular text)
    let parser = Parser::new_ext(&shortcode_result.processed_text, *request.options);

    let wrapper_nonce = generate_code_block_wrapper_nonce();

    // Process events with custom logic for images/links plus code-block wrapper placeholders
    let mut event_state = RenderEventState::new(wrapper_nonce.clone());
    let mut events = Vec::new();
    for event in parser {
        let output_start_index = events.len();
        events.extend(event_state.process_event(
            event,
            output_start_index,
            request.md_path,
            request.cache,
        ));
    }

    let anchored_headings = event_state.into_markdown_headings();
    apply_heading_ids(&mut events, &anchored_headings);
    let headings: Vec<MarkdownHeading> = anchored_headings
        .into_iter()
        .map(|heading| heading.heading)
        .collect();
    render_state.document_structure = select_document_structure(&headings);

    let mut html_output = String::new();
    html::push_html(&mut html_output, events.into_iter());

    // Sanitize HTML output from Markdown conversion (shortcode strings are just text so they're safe)
    let sanitized_html = request.sanitizer.clean(&html_output);

    // Post-process HTML to add target="_blank" to external links (before shortcode replacement)
    let processed_html = post_process_html(sanitized_html, request.md_path, request.cache)?;

    let wrapper_replaced_html = match &wrapper_nonce {
        Some(nonce) => replace_code_block_wrapper_placeholders_best_effort(
            &processed_html,
            nonce,
            request.md_path,
        ),
        None => processed_html,
    };

    // Replace shortcode strings with their rendered HTML as the final step

    let hook_context = render_state.hook_context();
    let final_html = replace_shortcode_placeholders(
        &wrapper_replaced_html,
        &shortcode_result.hash_to_html_map,
        &shortcode_result.hash_to_type_map,
        request.hooks,
        &hook_context,
    );
    render_state.has_hero = shortcode_result.contains_hero;
    let final_html = assemble_balanced_content_stream(
        final_html,
        request.hooks,
        &hook_context,
    );

    Ok(RenderedMarkdown {
        html: final_html,
        contains_dynamic_shortcodes: shortcode_result.contains_dynamic_shortcodes,
        render_state,
    })
}

/// Wraps the substituted body in content segments so `{content}` is a fully
/// balanced stream handed to the layout grid: a leading escape's closes are
/// drained because nothing is open yet, a trailing escape's return is
/// truncated because nothing follows it, initial opens are skipped when
/// leading-drained, and final closes are skipped when trailing-truncated.
fn assemble_balanced_content_stream(
    mut html: String,
    hooks: &dyn RenderPipelineSupportHooks,
    hook_context: &crate::markdown::PageRenderHookContext,
) -> String {
    let closes = hooks.close_content_segment();
    let leading_escape = html.starts_with(&closes);
    if leading_escape {
        html.drain(..closes.len());
    }

    // A trailing return only reopens a segment nothing follows, so strip the
    // reopened opens but keep the band close.
    let reopened = hooks.open_content_segment(hook_context);
    let trimmed_len = html.trim_end().len();
    let trailing_escape = html[..trimmed_len].ends_with(&reopened);
    if trailing_escape {
        let new_len = trimmed_len - reopened.len();
        html.truncate(new_len);
    }

    let mut stream = String::new();
    if !leading_escape {
        stream.push_str(&hooks.open_content_segment(hook_context));
    }
    stream.push_str(&html);
    if !trailing_escape {
        stream.push_str(&hooks.close_content_segment());
    }
    stream
}

fn generate_code_block_wrapper_nonce() -> Option<String> {
    let mut bytes = [0u8; 16];
    if let Err(err) = fill(&mut bytes) {
        error!("🚨 Failed to generate code-block wrapper nonce: {}", err);
        // Without a strong nonce, wrapper placeholder replacement can be coerced by user content.
        // Disable copy-button wrappers rather than degrade security properties.
        return None;
    }
    Some(encode_hex(&bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

struct RenderEventState {
    nonce: Option<String>,
    in_wrapped_code_block: bool,
    start_count: usize,
    end_count: usize,
    current_heading: Option<HeadingLabelBuilder>,
    heading_drafts: Vec<PendingHeadingDraft>,
}

struct PendingHeadingDraft {
    draft: HeadingDraft,
    event_index: usize,
}

struct AnchoredMarkdownHeading {
    heading: MarkdownHeading,
    event_index: usize,
}

impl RenderEventState {
    fn new(nonce: Option<String>) -> Self {
        Self {
            nonce,
            in_wrapped_code_block: false,
            start_count: 0,
            end_count: 0,
            current_heading: None,
            heading_drafts: Vec::new(),
        }
    }

    fn start_token(&self) -> String {
        let Some(nonce) = &self.nonce else {
            return String::new();
        };
        format!("NOP_CODEBLOCK_WRAPPER_START_{}", nonce)
    }

    fn end_token(&self) -> String {
        let Some(nonce) = &self.nonce else {
            return String::new();
        };
        format!("NOP_CODEBLOCK_WRAPPER_END_{}", nonce)
    }

    fn process_event<'a>(
        &mut self,
        event: Event<'a>,
        output_start_index: usize,
        current_md_path: &str,
        cache: &PageMetaCache,
    ) -> Vec<Event<'a>> {
        let event = process_event(event, current_md_path, cache);
        match event {
            Event::Start(Tag::Heading {
                level,
                id,
                classes,
                attrs,
            }) => {
                self.current_heading = Some(HeadingLabelBuilder::new(level, output_start_index));
                vec![Event::Start(Tag::Heading {
                    level,
                    id,
                    classes,
                    attrs,
                })]
            }
            Event::End(TagEnd::Heading(level)) => {
                if let Some(builder) = self.current_heading.take()
                    && let Some(heading) = builder.finish()
                {
                    self.heading_drafts.push(heading);
                }
                vec![Event::End(TagEnd::Heading(level))]
            }
            Event::Text(text) => {
                if let Some(builder) = self.current_heading.as_mut() {
                    builder.push_text(&text);
                }
                vec![Event::Text(text)]
            }
            Event::Code(text) => {
                if let Some(builder) = self.current_heading.as_mut() {
                    builder.push_text(&text);
                }
                vec![Event::Code(text)]
            }
            Event::Html(html) => {
                if let Some(builder) = self.current_heading.as_mut() {
                    builder.observe_raw_html(&html);
                }
                vec![Event::Html(html)]
            }
            Event::SoftBreak => {
                if let Some(builder) = self.current_heading.as_mut() {
                    builder.push_break();
                }
                vec![Event::SoftBreak]
            }
            Event::HardBreak => {
                if let Some(builder) = self.current_heading.as_mut() {
                    builder.push_break();
                }
                vec![Event::HardBreak]
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                let should_wrap = self.nonce.is_some() && matches!(kind, CodeBlockKind::Fenced(_));
                self.in_wrapped_code_block = should_wrap;
                if should_wrap {
                    self.start_count += 1;
                    return vec![
                        Event::Html(CowStr::Boxed(self.start_token().into_boxed_str())),
                        Event::Start(Tag::CodeBlock(kind)),
                    ];
                }
                vec![Event::Start(Tag::CodeBlock(kind))]
            }
            Event::End(TagEnd::CodeBlock) => {
                let should_wrap = self.in_wrapped_code_block;
                self.in_wrapped_code_block = false;
                if should_wrap {
                    self.end_count += 1;
                    return vec![
                        Event::End(TagEnd::CodeBlock),
                        Event::Html(CowStr::Boxed(self.end_token().into_boxed_str())),
                    ];
                }
                vec![Event::End(TagEnd::CodeBlock)]
            }
            other => vec![other],
        }
    }

    fn into_markdown_headings(self) -> Vec<AnchoredMarkdownHeading> {
        let mut event_indices = Vec::with_capacity(self.heading_drafts.len());
        let drafts = self
            .heading_drafts
            .into_iter()
            .map(|heading| {
                event_indices.push(heading.event_index);
                heading.draft
            })
            .collect();

        assign_heading_anchor_ids(drafts)
            .into_iter()
            .zip(event_indices)
            .map(|(heading, event_index)| AnchoredMarkdownHeading {
                heading,
                event_index,
            })
            .collect()
    }
}

struct HeadingLabelBuilder {
    rank: u8,
    label: String,
    suppressed_raw_tag: Option<&'static str>,
    start_event_index: usize,
}

impl HeadingLabelBuilder {
    fn new(level: HeadingLevel, start_event_index: usize) -> Self {
        Self {
            rank: heading_level_rank(level),
            label: String::new(),
            suppressed_raw_tag: None,
            start_event_index,
        }
    }

    fn push_text(&mut self, text: &str) {
        if self.suppressed_raw_tag.is_some() {
            return;
        }

        let mut plain_text = String::with_capacity(text.len());
        let mut cursor = 0;
        while cursor < text.len() {
            let remainder = &text[cursor..];
            if let Some(consumed) = consume_shortcode_hash(remainder) {
                cursor += consumed;
                continue;
            }

            let Some(ch) = remainder.chars().next() else {
                break;
            };
            plain_text.push(ch);
            cursor += ch.len_utf8();
        }

        for part in plain_text.split_whitespace() {
            if !self.label.is_empty() {
                self.label.push(' ');
            }
            self.label.push_str(part);
        }
    }

    fn push_break(&mut self) {
        if self.suppressed_raw_tag.is_some() {
            return;
        }
        if !self.label.ends_with(' ') && !self.label.is_empty() {
            self.label.push(' ');
        }
    }

    fn observe_raw_html(&mut self, html: &str) {
        if let Some(tag) = self.suppressed_raw_tag {
            if is_closing_raw_tag(html, tag) {
                self.suppressed_raw_tag = None;
            }
            return;
        }

        self.suppressed_raw_tag = removed_raw_html_tag(html);
    }

    fn finish(self) -> Option<PendingHeadingDraft> {
        let label = self.label.trim().to_string();
        if label.is_empty() {
            return None;
        }

        Some(PendingHeadingDraft {
            draft: HeadingDraft {
                rank: self.rank,
                label,
            },
            event_index: self.start_event_index,
        })
    }
}

fn apply_heading_ids<'a>(events: &mut [Event<'a>], headings: &[AnchoredMarkdownHeading]) {
    for heading in headings {
        if let Some(Event::Start(Tag::Heading { id, .. })) = events.get_mut(heading.event_index) {
            *id = Some(CowStr::Boxed(
                heading.heading.anchor_id.clone().into_boxed_str(),
            ));
        }
    }
}

fn consume_shortcode_hash(s: &str) -> Option<usize> {
    const PREFIX: &str = "SHORTCODE_HASH_";
    const HASH_LEN: usize = 128;
    let bytes = s.as_bytes();
    if bytes.len() >= PREFIX.len() + HASH_LEN
        && bytes.starts_with(PREFIX.as_bytes())
        && bytes[PREFIX.len()..PREFIX.len() + HASH_LEN]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        Some(PREFIX.len() + HASH_LEN)
    } else {
        None
    }
}

fn removed_raw_html_tag(html: &str) -> Option<&'static str> {
    let tag = opening_tag_name(html)?;
    if tag.eq_ignore_ascii_case("script") {
        Some("script")
    } else if tag.eq_ignore_ascii_case("link") {
        Some("link")
    } else if tag.eq_ignore_ascii_case("iframe") {
        Some("iframe")
    } else if tag.eq_ignore_ascii_case("object") {
        Some("object")
    } else if tag.eq_ignore_ascii_case("embed") {
        Some("embed")
    } else {
        None
    }
}

fn opening_tag_name(html: &str) -> Option<&str> {
    let trimmed = html.trim_start();
    let rest = trimmed.strip_prefix('<')?;
    if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
        return None;
    }
    let end = rest
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace() || *ch == '>' || *ch == '/')
        .map(|(index, _)| index)
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(&rest[..end])
}

fn is_closing_raw_tag(html: &str, tag: &str) -> bool {
    let trimmed = html.trim_start().to_ascii_lowercase();
    trimmed.starts_with(&format!("</{}", tag))
}

fn heading_level_rank(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

fn replace_code_block_wrapper_placeholders_best_effort(
    html: &str,
    nonce: &str,
    md_path: &str,
) -> String {
    let start_token = format!("NOP_CODEBLOCK_WRAPPER_START_{}", nonce);
    let end_token = format!("NOP_CODEBLOCK_WRAPPER_END_{}", nonce);

    if !html.contains(&start_token) && !html.contains(&end_token) {
        return html.to_string();
    }

    let wrapper_start = r#"<figure data-site-code-block="true"><figcaption><button type="button" data-site-code-copy="true" aria-label="Copy code block"><img src="/builtin/copy.svg" alt="" width="16" height="16"><span class="site-visually-hidden" data-site-code-copy-status="true"></span></button></figcaption>"#;
    let wrapper_end = r#"</figure>"#;

    let mut out = String::with_capacity(html.len() + 256);
    let mut cursor = 0usize;
    let mut open_wrappers = 0usize;
    let mut stray_starts = 0usize;
    let mut stray_ends = 0usize;

    loop {
        let next_start = html[cursor..].find(&start_token).map(|idx| cursor + idx);
        let next_end = html[cursor..].find(&end_token).map(|idx| cursor + idx);

        let (pos, is_start) = match (next_start, next_end) {
            (None, None) => break,
            (Some(s), None) => (s, true),
            (None, Some(e)) => (e, false),
            (Some(s), Some(e)) => {
                if s <= e {
                    (s, true)
                } else {
                    (e, false)
                }
            }
        };

        out.push_str(&html[cursor..pos]);
        if is_start {
            out.push_str(wrapper_start);
            open_wrappers += 1;
            cursor = pos + start_token.len();
        } else {
            if open_wrappers == 0 {
                // Stray end token: drop it, but keep output valid.
                stray_ends += 1;
            } else {
                out.push_str(wrapper_end);
                open_wrappers -= 1;
            }
            cursor = pos + end_token.len();
        }
    }

    out.push_str(&html[cursor..]);

    if open_wrappers > 0 {
        // Close any wrappers that couldn't find a matching end token.
        stray_starts += open_wrappers;
        for _ in 0..open_wrappers {
            out.push_str(wrapper_end);
        }
    }

    if stray_starts > 0 || stray_ends > 0 {
        error!(
            "🚨 Code block wrapper placeholder mismatch in {} (stray_starts={}, stray_ends={})",
            md_path, stray_starts, stray_ends
        );
    }

    out
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
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            let url_str = dest_url.as_ref();
            match super::image_source::resolve(url_str, current_md_path, cache) {
                Ok(super::image_source::ResolvedImage::External(url)) => {
                    Event::Start(Tag::Image {
                        link_type,
                        dest_url: CowStr::Boxed(url.into()),
                        title,
                        id,
                    })
                }
                Ok(super::image_source::ResolvedImage::Local(url)) => Event::Start(Tag::Image {
                    link_type,
                    dest_url: CowStr::Boxed(url.into()),
                    title,
                    id,
                }),
                Err(super::image_source::ImageSourceError::PathTraversal) => Event::Html(
                    "<div class=\"notification is-danger\">Error: Invalid image path detected</div>"
                        .into(),
                ),
                Err(super::image_source::ImageSourceError::ReservedImgPath) => Event::Html(
                    "<div class=\"notification is-danger\">Error: /img path is invalid for images</div>"
                        .into(),
                ),
                Err(super::image_source::ImageSourceError::Empty) => Event::Html(
                    "<div class=\"notification is-danger\">Error: Invalid image path</div>"
                        .into(),
                ),
                Err(super::image_source::ImageSourceError::AliasNotFound) => Event::Html(
                    "<div class=\"notification is-warning\">Error: Image not found</div>".into(),
                ),
                Err(super::image_source::ImageSourceError::NotImage) => Event::Html(
                    "<div class=\"notification is-warning\">Error: Image not found or invalid format</div>"
                        .into(),
                ),
            }
        }
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => {
            // Handle links by modifying attributes
            let url_str = dest_url.as_ref();

            // Check if it's an external URL
            if url_str.starts_with("http://") || url_str.starts_with("https://") {
                // For external links, we'll handle this in a post-processing step
                Event::Start(Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    id,
                })
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
                    Event::Start(Tag::Link {
                        link_type,
                        dest_url: CowStr::Boxed(versioned_url.into()),
                        title,
                        id,
                    })
                } else {
                    Event::Start(Tag::Link {
                        link_type,
                        dest_url,
                        title,
                        id,
                    })
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
    use crate::PageRenderContext;
    use crate::markdown::render_pipeline_support_hooks::DefaultRenderPipelineSupportHooks;
    use crate::markdown::{DocumentStructure, DocumentStructureEntry};
    use crate::nav::generate_navigation_with_user;
    use crate::shortcode::{ShortcodeRegistry, ShortcodeType, link_card, video};
    use crate::test_support::TestFixtureRoot;
    use nop_config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config,
    };
    use nop_content_store::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, ContentWidthMode, blob_path, content_id_hex,
        sidecar_path, write_sidecar_atomic,
    };
    use nop_rt_paths::RuntimePaths;
    use nop_rt_release::ReleaseTracker;
    use nop_rt_templates::MiniJinjaEngine;
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

    // Helper function to create a test config
    fn create_test_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: nop_config::test_server_list(),
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
                login_sessions: nop_config::LoginSessionConfig::default(),
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
            search: nop_config::SearchConfig::default(),
            settings: Default::default(),
            dev_mode: None,
        }
    }

    fn create_fixture_paths(prefix: &str) -> (TestFixtureRoot, RuntimePaths) {
        let fixture = TestFixtureRoot::new_unique(prefix).expect("fixture root");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        (fixture, runtime_paths)
    }

    // Helper function to create a test cache for tests
    fn create_test_cache(runtime_paths: &RuntimePaths) -> PageMetaCache {
        PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            nop_content_store::reserved_paths::ReservedPaths::default(),
        )
    }

    fn create_test_sanitizer() -> HtmlSanitizer {
        HtmlSanitizer::new()
    }

    fn render_markdown(
        markdown: &str,
        registry: &ShortcodeRegistry,
        options: &Options,
        sanitizer: &HtmlSanitizer,
        cache: &PageMetaCache,
        md_path: &str,
        content_width: ContentWidthMode,
    ) -> RenderedMarkdown {
        let hooks = DefaultRenderPipelineSupportHooks;
        generate_html(&RenderRequest {
            markdown,
            shortcode_registry: registry,
            options,
            sanitizer,
            cache,
            md_path,
            user: None,
            hooks: &hooks,
            render_state: PageRenderState::new(false, false, content_width),
        })
        .expect("render markdown")
    }

    fn container_escape_test_registry() -> ShortcodeRegistry {
        let mut registry = ShortcodeRegistry::new();
        registry.register(
            "breakout",
            |_shortcode, _ctx| Ok(r#"<section class="breakout-test">Hero</section>"#.to_string()),
            ShortcodeType {
                dynamic: false,
                container_escape: true,
            },
        );
        registry
    }

    fn heading_html_shortcode_registry() -> ShortcodeRegistry {
        let mut registry = ShortcodeRegistry::new();
        registry.register(
            "heading-html",
            |_shortcode, _ctx| {
                Ok((1..=6)
                    .map(|rank| format!("<h{rank}>Shortcode H{rank}</h{rank}>"))
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
            ShortcodeType::default(),
        );
        registry.register(
            "opaque",
            |shortcode, _ctx| {
                let title = shortcode
                    .attributes
                    .get("title")
                    .map(String::as_str)
                    .unwrap_or("");
                Ok(format!(r#"<p class="opaque-shortcode">{title}</p>"#))
            },
            ShortcodeType::default(),
        );
        registry
    }

    fn structure_entries(rendered: &RenderedMarkdown) -> Vec<(String, String, u8)> {
        rendered
            .render_state
            .document_structure
            .entries
            .iter()
            .map(|entry| (entry.id.clone(), entry.label.clone(), entry.level))
            .collect()
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

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
        let html = rendered.html;

        // Check basic markdown elements are rendered
        assert!(html.contains(r#"<h1 id="test-heading">Test Heading</h1>"#));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<em>italic</em>"));
        assert!(html.contains("<ul>"));
        assert!(html.contains("<li>List item 1</li>"));
        assert!(html.contains("<li>List item 2</li>"));
        assert!(html.contains(r#"data-site-code-block="true""#));
        assert!(html.contains(r#"data-site-code-copy="true""#));
        assert!(html.contains(r#"<img src="/builtin/copy.svg" alt="""#));
        assert!(!html.contains("NOP_CODEBLOCK_WRAPPER_START_"));
        assert!(!html.contains("NOP_CODEBLOCK_WRAPPER_END_"));
        assert!(html.contains("<pre><code"));
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
    fn leading_container_escape_renders_band_then_first_segment() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-leading-breakout");
        let registry = container_escape_test_registry();
        let options = Options::empty();
        let sanitizer = create_test_sanitizer();
        let cache = create_test_cache(&runtime_paths);

        let rendered = render_markdown(
            "((breakout))\n\nAfter hero.",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "landing",
            ContentWidthMode::Auto,
        );

        assert!(
            rendered
                .html
                .starts_with("<div class=\"site-doc-band\">")
        );
        assert!(
            rendered
                .html
                .contains("</div><div class=\"content-wrapper")
        );
        assert!(
            rendered
                .html
                .contains(r#"<div class="container content-container""#)
        );
        assert!(rendered.html.contains("<p>After hero.</p>"));
        assert_eq!(
            rendered.html.matches("<div").count(),
            rendered.html.matches("</div>").count()
        );
        assert!(!rendered.render_state.has_hero);
    }

    #[test]
    fn mid_content_escape_splits_segments_around_band() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-mid-breakout");
        let registry = container_escape_test_registry();
        let options = Options::empty();
        let sanitizer = create_test_sanitizer();
        let cache = create_test_cache(&runtime_paths);

        let rendered = render_markdown(
            "Before\n\n((breakout))\n\nAfter.",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "landing",
            ContentWidthMode::Auto,
        );

        assert!(
            rendered
                .html
                .contains("</div></div></div><div class=\"site-doc-band\">")
        );
        assert!(
            rendered
                .html
                .contains("</div><div class=\"content-wrapper")
        );
        assert_eq!(
            rendered.html.matches("<div").count(),
            rendered.html.matches("</div>").count()
        );
        assert_eq!(
            rendered.html.matches("content-wrapper").count(),
            2
        );
    }

    #[test]
    fn only_container_escape_renders_bare_band() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-only-breakout");
        let registry = container_escape_test_registry();
        let options = Options::empty();
        let sanitizer = create_test_sanitizer();
        let cache = create_test_cache(&runtime_paths);

        let rendered = render_markdown(
            "((breakout))",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "landing",
            ContentWidthMode::Auto,
        );

        assert_eq!(
            rendered.html,
            r#"<div class="site-doc-band"><section class="breakout-test">Hero</section></div>"#
        );
    }

    #[test]
    fn trailing_container_escape_leaves_no_empty_segment() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-trailing-breakout");
        let registry = container_escape_test_registry();
        let options = Options::empty();
        let sanitizer = create_test_sanitizer();
        let cache = create_test_cache(&runtime_paths);

        let rendered = render_markdown(
            "After.\n\n((breakout))",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "landing",
            ContentWidthMode::Auto,
        );

        assert!(rendered.html.ends_with("</div>"));
        assert_eq!(
            rendered.html.matches("content-wrapper").count(),
            1
        );
        assert_eq!(
            rendered.html.matches("<div").count(),
            rendered.html.matches("</div>").count()
        );
    }

    fn hero_escape_test_registry() -> ShortcodeRegistry {
        let mut registry = ShortcodeRegistry::new();
        registry.register(
            "hero-img",
            |_shortcode, _ctx| Ok(r#"<div class="sc-hero-img">Hero</div>"#.to_string()),
            ShortcodeType {
                dynamic: false,
                container_escape: true,
            },
        );
        registry
    }

    #[test]
    fn hero_shortcode_sets_has_hero_flag() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-hero-flag");
        let registry = hero_escape_test_registry();
        let options = Options::empty();
        let sanitizer = create_test_sanitizer();
        let cache = create_test_cache(&runtime_paths);

        let rendered = render_markdown(
            "((hero-img src=\"a.png\"))\n\n# Title\n\n## Alpha\n\n## Beta",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "landing",
            ContentWidthMode::Auto,
        );

        assert!(rendered.render_state.has_hero);
        assert!(!rendered.render_state.document_structure.is_empty());
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

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
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
        assert!(html.contains(r#"<h1 id="video-test">Video Test</h1>"#));
        assert!(html.contains("Some text after the videos."));
        assert!(!rendered.contains_dynamic_shortcodes);
    }

    #[test]
    fn test_generate_html_indented_code_block_does_not_get_copy_button() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-indented-code");
        let registry = create_default_registry();
        let mut options = Options::empty();
        options.insert(Options::ENABLE_STRIKETHROUGH);

        let markdown_content = r#"# Indented code

    echo hello

After."#;

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        let html = rendered.html;
        assert!(html.contains("<pre><code>"));
        assert!(!html.contains(r#"data-site-code-block="true""#));
        assert!(!html.contains(r#"data-site-code-copy="true""#));
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

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
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

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
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
        assert!(html.contains(r#"<h1 id="link-card-test">Link Card Test</h1>"#));
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

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
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

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
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
        assert!(html.contains(r#"<h1 id="mixed-content-test">Mixed Content Test</h1>"#));
        assert!(html.contains(r#"<h2 id="video-section">Video Section</h2>"#));
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
    fn displayed_headings_receive_unique_generated_ids() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-heading-ids");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            "# Page Title\n\n## Repeat!\n\nText.\n\n## Repeat\n\n### Child\n\n### Child",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(
            rendered
                .html
                .contains(r#"<h1 id="page-title">Page Title</h1>"#)
        );
        assert!(rendered.html.contains(r#"<h2 id="repeat">Repeat!</h2>"#));
        assert!(rendered.html.contains(r#"<h2 id="repeat-2">Repeat</h2>"#));
        assert!(rendered.html.contains(r#"<h3 id="child">Child</h3>"#));
        assert!(rendered.html.contains(r#"<h3 id="child-2">Child</h3>"#));
        assert_eq!(rendered.render_state.document_structure.entries.len(), 4);
    }

    #[test]
    fn heading_structure_labels_are_plain_text_for_markup_rendering() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-heading-labels");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            "## A & `B`\n\n## <span>C</span>\n",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        let labels: Vec<_> = rendered
            .render_state
            .document_structure
            .entries
            .iter()
            .map(|entry| entry.label.as_str())
            .collect();
        assert_eq!(labels, vec!["A & B", "C"]);
    }

    #[test]
    fn empty_markdown_headings_do_not_invent_section_entries_or_shift_ids() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-empty-heading-labels");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            "# Page\n\n##\n\n## Alpha\n\n###\n\n## Beta\n\n### Detail",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(!rendered.html.contains(r#"id="section"#));
        assert!(rendered.html.contains("<h2></h2>"));
        assert!(rendered.html.contains("<h3></h3>"));
        assert!(rendered.html.contains(r#"<h2 id="alpha">Alpha</h2>"#));
        assert!(rendered.html.contains(r#"<h2 id="beta">Beta</h2>"#));
        assert!(rendered.html.contains(r#"<h3 id="detail">Detail</h3>"#));
        assert_eq!(
            structure_entries(&rendered),
            vec![
                ("alpha".to_string(), "Alpha".to_string(), 1),
                ("beta".to_string(), "Beta".to_string(), 1),
                ("detail".to_string(), "Detail".to_string(), 2),
            ]
        );
    }

    #[test]
    fn shortcode_output_headings_do_not_affect_document_structure() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-shortcode-heading-opaque");
        let registry = heading_html_shortcode_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            "# Page\n\n## Markdown One\n\n((heading-html))\n\n## Markdown Two\n\n### Markdown Detail",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(rendered.html.contains("<h1>Shortcode H1</h1>"));
        assert!(rendered.html.contains("<h6>Shortcode H6</h6>"));
        assert_eq!(
            structure_entries(&rendered),
            vec![
                ("markdown-one".to_string(), "Markdown One".to_string(), 1),
                ("markdown-two".to_string(), "Markdown Two".to_string(), 1),
                (
                    "markdown-detail".to_string(),
                    "Markdown Detail".to_string(),
                    2,
                ),
            ]
        );
    }

    #[test]
    fn raw_html_headings_do_not_affect_document_structure() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-raw-heading-opaque");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            r#"# Page

<h1>Raw H1</h1>
<h2>Raw H2</h2>
<h3>Raw H3</h3>
<h4>Raw H4</h4>
<h5>Raw H5</h5>
<h6>Raw H6</h6>

## Markdown One

## Markdown Two

### Markdown Detail"#,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(rendered.html.contains("<h1>Raw H1</h1>"));
        assert!(rendered.html.contains("<h6>Raw H6</h6>"));
        assert_eq!(
            structure_entries(&rendered),
            vec![
                ("markdown-one".to_string(), "Markdown One".to_string(), 1),
                ("markdown-two".to_string(), "Markdown Two".to_string(), 1),
                (
                    "markdown-detail".to_string(),
                    "Markdown Detail".to_string(),
                    2,
                ),
            ]
        );
    }

    #[test]
    fn markdown_headings_retain_selected_levels_labels_and_anchors() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-heading-structure-levels");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            "# Page\n\n## One\n\n### Detail A\n\n#### Deep\n\n##### Deeper\n\n###### Deepest\n\n## Two\n\n### Detail B",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(rendered.html.contains(r#"<h1 id="page">Page</h1>"#));
        assert!(rendered.html.contains(r#"<h6 id="deepest">Deepest</h6>"#));
        assert_eq!(
            structure_entries(&rendered),
            vec![
                ("one".to_string(), "One".to_string(), 1),
                ("detail-a".to_string(), "Detail A".to_string(), 2),
                ("two".to_string(), "Two".to_string(), 1),
                ("detail-b".to_string(), "Detail B".to_string(), 2),
            ]
        );
    }

    #[test]
    fn mixed_markdown_shortcode_and_raw_html_headings_keep_markdown_structure_only() {
        let (_fixture, runtime_paths) = create_fixture_paths("markdown-mixed-heading-sources");
        let registry = heading_html_shortcode_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            r#"# Page

<h2>Raw Alpha</h2>

## Alpha

((heading-html))

<h3>Raw Detail</h3>

## Beta"#,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(rendered.html.contains("<h2>Raw Alpha</h2>"));
        assert!(rendered.html.contains("<h2>Shortcode H2</h2>"));
        assert_eq!(
            structure_entries(&rendered),
            vec![
                ("alpha".to_string(), "Alpha".to_string(), 1),
                ("beta".to_string(), "Beta".to_string(), 1),
            ]
        );
    }

    #[test]
    fn multiline_shortcode_attribute_hashes_do_not_create_or_shift_headings() {
        let (_fixture, runtime_paths) =
            create_fixture_paths("markdown-multiline-shortcode-heading");
        let registry = heading_html_shortcode_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();

        let rendered = render_markdown(
            "# Page\n\n## Alpha\n\n((opaque title=\"Intro\n# Phantom One\n## Phantom Two\"))\n\n## Beta\n\n### Detail",
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(rendered.html.contains("Phantom One"));
        assert!(!rendered.html.contains(r#"<h1 id="phantom-one">"#));
        assert!(!rendered.html.contains(r#"<h2 id="phantom-two">"#));
        assert_eq!(
            structure_entries(&rendered),
            vec![
                ("alpha".to_string(), "Alpha".to_string(), 1),
                ("beta".to_string(), "Beta".to_string(), 1),
                ("detail".to_string(), "Detail".to_string(), 2),
            ]
        );
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

<figure style="float:right; margin: 0 0 1rem 1rem;">
  <img style="float:right; margin: 0 0 1rem 1rem; max-width: 40%;" src="/id/abcdef">
  <figcaption style="text-align: center;">Caption</figcaption>
</figure>

<p style="clear: both;">Paragraph after figure.</p>

<h2 style="text-align: center;">Styled heading</h2>

Video shortcode: ((video src="safe.mp4" width="640"))

More user content: <object data="bad.swf"></object>

Link card: ((link-card title="Safe Link" link="https://safe.com"))

JavaScript in user content: <a href="javascript:alert('bad')">bad link</a>"#;

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
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
        assert!(html.contains(r#"<h1 id="security-test">Security Test</h1>"#));
        assert!(html.contains("User content with dangerous HTML"));
        assert!(html.contains("More user content"));
        assert!(html.contains(r#"<figure style="float:right"#));
        assert!(html.contains(r#"<img style="float:right"#));
        assert!(html.contains(r#"max-width: 40%"#));
        assert!(html.contains(r#"<figcaption style="text-align: center;">Caption</figcaption>"#));
        assert!(html.contains(r#"<p style="clear: both;">Paragraph after figure.</p>"#));
        assert!(html.contains(r#"<h2 style="text-align: center;">Styled heading</h2>"#));
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

        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );
        let html = rendered.html;

        // Check that regular markdown is processed
        assert!(html.contains(r#"<h1 id="no-shortcodes">No Shortcodes</h1>"#));
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
        let blue_theme = r#"# Blue Theme variables
color-background-primary-light #3366ff
font-body-family "Test Font", sans-serif
"#;
        fs::write(runtime_paths.themes_dir.join("blue.theme"), blue_theme)
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
            disable_navbar: false,
            disable_floating_nav: false,
            content_width: Default::default(),
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
            nop_content_store::reserved_paths::ReservedPaths::default(),
        );
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime
            .block_on(cache.rebuild_cache(true))
            .expect("cache rebuild");

        let title = sidecar.title.as_deref().expect("sidecar title");
        let theme = sidecar.theme.as_deref();

        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            markdown_content,
            &registry,
            &options,
            &sanitizer,
            &cache,
            "about",
            ContentWidthMode::Auto,
        );
        let navigation =
            generate_navigation_with_user(&cache, None, config.navigation.max_dropdown_items);
        let release_tracker = ReleaseTracker::new();
        let templates = MiniJinjaEngine::new();
        let settings = config
            .settings
            .normalized_with_legacy_app(Some(&config.app))
            .expect("normalized runtime settings");
        let runtime_settings = nop_config::RuntimeSettings::new(&settings);

        let content_id_hex_value = content_id_hex(content_id);
        let render_ctx = PageRenderContext {
            config: &config,
            runtime_settings: &runtime_settings,
            runtime_paths: &runtime_paths,
            theme,
            release_tracker: &release_tracker,
            template_engine: &templates,
            app_version: "Release 1",
            show_admin_version_footer: false,
        };
        let html_page = runtime.block_on(generate_html_page_with_user(
            title,
            &rendered.html,
            &navigation,
            &rendered.render_state,
            &content_id_hex_value,
            &render_ctx,
        ));

        assert!(html_page.contains("<title>About NoPressure</title>"));
        assert!(html_page.contains(r#"<h1 id="about-nopressure">About NoPressure</h1>"#));
        assert!(html_page.contains("/builtin/theme-preset.css?v="));
        assert!(html_page.contains("--color-background-primary-light: #3366ff;"));
        assert!(html_page.contains("Test App"));
        assert!(html_page.contains("/builtin/bulma.min.css?v="));
        assert!(html_page.contains(&format!(
            "data-site-content-id=\"{}\"",
            content_id_hex_value
        )));
        assert!(!html_page.contains("data-site-doc-structure"));
        assert!(!html_page.contains("data-site-doc-structure-menu"));
        assert!(html_page.contains(r#"class="doc-layout""#));
        assert!(!html_page.contains("{title}"));
        assert!(!html_page.contains("{content}"));
        assert!(!html_page.contains("{nav_html}"));
        assert!(!html_page.contains("{user_nav_html}"));
    }

    #[test]
    fn disabled_navbar_omits_narrow_structure_menu_but_keeps_desktop_panel() {
        let fixture = TestFixtureRoot::new_unique("markdown-disabled-navbar-structure")
            .expect("fixture root");
        fixture.init_runtime_layout().expect("layout init");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        let config = create_test_config();
        let settings = config
            .settings
            .normalized_with_legacy_app(Some(&config.app))
            .expect("normalized runtime settings");
        let runtime_settings = nop_config::RuntimeSettings::new(&settings);
        let release_tracker = ReleaseTracker::new();
        let templates = MiniJinjaEngine::new();
        let mut render_state = PageRenderState::new(true, false, ContentWidthMode::Auto);
        render_state.document_structure = DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "section".to_string(),
                label: "Section".to_string(),
                level: 1,
            }],
            title: None,
        };
        let render_ctx = PageRenderContext {
            config: &config,
            runtime_settings: &runtime_settings,
            runtime_paths: &runtime_paths,
            theme: None,
            release_tracker: &release_tracker,
            template_engine: &templates,
            app_version: "Release 1",
            show_admin_version_footer: false,
        };
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");

        let html_page = runtime.block_on(generate_html_page_with_user(
            "Disabled Navbar",
            r#"<h2 id="section">Section</h2>"#,
            &[],
            &render_state,
            "0000000000000001",
            &render_ctx,
        ));

        assert!(!html_page.contains("data-site-navbar"));
        assert!(html_page.contains("data-site-doc-structure"));
        assert!(html_page.contains(r##"href="#section""##));
        assert!(!html_page.contains("data-site-doc-structure-menu"));
        assert!(!html_page.contains("data-site-doc-structure-menu-toggle"));
    }

    #[test]
    fn hero_presence_omits_panel_but_keeps_drawer_and_topbar() {
        let fixture =
            TestFixtureRoot::new_unique("markdown-hero-structure").expect("fixture root");
        fixture.init_runtime_layout().expect("layout init");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        let config = create_test_config();
        let settings = config
            .settings
            .normalized_with_legacy_app(Some(&config.app))
            .expect("normalized runtime settings");
        let runtime_settings = nop_config::RuntimeSettings::new(&settings);
        let release_tracker = ReleaseTracker::new();
        let templates = MiniJinjaEngine::new();
        let mut render_state = PageRenderState::new(false, false, ContentWidthMode::Auto);
        render_state.has_hero = true;
        render_state.document_structure = DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "section".to_string(),
                label: "Section".to_string(),
                level: 1,
            }],
            title: None,
        };
        let render_ctx = PageRenderContext {
            config: &config,
            runtime_settings: &runtime_settings,
            runtime_paths: &runtime_paths,
            theme: None,
            release_tracker: &release_tracker,
            template_engine: &templates,
            app_version: "Release 1",
            show_admin_version_footer: false,
        };
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");

        let html_page = runtime.block_on(generate_html_page_with_user(
            "Hero Page",
            r#"<h2 id="section">Section</h2>"#,
            &[],
            &render_state,
            "0000000000000001",
            &render_ctx,
        ));

        assert!(html_page.contains("data-site-navbar"));
        assert!(!html_page.contains("<aside"));
        assert!(html_page.contains("data-site-structure-drawer"));
        assert!(html_page.contains("data-site-topbar"));
        assert!(html_page.contains(r##"href="#section""##));
    }

    #[test]
    fn disabled_floating_nav_omits_structure_panel_and_mobile_links() {
        let fixture =
            TestFixtureRoot::new_unique("markdown-disabled-floating-nav").expect("fixture root");
        fixture.init_runtime_layout().expect("layout init");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        let config = create_test_config();
        let settings = config
            .settings
            .normalized_with_legacy_app(Some(&config.app))
            .expect("normalized runtime settings");
        let runtime_settings = nop_config::RuntimeSettings::new(&settings);
        let release_tracker = ReleaseTracker::new();
        let templates = MiniJinjaEngine::new();
        let mut render_state = PageRenderState::new(false, true, ContentWidthMode::Auto);
        render_state.document_structure = DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "section".to_string(),
                label: "Section".to_string(),
                level: 1,
            }],
            title: None,
        };
        let render_ctx = PageRenderContext {
            config: &config,
            runtime_settings: &runtime_settings,
            runtime_paths: &runtime_paths,
            theme: None,
            release_tracker: &release_tracker,
            template_engine: &templates,
            app_version: "Release 1",
            show_admin_version_footer: false,
        };
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");

        let html_page = runtime.block_on(generate_html_page_with_user(
            "Disabled Floating Nav",
            r#"<h2 id="section">Section</h2>"#,
            &[],
            &render_state,
            "0000000000000001",
            &render_ctx,
        ));

        assert!(html_page.contains("data-site-navbar"));
        assert!(!html_page.contains("data-site-doc-structure"));
        assert!(!html_page.contains("data-site-doc-structure-menu"));
        assert!(!html_page.contains(r##"href="#section""##));
    }

    #[test]
    fn navbar_omits_structure_menu_links() {
        let fixture =
            TestFixtureRoot::new_unique("markdown-navbar-structure-menu").expect("fixture root");
        fixture.init_runtime_layout().expect("layout init");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        let config = create_test_config();
        let settings = config
            .settings
            .normalized_with_legacy_app(Some(&config.app))
            .expect("normalized runtime settings");
        let runtime_settings = nop_config::RuntimeSettings::new(&settings);
        let release_tracker = ReleaseTracker::new();
        let templates = MiniJinjaEngine::new();
        let mut render_state = PageRenderState::new(false, false, ContentWidthMode::Auto);
        render_state.document_structure = DocumentStructure {
            entries: vec![DocumentStructureEntry {
                id: "section".to_string(),
                label: "Section".to_string(),
                level: 1,
            }],
            title: None,
        };
        let render_ctx = PageRenderContext {
            config: &config,
            runtime_settings: &runtime_settings,
            runtime_paths: &runtime_paths,
            theme: None,
            release_tracker: &release_tracker,
            template_engine: &templates,
            app_version: "Release 1",
            show_admin_version_footer: false,
        };
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");

        let html_page = runtime.block_on(generate_html_page_with_user(
            "Navbar Structure",
            r#"<h2 id="section">Section</h2>"#,
            &[],
            &render_state,
            "0000000000000001",
            &render_ctx,
        ));

        let mobile_menu_start = html_page
            .find(r#"data-site-mobile-menu"#)
            .expect("mobile menu");
        let navbar_end = html_page[mobile_menu_start..]
            .find("</nav>")
            .map(|offset| mobile_menu_start + offset)
            .expect("navbar end");

        assert!(html_page.contains("data-site-doc-structure"));
        assert!(html_page.contains(r##"data-site-doc-structure-link href="#section""##));
        assert!(!html_page.contains("data-site-doc-structure-menu"));
        assert!(!html_page.contains("data-site-doc-structure-menu-toggle"));
        assert!(!html_page.contains("data-site-doc-structure-menu-panel"));
        assert!(!html_page.contains(">Structure<"));
        assert!(!html_page[mobile_menu_start..navbar_end].contains("data-site-doc-structure-link"));
    }

    fn make_paragraph(len: usize) -> String {
        "a".repeat(len)
    }

    #[test]
    fn content_width_auto_stays_compact_for_long_paragraphs() {
        let (_fixture, runtime_paths) = create_fixture_paths("content-width-auto");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            &make_paragraph(300),
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Auto,
        );

        assert!(rendered.render_state.use_compact_width);
    }

    #[test]
    fn content_width_wide_overrides_short_paragraphs() {
        let (_fixture, runtime_paths) = create_fixture_paths("content-width-wide");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            &make_paragraph(10),
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Wide,
        );

        assert!(!rendered.render_state.use_compact_width);
    }

    #[test]
    fn content_width_narrow_overrides_long_paragraphs() {
        let (_fixture, runtime_paths) = create_fixture_paths("content-width-narrow");
        let registry = create_default_registry();
        let options = Options::empty();
        let cache = create_test_cache(&runtime_paths);
        let sanitizer = create_test_sanitizer();
        let rendered = render_markdown(
            &make_paragraph(300),
            &registry,
            &options,
            &sanitizer,
            &cache,
            "test.md",
            ContentWidthMode::Narrow,
        );

        assert!(rendered.render_state.use_compact_width);
    }
}
