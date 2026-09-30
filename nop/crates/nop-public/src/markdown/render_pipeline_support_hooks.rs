// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

//! Hooks the markdown render pipeline calls when a shortcode marked
//! `container_escape` needs to break out of the page's content container.
//!
//! `escape_container` is emitted immediately before the shortcode's HTML to
//! close the container; `return_to_container` is emitted immediately after to
//! reopen it. Implementations carry their own state, so width / theme / page
//! kind awareness can grow on the implementing side without changing the
//! markdown layer's call site.

use super::document_structure::DocumentStructure;
use nop_content_store::flat_storage::ContentWidthMode;

/// Layout-affecting state carried through public page rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRenderState {
    pub disable_navbar: bool,
    pub disable_floating_nav: bool,
    pub content_width: ContentWidthMode,
    pub document_structure: DocumentStructure,
    pub use_compact_width: bool,
    pub has_hero: bool,
}

impl PageRenderState {
    pub fn new(
        disable_navbar: bool,
        disable_floating_nav: bool,
        content_width: ContentWidthMode,
    ) -> Self {
        Self {
            disable_navbar,
            disable_floating_nav,
            content_width,
            document_structure: DocumentStructure::default(),
            use_compact_width: false,
            has_hero: false,
        }
    }

    pub fn hook_context(&self) -> PageRenderHookContext {
        PageRenderHookContext {
            use_compact_width: self.use_compact_width,
        }
    }
}

/// Per-page context handed to every hook invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRenderHookContext {
    /// `true` when the surrounding page is rendered with the compact (960px)
    /// content width. Hook implementations consult this so the reopened
    /// container matches the page's actual width variant.
    pub use_compact_width: bool,
}

/// Full-width band wrapping container-escape shortcode output so it spans the
/// whole grid instead of the centered content column.
pub(crate) const DOC_BAND_OPEN: &str = "<div class=\"site-doc-band\">";
/// Closes a [`DOC_BAND_OPEN`] band.
pub(crate) const DOC_BAND_CLOSE: &str = "</div>";

/// Render-pipeline support hooks the layout layer hands to the markdown
/// renderer. The content stream is a balanced sequence of content segments
/// (wrapper, container, content) with full-width escape bands between them;
/// every method is called per container-escape shortcode site.
pub trait RenderPipelineSupportHooks: Send + Sync {
    /// HTML fragment that opens a content segment: wrapper, container, content.
    fn open_content_segment(&self, ctx: &PageRenderHookContext) -> String;

    /// HTML fragment that closes a content segment: content, container, wrapper.
    fn close_content_segment(&self) -> String;

    /// HTML fragment that closes the open segment and opens the escape band.
    fn escape_container(&self, ctx: &PageRenderHookContext) -> String;

    /// HTML fragment that closes the escape band and reopens a content segment.
    fn return_to_container(&self, ctx: &PageRenderHookContext) -> String;
}

/// Hooks that mirror the content stream segments handed to `main_layout.html`.
pub struct DefaultRenderPipelineSupportHooks;

pub(crate) fn content_wrapper_class(use_compact_width: bool) -> &'static str {
    if use_compact_width {
        "content-wrapper"
    } else {
        "content-wrapper is-wide"
    }
}

pub(crate) fn content_container_max_width(use_compact_width: bool) -> &'static str {
    if use_compact_width {
        "min(var(--size-content-measure, 75ch), 100%)"
    } else {
        "1152px"
    }
}

pub(crate) fn content_container_style(use_compact_width: bool) -> String {
    format!(
        "max-width: {};",
        content_container_max_width(use_compact_width)
    )
}

pub(crate) fn open_content_container(use_compact_width: bool) -> String {
    format!(
        r#"<div class="container content-container" style="{}"><div class="content">"#,
        content_container_style(use_compact_width)
    )
}

impl RenderPipelineSupportHooks for DefaultRenderPipelineSupportHooks {
    fn open_content_segment(&self, ctx: &PageRenderHookContext) -> String {
        format!(
            r#"<div class="{}" data-compact="{}" data-site-close-dropdowns>{}"#,
            content_wrapper_class(ctx.use_compact_width),
            ctx.use_compact_width,
            open_content_container(ctx.use_compact_width)
        )
    }

    fn close_content_segment(&self) -> String {
        // Closes `.content`, then `.container.content-container`, then `.content-wrapper`.
        "</div></div></div>".to_string()
    }

    fn escape_container(&self, _ctx: &PageRenderHookContext) -> String {
        format!("{}{}", self.close_content_segment(), DOC_BAND_OPEN)
    }

    fn return_to_container(&self, ctx: &PageRenderHookContext) -> String {
        format!("{}{}", DOC_BAND_CLOSE, self.open_content_segment(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_hooks_close_segment_closes_content_container_and_wrapper() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let closes = hooks.close_content_segment();
        assert_eq!(closes.matches("</div>").count(), 3);
        assert!(!closes.contains("<div"));
    }

    #[test]
    fn default_hooks_escape_closes_segment_and_opens_full_width_band() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let ctx = PageRenderHookContext {
            use_compact_width: false,
        };
        let escape = hooks.escape_container(&ctx);
        assert_eq!(escape.matches("</div>").count(), 3);
        assert!(escape.contains("site-doc-band"));
        assert!(escape.ends_with("<div class=\"site-doc-band\">"));
    }

    #[test]
    fn default_hooks_return_uses_wide_max_width_when_not_compact() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let ctx = PageRenderHookContext {
            use_compact_width: false,
        };
        let ret = hooks.return_to_container(&ctx);
        assert!(ret.contains("max-width: 1152px;"));
        assert!(!ret.contains("960px"));
        assert!(ret.contains(r#"class="container content-container""#));
        assert!(ret.contains(r#"class="content""#));
        assert!(ret.starts_with("</div>"));
        assert!(ret.contains(r#"class="content-wrapper is-wide""#));
        assert!(ret.contains("data-site-close-dropdowns"));
        assert_eq!(ret.matches("<div").count(), 3);
        assert_eq!(ret.matches("</div").count(), 1);
    }

    #[test]
    fn default_hooks_return_uses_compact_max_width_when_compact() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let ctx = PageRenderHookContext {
            use_compact_width: true,
        };
        let ret = hooks.return_to_container(&ctx);
        assert!(ret.contains("max-width: min(var(--size-content-measure, 75ch), 100%);"));
        assert!(!ret.contains("1152px"));
    }

    #[test]
    fn escape_and_return_balance_each_other() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let ctx = PageRenderHookContext {
            use_compact_width: false,
        };
        let opens = hooks.return_to_container(&ctx).matches("<div").count();
        let closes = hooks.escape_container(&ctx).matches("</div>").count();
        assert_eq!(opens, closes);
    }

    #[test]
    fn open_and_close_content_segment_balance() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let ctx = PageRenderHookContext {
            use_compact_width: true,
        };
        let opens = hooks.open_content_segment(&ctx);
        let closes = hooks.close_content_segment();
        assert_eq!(opens.matches("<div").count(), 3);
        assert_eq!(opens.matches("<div").count(), closes.matches("</div>").count());
        assert!(opens.contains(r#"class="content-wrapper""#));
        assert!(opens.contains(r#"data-compact="true""#));
        assert!(opens.contains("data-site-close-dropdowns"));
    }
}
