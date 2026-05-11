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

/// Per-page context handed to every hook invocation.
///
/// Future fields (theme, page kind, content id, …) extend this struct without
/// changing the trait shape.
pub struct PageRenderHookContext {
    /// `true` when the surrounding page is rendered with the compact (960px)
    /// content width. Hook implementations consult this so the reopened
    /// container matches the page's actual width variant.
    pub use_compact_width: bool,
}

/// Render-pipeline support hooks the layout layer hands to the markdown
/// renderer. Both methods are called per container-escape shortcode site.
pub trait RenderPipelineSupportHooks: Send + Sync {
    /// HTML fragment that closes the page's content container.
    fn escape_container(&self, ctx: &PageRenderHookContext) -> String;

    /// HTML fragment that reopens the page's content container.
    fn return_to_container(&self, ctx: &PageRenderHookContext) -> String;
}

/// Hooks that mirror the current `main_layout.html` nesting. The outer
/// `.content-wrapper` is full-viewport-width already and is not escaped or
/// reopened — only `.container.content-container` and `.content` are.
pub struct DefaultRenderPipelineSupportHooks;

impl RenderPipelineSupportHooks for DefaultRenderPipelineSupportHooks {
    fn escape_container(&self, _ctx: &PageRenderHookContext) -> String {
        // Closes `.content` then `.container.content-container`.
        "</div></div>".to_string()
    }

    fn return_to_container(&self, ctx: &PageRenderHookContext) -> String {
        let max_width = if ctx.use_compact_width { 960 } else { 1152 };
        format!(
            r#"<div class="container content-container" style="max-width: {}px;"><div class="content">"#,
            max_width
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_hooks_escape_returns_two_close_divs() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let ctx = PageRenderHookContext {
            use_compact_width: false,
        };
        let escape = hooks.escape_container(&ctx);
        assert_eq!(escape.matches("</div>").count(), 2);
        assert!(!escape.contains("<div"));
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
        assert_eq!(ret.matches("<div").count(), 2);
        assert_eq!(ret.matches("</div").count(), 0);
    }

    #[test]
    fn default_hooks_return_uses_compact_max_width_when_compact() {
        let hooks = DefaultRenderPipelineSupportHooks;
        let ctx = PageRenderHookContext {
            use_compact_width: true,
        };
        let ret = hooks.return_to_container(&ctx);
        assert!(ret.contains("max-width: 960px;"));
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
}
