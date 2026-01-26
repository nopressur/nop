// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::public::PageRenderContext;
use crate::public::nav::NavItem;
use crate::templates::{load_template, render_template};

use super::theme::load_theme_content;

const USER_MENU_PLACEHOLDER: &str = r#"<div data-site-user-menu></div>"#;

pub async fn generate_html_page_with_user(
    title: &str,
    content: &str,
    navigation: &[NavItem],
    use_compact_width: bool,
    render_ctx: &PageRenderContext<'_>,
) -> String {
    // Load theme content
    let theme_content = load_theme_content(render_ctx.runtime_paths, render_ctx.theme).await;

    // Generate navigation HTML
    let nav_html =
        crate::public::nav::generate_navigation_html(navigation, render_ctx.template_engine);

    // Generate user navigation HTML
    let user_nav_html = generate_user_navigation_placeholder();

    // Load template
    let template = load_template("public/main_layout").unwrap_or_else(|_| {
        // Fallback template if loading fails
        r#"<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body><div>{content}</div></body></html>"#
            .to_string()
    });

    // Prepare template variables
    let escaped_title = crate::public::nav::html_escape(title);
    let escaped_app_name = crate::public::nav::html_escape(&render_ctx.config.app.name);
    let release_hex = render_ctx.release_tracker.current_hex();
    let bulma_href = format!("/builtin/bulma.min.css?v={}", release_hex);
    let favicon_href = format!("/builtin/favicon.ico?v={}", release_hex);
    let site_src = format!("/builtin/site.js?v={}", release_hex);
    let (content_wrapper_class, content_container_style) = if use_compact_width {
        ("content-wrapper", "max-width: 960px;")
    } else {
        ("content-wrapper is-wide", "max-width: 1152px;")
    };

    let vars = crate::template_vars! {
        "title" => &escaped_title,
        "content" => content,
        "theme_content" => &theme_content,
        "nav_html" => &nav_html,
        "user_nav_html" => &user_nav_html,
        "app_name" => &escaped_app_name,
        "bulma_css" => &bulma_href,
        "favicon_ico" => &favicon_href,
        "site_js" => &site_src,
        "content_wrapper_class" => &content_wrapper_class,
        "content_compact" => &use_compact_width.to_string(),
        "short_paragraph_length" => &render_ctx.config.rendering.short_paragraph_length.to_string(),
        "content_container_style" => &content_container_style,
    };

    render_template(&template, &vars)
}

fn generate_user_navigation_placeholder() -> String {
    USER_MENU_PLACEHOLDER.to_string()
}
