// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::blob_path;
use crate::public::cache::{HtmlCacheEnvelope, finalize_html_response};
use crate::public::nav::generate_navigation_with_user;
use crate::public::page_meta_cache::check_file_access;
use crate::public::{PageRenderContext, PublicRequestContext};
use crate::security;
use actix_web::{HttpResponse, Result};
use gray_matter::{Matter, engine::YAML};
use pulldown_cmark::Options;
use tokio::fs;

use super::parser::generate_html;
use super::render::generate_html_page_with_user;

pub async fn serve_markdown_alias(
    alias: &str,
    ctx: &PublicRequestContext<'_>,
) -> Result<HttpResponse> {
    let config = ctx.config;
    let cache = ctx.cache;
    let user = ctx.user();
    let shortcode_registry = ctx.shortcode_registry;
    let release_tracker = ctx.release_tracker;
    let sanitizer = &ctx.app_state.html_sanitizer;
    let error_renderer = &ctx.app_state.error_renderer;
    let template_engine = ctx.app_state.templates.as_ref();
    let req = ctx.req;

    let (file_exists, has_access) = check_file_access(cache, alias, user, Some(req), Some(config));

    if !file_exists {
        log::debug!("Alias does not exist: {}", alias);
        return handle_access_denied(alias, ctx);
    }
    if !has_access {
        log::warn!("User does not have access to alias: {}", alias);
        return handle_access_denied(alias, ctx);
    }

    let object = match cache.get_by_alias(alias) {
        Some(object) => object,
        None => return crate::public::error::serve_404(error_renderer, Some(template_engine)),
    };

    let blob_path = blob_path(
        &ctx.app_state.runtime_paths.content_dir,
        object.key.id,
        object.key.version,
    );

    let canonical_file_path = match security::canonical_path_checks(
        &blob_path,
        &ctx.app_state.runtime_paths.content_dir.to_string_lossy(),
        Some(&config.app.name),
    ) {
        Ok(path) => path,
        Err(error_response) => return error_response,
    };

    let content = match fs::read_to_string(&canonical_file_path).await {
        Ok(content) => content,
        Err(_) => return crate::public::error::serve_500(error_renderer, Some(template_engine)),
    };

    let matter = Matter::<YAML>::new();
    let result = matter.parse(&content);

    let title = object
        .title
        .clone()
        .unwrap_or_else(|| config.app.name.clone());
    let theme = object.theme.clone();

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_TASKLISTS);

    let rendered_html = match generate_html(
        &result,
        shortcode_registry,
        &options,
        sanitizer,
        cache,
        alias,
        user,
        config.rendering.short_paragraph_length,
    ) {
        Ok(rendered) => rendered,
        Err(error) => {
            log::error!("Failed to render markdown '{}': {}", alias, error);
            return crate::public::error::serve_500(error_renderer, Some(template_engine));
        }
    };

    let navigation = generate_navigation_with_user(cache, user);

    let render_ctx = PageRenderContext {
        config,
        runtime_paths: &ctx.app_state.runtime_paths,
        theme: theme.as_deref(),
        user,
        release_tracker,
        template_engine,
    };
    let html_page = generate_html_page_with_user(
        &title,
        &rendered_html.html,
        &navigation,
        rendered_html.use_compact_width,
        &render_ctx,
    )
    .await;

    let content_hash = Some(format!("{:x}", md5::compute(content.as_bytes())));

    Ok(finalize_html_response(
        req,
        HtmlCacheEnvelope {
            release_tracker,
            content_hash,
            contains_dynamic_content: rendered_html.contains_dynamic_shortcodes,
            content_type: "text/html; charset=utf-8",
        },
        html_page,
    ))
}

pub fn handle_access_denied(alias: &str, ctx: &PublicRequestContext<'_>) -> Result<HttpResponse> {
    let user = ctx.user();
    if user.is_none() {
        let current_path = if alias == "index" {
            "/".to_string()
        } else {
            format!("/{}", alias)
        };

        Ok(HttpResponse::Found()
            .append_header((
                "Location",
                format!("/login?return_path={}", urlencoding::encode(&current_path)),
            ))
            .finish())
    } else {
        crate::public::error::serve_404(
            &ctx.app_state.error_renderer,
            Some(ctx.app_state.templates.as_ref()),
        )
    }
}
