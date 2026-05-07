// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::PublicRequestContext;
use super::streaming::{calculate_range_bounds, format_content_range_header, parse_range_header};
use super::{markdown, shortcode::ShortcodeRegistry};
use crate::RenderTools;
use actix_web::{HttpRequest, HttpResponse, Result, body::SizedStream, http, web};
use log::debug;
use nop_config::ValidatedConfig;
use nop_content_store::flat_storage::{
    blob_path, canonicalize_alias, content_id_hex, parse_content_id_hex,
};
use nop_rt_iam::AuthRequest;
use nop_rt_page_cache::PageMetaCache;
use nop_rt_paths::RuntimePaths;
use nop_rt_release::ReleaseTracker;
use nop_rt_security as security;
use nop_rt_security::SecurityTools;
use nop_rt_security::check_file_access;
use nop_rt_templates::RequestTools;
use nop_rt_templates::error;
use tokio_util::io::ReaderStream;

const DEFAULT_HOME_ALIAS: &str = "index";
const CACHE_CONTROL_IMMUTABLE: &str = "public, max-age=31536000, immutable";

#[allow(clippy::too_many_arguments)]
pub async fn index(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    cache: web::Data<PageMetaCache>,
    shortcode_registry: web::Data<ShortcodeRegistry>,
    release_tracker: web::Data<ReleaseTracker>,
    runtime_paths: web::Data<RuntimePaths>,
    request_tools: web::Data<RequestTools>,
    render_tools: web::Data<RenderTools>,
    security_tools: web::Data<SecurityTools>,
) -> Result<HttpResponse> {
    if let Some(error_response) = security::is_ip_blocked(
        &security_tools.threat_tracker,
        &req,
        &config,
        &request_tools.error_renderer,
        Some(request_tools.templates.as_ref()),
    )
    .await
    {
        return error_response;
    }

    let raw_path = req.path().trim_start_matches('/');
    if let Some(error_response) = security::route_checks(
        raw_path,
        Some(&req),
        Some(&config),
        Some(&security_tools.threat_tracker),
        Some(&request_tools.error_renderer),
        Some(request_tools.templates.as_ref()),
    ) {
        return error_response;
    }

    let ctx = PublicRequestContext::new(
        config.as_ref(),
        cache.as_ref(),
        shortcode_registry.as_ref(),
        release_tracker.as_ref(),
        runtime_paths.as_ref(),
        request_tools.as_ref(),
        render_tools.as_ref(),
        &req,
        req.user_info(),
    );

    markdown::serve_markdown_alias(DEFAULT_HOME_ALIAS, &ctx).await
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_route(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    cache: web::Data<PageMetaCache>,
    shortcode_registry: web::Data<ShortcodeRegistry>,
    release_tracker: web::Data<ReleaseTracker>,
    runtime_paths: web::Data<RuntimePaths>,
    request_tools: web::Data<RequestTools>,
    render_tools: web::Data<RenderTools>,
    security_tools: web::Data<SecurityTools>,
) -> Result<HttpResponse> {
    if let Some(error_response) = security::is_ip_blocked(
        &security_tools.threat_tracker,
        &req,
        &config,
        &request_tools.error_renderer,
        Some(request_tools.templates.as_ref()),
    )
    .await
    {
        return error_response;
    }

    let raw_path: String = req.match_info().get("path").unwrap_or("").to_string();

    if let Some(error_response) = security::route_checks(
        &raw_path,
        Some(&req),
        Some(&config),
        Some(&security_tools.threat_tracker),
        Some(&request_tools.error_renderer),
        Some(request_tools.templates.as_ref()),
    ) {
        return error_response;
    }

    let alias = if raw_path.is_empty() {
        DEFAULT_HOME_ALIAS.to_string()
    } else {
        raw_path
    };

    let canonical_alias = match canonicalize_route_path(&alias) {
        Some(alias) => alias,
        None => {
            return error::serve_404(
                &request_tools.error_renderer,
                Some(request_tools.templates.as_ref()),
            );
        }
    };

    let ctx = PublicRequestContext::new(
        config.as_ref(),
        cache.as_ref(),
        shortcode_registry.as_ref(),
        release_tracker.as_ref(),
        runtime_paths.as_ref(),
        request_tools.as_ref(),
        render_tools.as_ref(),
        &req,
        req.user_info(),
    );

    let user = ctx.user();

    let user_roles = user.map(|user| user.roles.as_slice());
    let dev_mode_bypass_allowed = security::is_dev_mode_bypass_allowed(&req, &config);
    let (file_exists, has_access) = check_file_access(
        &cache,
        &canonical_alias,
        user_roles,
        dev_mode_bypass_allowed,
    );

    if !file_exists {
        return error::serve_404(
            &request_tools.error_renderer,
            Some(request_tools.templates.as_ref()),
        );
    }

    if !has_access {
        if let Some(object) = cache.get_by_alias(&canonical_alias)
            && object.is_markdown
        {
            return markdown::handle_access_denied(&canonical_alias, &ctx);
        }

        return error::serve_404(
            &request_tools.error_renderer,
            Some(request_tools.templates.as_ref()),
        );
    }

    let object = match cache.get_by_alias(&canonical_alias) {
        Some(object) => object,
        None => {
            return error::serve_404(
                &request_tools.error_renderer,
                Some(request_tools.templates.as_ref()),
            );
        }
    };

    if object.is_markdown {
        return markdown::serve_markdown_alias(&canonical_alias, &ctx).await;
    }

    serve_object_blob(&object, &ctx).await
}

fn canonicalize_route_path(raw_path: &str) -> Option<String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.trim_start_matches('/').to_ascii_lowercase();
    if let Some(id_hex) = normalized.strip_prefix("id/") {
        if id_hex.contains('/') {
            return None;
        }
        let id = parse_content_id_hex(id_hex).ok()?;
        return Some(format!("id/{}", content_id_hex(id)));
    }
    canonicalize_alias(trimmed).ok()
}

async fn serve_object_blob(
    object: &nop_rt_page_cache::CachedObject,
    ctx: &PublicRequestContext<'_>,
) -> Result<HttpResponse> {
    use tokio::fs;

    let content_dir = ctx.runtime_paths.content_dir.to_string_lossy();
    let file_path = blob_path(
        &ctx.runtime_paths.content_dir,
        object.key.id,
        object.key.version,
    );

    let canonical_file_path = match security::canonical_path_checks(
        &file_path,
        content_dir.as_ref(),
        Some(&ctx.config.app.name),
    ) {
        Ok(path) => path,
        Err(error_response) => return error_response,
    };

    if ctx.config.streaming.enabled {
        return serve_streaming_file(
            &canonical_file_path,
            &object.mime,
            ctx.req,
            ctx.config,
            &ctx.request_tools.error_renderer,
            ctx.request_tools.templates.as_ref(),
        )
        .await;
    }

    let content = match fs::read(&canonical_file_path).await {
        Ok(content) => content,
        Err(_) => {
            return error::serve_404(
                &ctx.request_tools.error_renderer,
                Some(ctx.request_tools.templates.as_ref()),
            );
        }
    };

    Ok(HttpResponse::Ok()
        .content_type(object.mime.as_str())
        .insert_header(("Cache-Control", CACHE_CONTROL_IMMUTABLE))
        .body(content))
}

async fn serve_streaming_file(
    file_path: &std::path::Path,
    mime_type: &str,
    req: &HttpRequest,
    _config: &ValidatedConfig,
    error_renderer: &error::ErrorRenderer,
    template_engine: &dyn nop_rt_templates::TemplateEngine,
) -> Result<HttpResponse> {
    let file_size = match tokio::fs::metadata(file_path).await {
        Ok(metadata) => metadata.len(),
        Err(_) => return error::serve_404(error_renderer, Some(template_engine)),
    };

    if let Some(range_value) = req.headers().get("range")
        && let Ok(range_str) = range_value.to_str()
        && let Some(ranges) = parse_range_header(range_str)
        && ranges.len() == 1
    {
        match calculate_range_bounds(&ranges[0], file_size) {
            Some((start, end)) => {
                return serve_partial_content(
                    file_path,
                    start,
                    end,
                    file_size,
                    mime_type,
                    error_renderer,
                    template_engine,
                )
                .await;
            }
            None => {
                debug!(
                    "Unsatisfiable range request for {}: range {:?}, file size {}",
                    file_path.display(),
                    ranges[0],
                    file_size
                );
                return Ok(HttpResponse::build(http::StatusCode::RANGE_NOT_SATISFIABLE)
                    .insert_header(("Content-Range", format!("bytes */{}", file_size)))
                    .finish());
            }
        }
    }

    serve_entire_file_with_ranges(
        file_path,
        file_size,
        mime_type,
        error_renderer,
        template_engine,
    )
    .await
}

async fn serve_partial_content(
    file_path: &std::path::Path,
    start: u64,
    end: u64,
    total_size: u64,
    mime_type: &str,
    error_renderer: &error::ErrorRenderer,
    template_engine: &dyn nop_rt_templates::TemplateEngine,
) -> Result<HttpResponse> {
    use std::io::SeekFrom;
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let range_size = end - start + 1;

    let mut file = match File::open(file_path).await {
        Ok(f) => f,
        Err(_) => return error::serve_404(error_renderer, Some(template_engine)),
    };

    if file.seek(SeekFrom::Start(start)).await.is_err() {
        return error::serve_500(error_renderer, Some(template_engine));
    }

    let stream = ReaderStream::new(file.take(range_size));
    let body = SizedStream::new(range_size, stream);

    Ok(HttpResponse::PartialContent()
        .content_type(mime_type)
        .insert_header(("Accept-Ranges", "bytes"))
        .insert_header((
            "Content-Range",
            format_content_range_header(start, end, total_size),
        ))
        .insert_header(("Content-Length", range_size.to_string()))
        .insert_header(("Cache-Control", CACHE_CONTROL_IMMUTABLE))
        .body(body))
}

async fn serve_entire_file_with_ranges(
    file_path: &std::path::Path,
    file_size: u64,
    mime_type: &str,
    error_renderer: &error::ErrorRenderer,
    template_engine: &dyn nop_rt_templates::TemplateEngine,
) -> Result<HttpResponse> {
    use tokio::fs::File;

    let file = match File::open(file_path).await {
        Ok(file) => file,
        Err(_) => return error::serve_404(error_renderer, Some(template_engine)),
    };

    let stream = ReaderStream::new(file);
    let body = SizedStream::new(file_size, stream);

    Ok(HttpResponse::Ok()
        .content_type(mime_type)
        .insert_header(("Accept-Ranges", "bytes"))
        .insert_header(("Content-Length", file_size.to_string()))
        .insert_header(("Cache-Control", CACHE_CONTROL_IMMUTABLE))
        .body(body))
}

#[cfg(test)]
pub(super) mod test_support {
    use super::ValidatedConfig;
    use crate::test_support::TestConfigBuilder;

    pub(super) fn build_test_config(streaming_enabled: bool) -> ValidatedConfig {
        let mut config = TestConfigBuilder::new()
            .with_streaming(streaming_enabled)
            .build();
        config.server.port = 8080;
        if let Some(server) = config.servers.first_mut() {
            server.port = 8080;
        }
        config.security.max_violations = 10;
        config.security.cooldown_seconds = 60;
        config.upload.allowed_extensions = vec!["md".to_string(), "txt".to_string()];
        config
    }
}

#[cfg(test)]
mod tests;
