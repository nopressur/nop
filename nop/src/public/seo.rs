// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::content::flat_storage::content_id_hex;
use crate::content::reserved_paths::ReservedPaths;
use crate::public::page_meta_cache::{PageMetaCache, ResolvedRoles};
use crate::security;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use chrono::{DateTime, Utc};
use std::fmt::Write;
use std::time::SystemTime;

pub async fn robots_txt(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    if let Some(error_response) = security::is_ip_blocked(
        &app_state.threat_tracker,
        &req,
        &config,
        &app_state.error_renderer,
        Some(app_state.templates.as_ref()),
    )
    .await
    {
        return error_response;
    }

    let reserved_paths = ReservedPaths::from_config(&config);
    let base_url = request_base_url(&req);

    let mut body = String::new();
    body.push_str("User-agent: *\n");
    for rule in reserved_paths.robots_disallow_rules() {
        let _ = writeln!(body, "Disallow: {}", rule);
    }
    body.push_str("Allow: /\n\n");
    let _ = writeln!(body, "Sitemap: {}/sitemap.xml", base_url);

    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(body))
}

pub async fn sitemap_xml(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    cache: web::Data<PageMetaCache>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    if let Some(error_response) = security::is_ip_blocked(
        &app_state.threat_tracker,
        &req,
        &config,
        &app_state.error_renderer,
        Some(app_state.templates.as_ref()),
    )
    .await
    {
        return error_response;
    }

    let reserved_paths = ReservedPaths::from_config(&config);
    let base_url = request_base_url(&req);

    let mut entries = Vec::new();
    for object in cache.list_objects() {
        if !object.is_markdown {
            continue;
        }
        if !matches!(object.resolved_roles, ResolvedRoles::Public) {
            continue;
        }

        let path = if object.alias.trim().is_empty() {
            format!("id/{}", content_id_hex(object.key.id))
        } else {
            if reserved_paths.alias_is_reserved(&object.alias) {
                continue;
            }
            object.alias
        };

        let loc = format!("{}/{}", base_url, path);
        entries.push(SitemapEntry {
            loc,
            last_modified: object.last_modified,
        });
    }

    entries.sort_by(|left, right| left.loc.cmp(&right.loc));

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");

    for entry in entries {
        let loc = escape_xml(&entry.loc);
        let lastmod = format_lastmod(entry.last_modified);
        xml.push_str("  <url>\n");
        let _ = writeln!(xml, "    <loc>{}</loc>", loc);
        let _ = writeln!(xml, "    <lastmod>{}</lastmod>", lastmod);
        xml.push_str("  </url>\n");
    }

    xml.push_str("</urlset>\n");

    Ok(HttpResponse::Ok()
        .content_type("application/xml; charset=utf-8")
        .body(xml))
}

struct SitemapEntry {
    loc: String,
    last_modified: SystemTime,
}

fn request_base_url(req: &HttpRequest) -> String {
    let info = req.connection_info();
    format!("{}://{}", info.scheme(), info.host())
}

fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn format_lastmod(timestamp: SystemTime) -> String {
    let datetime: DateTime<Utc> = timestamp.into();
    datetime.format("%Y-%m-%d").to_string()
}
