// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::headers::{CacheDirective, set_cache_directive};
use crate::util::ReleaseTracker;
use actix_web::http::header::{ETAG, HeaderName, HeaderValue, IF_NONE_MATCH, VARY};
use actix_web::{HttpRequest, HttpResponse};
use log::warn;

pub struct HtmlCacheEnvelope<'a> {
    pub release_tracker: &'a ReleaseTracker,
    pub content_hash: Option<String>,
    pub contains_dynamic_content: bool,
    pub content_type: &'static str,
}

/// Builds an Actix response with the correct caching headers for HTML content.
pub fn finalize_html_response(
    req: &HttpRequest,
    envelope: HtmlCacheEnvelope<'_>,
    body: String,
) -> HttpResponse {
    if envelope.contains_dynamic_content || envelope.content_hash.is_none() {
        set_cache_directive(req, CacheDirective::NoStore);
        return HttpResponse::Ok()
            .content_type(envelope.content_type)
            .body(body);
    }

    set_cache_directive(req, CacheDirective::StaticHtml);

    let release_hex = envelope.release_tracker.current_hex();
    let hash = match envelope.content_hash.as_ref() {
        Some(hash) => hash,
        None => {
            warn!("Missing content hash for HTML response; falling back to no-store");
            set_cache_directive(req, CacheDirective::NoStore);
            return HttpResponse::Ok()
                .content_type(envelope.content_type)
                .body(body);
        }
    };
    let prefix = hash.chars().take(8).collect::<String>();
    let etag_value = format!("\"{}{}\"", prefix, release_hex);
    let x_release = HeaderName::from_static("x-release");
    let release_value = HeaderValue::from_str(&release_hex)
        .unwrap_or_else(|_| HeaderValue::from_static("invalid-release"));
    let etag_header = HeaderValue::from_str(&etag_value)
        .unwrap_or_else(|_| HeaderValue::from_static("\"invalid-etag\""));

    if let Some(candidate) = req.headers().get(IF_NONE_MATCH)
        && let Ok(tag_str) = candidate.to_str()
        && tag_str
            .split(',')
            .any(|candidate_tag| candidate_tag.trim() == etag_value)
    {
        return HttpResponse::NotModified()
            .insert_header((VARY, HeaderValue::from_static("Accept-Encoding")))
            .insert_header((ETAG, etag_header.clone()))
            .insert_header((x_release.clone(), release_value.clone()))
            .finish();
    }

    HttpResponse::Ok()
        .content_type(envelope.content_type)
        .insert_header((VARY, HeaderValue::from_static("Accept-Encoding")))
        .insert_header((ETAG, etag_header))
        .insert_header((x_release, release_value))
        .body(body)
}
