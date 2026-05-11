// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

//! Image-source resolution shared by markdown image links and shortcode handlers.
//!
//! `resolve` consolidates the path-traversal check, `/img` reservation,
//! relative-path normalisation, alias lookup, MIME validation, and per-asset
//! versioning. The resolver is `pub(crate)`; external callers (shortcode
//! handlers) reach it through `ShortcodeContext::resolve_image_source` so they
//! never see the cache or the markdown path being rendered.

use nop_rt_page_cache::PageMetaCache;
use nop_rt_security as security;

/// The form an image source takes after resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedImage {
    /// `http://` or `https://` URL passed through unchanged. Caller is
    /// responsible for HTML-attribute-escaping it before insertion.
    External(String),
    /// Versioned local URL with the per-asset `?v=<version>` cache-busting
    /// suffix appended (and any pre-existing query/fragment preserved).
    /// Caller is responsible for HTML-attribute-escaping it before insertion.
    Local(String),
}

/// Why a candidate image source could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSourceError {
    /// Empty string after trimming.
    Empty,
    /// Path-traversal patterns or other patterns rejected by the security helper.
    PathTraversal,
    /// Path begins with the reserved `/img` prefix.
    ReservedImgPath,
    /// Relative path resolved but the alias was not found in the page-meta cache.
    AliasNotFound,
    /// Alias was found but the resolved object's MIME does not start with `image/`.
    NotImage,
}

/// Resolve a candidate image source URL. The contract:
///
/// - `http(s)://` URLs come back as `Ok(ResolvedImage::External(url))`.
/// - Local relative paths come back as `Ok(ResolvedImage::Local(versioned))`.
/// - Anything else (empty, path traversal, `/img`, missing alias, non-image MIME)
///   returns the corresponding `ImageSourceError`.
pub(crate) fn resolve(
    url: &str,
    current_md_path: &str,
    cache: &PageMetaCache,
) -> Result<ResolvedImage, ImageSourceError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(ImageSourceError::Empty);
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(ResolvedImage::External(trimmed.to_string()));
    }

    if security::route_checks_legacy(trimmed).is_some() {
        return Err(ImageSourceError::PathTraversal);
    }

    if trimmed.starts_with("/img") {
        return Err(ImageSourceError::ReservedImgPath);
    }

    let (path_without_fragment, fragment) = split_fragment(trimmed);
    let (path_part, existing_query) = split_query(path_without_fragment);
    if path_part.is_empty() {
        return Err(ImageSourceError::Empty);
    }

    let normalized = security::normalize_relative_path(current_md_path, path_part)
        .ok_or(ImageSourceError::PathTraversal)?;

    let object = cache
        .get_by_alias(&normalized)
        .ok_or(ImageSourceError::AliasNotFound)?;

    if !object.mime.starts_with("image/") {
        return Err(ImageSourceError::NotImage);
    }

    let version = object.key.version.0.to_string();

    let mut query_parts: Vec<String> = Vec::new();
    if let Some(existing_query) = existing_query {
        query_parts.extend(
            existing_query
                .split('&')
                .filter(|s| !s.is_empty())
                .map(String::from),
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

    Ok(ResolvedImage::Local(new_url))
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
