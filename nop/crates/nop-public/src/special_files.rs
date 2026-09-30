// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::PublicRequestContext;
use crate::handlers::serve_object_blob;
use actix_web::{HttpResponse, Result};

#[derive(Debug, Clone, Copy)]
struct SpecialFallbackFile {
    alias: &'static str,
    builtin_filename: &'static str,
    uploaded_object_policy: UploadedObjectPolicy,
}

#[derive(Debug, Clone, Copy)]
enum UploadedObjectPolicy {
    NonMarkdownMimePrefix(&'static str),
}

const SPECIAL_FALLBACK_FILES: &[SpecialFallbackFile] = &[SpecialFallbackFile {
    alias: "favicon.ico",
    builtin_filename: "favicon.ico",
    uploaded_object_policy: UploadedObjectPolicy::NonMarkdownMimePrefix("image/"),
}];

pub(crate) async fn maybe_serve_special_fallback_file(
    canonical_alias: &str,
    ctx: &PublicRequestContext<'_>,
) -> Option<Result<HttpResponse>> {
    let special = SPECIAL_FALLBACK_FILES
        .iter()
        .find(|entry| entry.alias == canonical_alias)?;
    Some(serve_special_fallback_file(special, ctx).await)
}

async fn serve_special_fallback_file(
    special: &SpecialFallbackFile,
    ctx: &PublicRequestContext<'_>,
) -> Result<HttpResponse> {
    if let Some(object) = ctx.cache.get_by_alias(special.alias)
        && ctx.cache.user_has_access(special.alias, None) == Some(true)
        && uploaded_object_allowed(&object, special.uploaded_object_policy)
    {
        return serve_object_blob(&object, ctx).await;
    }

    nop_rt_builtin::serve_builtin_asset(special.builtin_filename, ctx.req).await
}

fn uploaded_object_allowed(
    object: &nop_rt_page_cache::CachedObject,
    policy: UploadedObjectPolicy,
) -> bool {
    match policy {
        UploadedObjectPolicy::NonMarkdownMimePrefix(prefix) => {
            !object.is_markdown && object.mime.starts_with(prefix)
        }
    }
}
