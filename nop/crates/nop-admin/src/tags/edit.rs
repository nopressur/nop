// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::shared;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use nop_config::ValidatedConfig;
use nop_rt_templates::RequestTools;
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct TagEditQuery {
    id: String,
}

pub async fn tags_new(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    request_tools: web::Data<RequestTools>,
) -> Result<HttpResponse> {
    shared::render_admin_spa_shell_response(&req, config.as_ref(), request_tools.as_ref(), None)
        .await
}

pub async fn tags_edit(
    req: HttpRequest,
    query: web::Query<TagEditQuery>,
    config: web::Data<ValidatedConfig>,
    request_tools: web::Data<RequestTools>,
) -> Result<HttpResponse> {
    let tag_id = query.id.trim();
    if tag_id.is_empty() {
        return Ok(HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body("Missing tag id"));
    }

    shared::render_admin_spa_shell_response(&req, config.as_ref(), request_tools.as_ref(), None)
        .await
}
