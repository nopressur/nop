// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::admin::shared;
use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PageEditPath {
    pub id: String,
}

pub async fn pages_edit(
    req: HttpRequest,
    path: web::Path<PageEditPath>,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    if path.id.trim().is_empty() {
        return Ok(HttpResponse::BadRequest()
            .content_type("text/html; charset=utf-8")
            .body("Missing content ID"));
    }

    shared::render_admin_spa_shell_response(&req, config.as_ref(), app_state.as_ref(), None).await
}

pub async fn pages_new(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    shared::render_admin_spa_shell_response(&req, config.as_ref(), app_state.as_ref(), None).await
}
