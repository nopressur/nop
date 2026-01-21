// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::admin::shared;
use crate::app_state::AppState;
use crate::config::{ValidatedConfig, ValidatedUsersConfig};
use actix_web::{HttpRequest, HttpResponse, Result, web};

pub async fn users_new(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // Check if OIDC is configured - if so, redirect to admin root
    if matches!(config.users, ValidatedUsersConfig::Oidc(_)) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", config.admin.path.as_str()))
            .finish());
    }

    shared::render_admin_spa_shell_response(&req, config.as_ref(), app_state.as_ref(), None).await
}

pub async fn users_edit(
    req: HttpRequest,
    path: web::Path<String>,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // Check if OIDC is configured - if so, redirect to admin root
    if matches!(config.users, ValidatedUsersConfig::Oidc(_)) {
        return Ok(HttpResponse::Found()
            .append_header(("Location", config.admin.path.as_str()))
            .finish());
    }

    let _email = urlencoding::decode(&path.into_inner())
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid email format"))?
        .into_owned();

    shared::render_admin_spa_shell_response(&req, config.as_ref(), app_state.as_ref(), None).await
}
