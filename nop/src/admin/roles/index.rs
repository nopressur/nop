// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::admin::shared;
use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use actix_web::{HttpRequest, HttpResponse, Result, web};

pub async fn roles_index(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    log::info!("Admin roles index requested");
    shared::render_admin_spa_shell_response(&req, config.as_ref(), app_state.as_ref(), None).await
}
