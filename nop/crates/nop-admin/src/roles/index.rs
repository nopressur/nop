// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::shared;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use nop_config::ValidatedConfig;
use nop_rt_templates::RequestTools;

pub async fn roles_index(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    request_tools: web::Data<RequestTools>,
) -> Result<HttpResponse> {
    log::info!("Admin roles index requested");
    shared::render_admin_spa_shell_response(&req, config.as_ref(), request_tools.as_ref(), None)
        .await
}
