// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::{HttpRequest, HttpResponse, Result, web};
use nop_config::ValidatedConfig;

/// Configure OIDC authentication routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(oidc_auth))
        .route("/callback", web::get().to(oidc_callback));
}

/// Display OIDC authentication page (not implemented)
pub async fn oidc_auth(_config: web::Data<ValidatedConfig>) -> Result<HttpResponse> {
    Ok(HttpResponse::NotFound().finish())
}

/// Handle OIDC callback (not implemented)
pub async fn oidc_callback(
    _req: HttpRequest,
    _config: web::Data<ValidatedConfig>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotFound().finish())
}
