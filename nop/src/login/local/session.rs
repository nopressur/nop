// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::iam::AuthRequest;
use crate::login::types::{LoginBootstrapRequest, LoginBootstrapResponse};
use crate::public::page_meta_cache::PageMetaCache;
use crate::security::{self, AuthAction};
use crate::util::{CsrfTokenOutcome, CsrfTokenStore, issue_csrf_token};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use serde_json::json;

use super::helpers::{
    check_auth_action_rate_limit, login_error_response, login_session_error_response,
    require_client_ip,
};

pub(super) async fn login_csrf_token(
    req: HttpRequest,
    csrf_store: web::Data<CsrfTokenStore>,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let ip = match require_client_ip(&req, &config, "Login CSRF token") {
        Ok(ip) => ip,
        Err(response) => return Ok(response),
    };
    let user_key = req.jwt_id();
    if let Err(response) = check_auth_action_rate_limit(
        app_state.as_ref(),
        AuthAction::LoginCsrfToken,
        ip,
        user_key,
        config.as_ref(),
        "Login CSRF token",
    )
    .await
    {
        return Ok(response);
    }

    match issue_csrf_token(&req, csrf_store.as_ref(), config.as_ref()) {
        CsrfTokenOutcome::Authorized { token, .. } | CsrfTokenOutcome::DevMode { token, .. } => {
            Ok(HttpResponse::Ok().json(json!({
                "csrf_token": token,
                "expires_in_seconds": csrf_store.expiry_seconds(),
            })))
        }
        CsrfTokenOutcome::Unauthorized => Ok(login_error_response(
            "unauthorized",
            "Authentication required.",
            StatusCode::UNAUTHORIZED,
        )),
    }
}

pub(super) async fn login_bootstrap(
    req: HttpRequest,
    payload: web::Json<LoginBootstrapRequest>,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
    page_cache: web::Data<PageMetaCache>,
) -> Result<HttpResponse> {
    if let Some(blocked_response) = security::is_ip_blocked(
        &app_state.threat_tracker,
        &req,
        &config,
        &app_state.error_renderer,
        Some(app_state.templates.as_ref()),
    )
    .await
    {
        return blocked_response;
    }

    let ip = match require_client_ip(&req, &config, "Login bootstrap") {
        Ok(ip) => ip,
        Err(response) => return Ok(response),
    };

    let return_path = payload.return_path.as_deref().and_then(|path| {
        security::validate_login_return_path(path, page_cache.as_ref(), &config, true)
    });

    let session = match app_state
        .login_sessions
        .issue(ip, return_path.clone(), &config.security.login_sessions)
        .await
    {
        Ok(session) => session,
        Err(err) => return Ok(login_session_error_response(err)),
    };

    Ok(HttpResponse::Ok().json(LoginBootstrapResponse {
        login_session_id: session.login_session_id,
        expires_in_seconds: session.expires_in_seconds,
        return_path: session.return_path,
    }))
}

/// Handle logout
pub(super) async fn handle_logout(
    req: HttpRequest,
    user_services: web::Data<crate::iam::UserServices>,
    csrf_store: web::Data<CsrfTokenStore>,
) -> Result<HttpResponse> {
    if let Some(jwt_id) = req.jwt_id() {
        csrf_store.cleanup_tokens_for_jwt_id(&jwt_id);
    }

    if let Some(jwt_service) = &user_services.get_ref().jwt_service() {
        let cookie = jwt_service.create_logout_cookie();
        Ok(HttpResponse::Ok().cookie(cookie).json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully",
            "redirect_url": "/login"
        })))
    } else {
        Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "message": "Logout failed: Authentication service not available"
        })))
    }
}
