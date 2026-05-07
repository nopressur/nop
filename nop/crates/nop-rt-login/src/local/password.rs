// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::LoginState;
use crate::sessions::LOGIN_SESSION_TTL_SECONDS;
use crate::types::{
    LoginSuccessResponse, PasswordEmailRequest, PasswordEmailResponse, PasswordLoginRequest,
};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use nop_config::ValidatedConfig;
use nop_rt_iam::UserServices;
use nop_rt_page_cache::PageMetaCache;
use nop_rt_security as security;
use nop_rt_security::SecurityTools;
use nop_rt_templates::RequestTools;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use super::helpers::{
    default_return_path, login_error_response, login_session_error_response, require_client_ip,
    validate_email_field, validate_front_end_hash, validate_login_session_id,
};

pub(super) async fn password_email(
    req: HttpRequest,
    payload: web::Json<PasswordEmailRequest>,
    config: web::Data<ValidatedConfig>,
    login_state: web::Data<LoginState>,
    request_tools: web::Data<RequestTools>,
    security_tools: web::Data<SecurityTools>,
    user_services: web::Data<UserServices>,
) -> Result<HttpResponse> {
    if let Some(blocked_response) = security::is_ip_blocked(
        &security_tools.threat_tracker,
        &req,
        &config,
        &request_tools.error_renderer,
        Some(request_tools.templates.as_ref()),
    )
    .await
    {
        return blocked_response;
    }

    if let Err(err) = validate_login_session_id(&payload.login_session_id) {
        log::warn!("Login email rejected: {}", err);
        return Ok(login_error_response(
            "login_session_expired",
            "Login session expired.",
            StatusCode::UNAUTHORIZED,
        ));
    }
    if let Err(err) = validate_email_field(&payload.email) {
        log::warn!("Login email rejected: {}", err);
        return Ok(login_error_response(
            "invalid_request",
            "Invalid request.",
            StatusCode::BAD_REQUEST,
        ));
    }

    let ip = match require_client_ip(&req, &config, "Login email") {
        Ok(ip) => ip,
        Err(response) => return Ok(response),
    };
    let _session = match login_state
        .login_sessions
        .use_session(
            ip,
            &payload.login_session_id,
            &config.security.login_sessions,
        )
        .await
    {
        Ok(session) => session,
        Err(err) => return Ok(login_session_error_response(err)),
    };

    let front_end_salt = fetch_front_end_salt(&payload.email, user_services.get_ref(), &config);

    Ok(HttpResponse::Ok().json(PasswordEmailResponse {
        front_end_salt,
        expires_in_seconds: LOGIN_SESSION_TTL_SECONDS,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn password_login(
    req: HttpRequest,
    payload: web::Json<PasswordLoginRequest>,
    config: web::Data<ValidatedConfig>,
    login_state: web::Data<LoginState>,
    request_tools: web::Data<RequestTools>,
    security_tools: web::Data<SecurityTools>,
    page_cache: web::Data<PageMetaCache>,
    user_services: web::Data<UserServices>,
) -> Result<HttpResponse> {
    if let Some(blocked_response) = security::is_ip_blocked(
        &security_tools.threat_tracker,
        &req,
        &config,
        &request_tools.error_renderer,
        Some(request_tools.templates.as_ref()),
    )
    .await
    {
        return blocked_response;
    }

    if let Err(err) = validate_login_session_id(&payload.login_session_id) {
        log::warn!("Login rejected: {}", err);
        return Ok(login_error_response(
            "login_session_expired",
            "Login session expired.",
            StatusCode::UNAUTHORIZED,
        ));
    }
    if let Err(err) = validate_email_field(&payload.email) {
        log::warn!("Login rejected: {}", err);
        return Ok(login_error_response(
            "invalid_credentials",
            "Invalid email or password.",
            StatusCode::UNAUTHORIZED,
        ));
    }
    if let Err(err) = validate_front_end_hash(&payload.front_end_hash, &config) {
        log::warn!("Login rejected: {}", err);
        return Ok(login_error_response(
            "invalid_credentials",
            "Invalid email or password.",
            StatusCode::UNAUTHORIZED,
        ));
    }

    let ip = match require_client_ip(&req, &config, "Login") {
        Ok(ip) => ip,
        Err(response) => return Ok(response),
    };
    let session = match login_state
        .login_sessions
        .use_session(
            ip,
            &payload.login_session_id,
            &config.security.login_sessions,
        )
        .await
    {
        Ok(session) => session,
        Err(err) => return Ok(login_session_error_response(err)),
    };

    let user_services_for_validate = user_services.clone();
    let email = payload.email.clone();
    let front_end_hash = payload.front_end_hash.clone();
    let valid = match web::block(move || {
        user_services_for_validate
            .password_validate(&email, &front_end_hash)
            .map_err(|err| err.to_string())
    })
    .await
    {
        Ok(Ok(valid)) => valid,
        Ok(Err(err)) => {
            log::error!("Password validation failed: {}", err);
            false
        }
        Err(err) => {
            log::error!("Password validation failed: {}", err);
            false
        }
    };

    if !valid {
        security::record_login_failure(
            &security_tools.threat_tracker,
            &req,
            &config,
            "invalid_credentials",
        );
        return Ok(login_error_response(
            "invalid_credentials",
            "Invalid email or password.",
            StatusCode::UNAUTHORIZED,
        ));
    }

    let user = match user_services.get_user(&payload.email) {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(login_error_response(
                "invalid_credentials",
                "Invalid email or password.",
                StatusCode::UNAUTHORIZED,
            ));
        }
        Err(err) => {
            log::error!("Failed to load user for login: {}", err);
            return Ok(login_error_response(
                "invalid_credentials",
                "Invalid email or password.",
                StatusCode::UNAUTHORIZED,
            ));
        }
    };

    let jwt_service = match user_services.jwt_service() {
        Some(service) => service,
        None => {
            log::error!("JWT service unavailable during login");
            return Ok(login_error_response(
                "invalid_credentials",
                "Invalid email or password.",
                StatusCode::UNAUTHORIZED,
            ));
        }
    };
    let token = match jwt_service.create_token(&user.email, &user) {
        Ok(token) => token,
        Err(err) => {
            log::error!("Failed to create session token: {}", err);
            return Ok(login_error_response(
                "invalid_credentials",
                "Invalid email or password.",
                StatusCode::UNAUTHORIZED,
            ));
        }
    };
    let cookie = jwt_service.create_auth_cookie(&token);

    let is_admin = user.roles.iter().any(|role| role == "admin");
    let return_path = match session.return_path.as_deref() {
        Some(path) => {
            security::validate_login_return_path(path, page_cache.as_ref(), &config, is_admin)
                .unwrap_or_else(|| default_return_path(is_admin, config.as_ref()))
        }
        None => default_return_path(is_admin, config.as_ref()),
    };

    login_state
        .login_sessions
        .invalidate(&payload.login_session_id);

    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(LoginSuccessResponse { return_path }))
}

pub(super) fn fetch_front_end_salt(
    email: &str,
    user_services: &UserServices,
    config: &ValidatedConfig,
) -> String {
    match user_services.current_front_end_salt(email) {
        Ok(salt) => salt,
        Err(err) => {
            log::warn!("Password salt fallback: {}", err);
            fallback_front_end_salt(config)
        }
    }
}

fn fallback_front_end_salt(config: &ValidatedConfig) -> String {
    let salt_len = config
        .users
        .local()
        .map(|local| local.password.front_end.salt_len)
        .unwrap_or(16);
    match nop_iam_passwords::generate_salt_hex(salt_len) {
        Ok(salt) => salt,
        Err(err) => {
            log::error!("Failed to generate front-end salt: {}", err);
            let mut bytes = vec![0u8; salt_len as usize];
            fill_fallback_salt_bytes(&mut bytes);
            hex::encode(bytes)
        }
    }
}

fn fill_fallback_salt_bytes(bytes: &mut [u8]) {
    let mut offset = 0usize;
    let mut counter = 0u64;
    while offset < bytes.len() {
        let mut hasher = Sha256::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        hasher.update(now.to_le_bytes());
        hasher.update(counter.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        let digest = hasher.finalize();
        let available = std::cmp::min(bytes.len() - offset, digest.len());
        bytes[offset..offset + available].copy_from_slice(&digest[..available]);
        offset += available;
        counter = counter.wrapping_add(1);
    }
}
