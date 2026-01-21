// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::iam::validate_hex_field;
use crate::login::sessions::LoginSessionError;
use crate::login::types::LoginErrorResponse;
use crate::management::{ResponsePayload, WorkflowCounter};
use crate::security::{self, AuthAction};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use std::net::IpAddr;

const LOGIN_SESSION_PREFIX: &str = "lsn_";
const MAX_LOGIN_SESSION_CHARS: usize = 128;

pub(super) fn require_client_ip(
    req: &HttpRequest,
    config: &ValidatedConfig,
    context: &str,
) -> Result<IpAddr, HttpResponse> {
    match security::extract_client_ip(req, config) {
        Some(ip) => Ok(ip),
        None => {
            log::warn!("{} rejected: client IP unavailable", context);
            Err(login_error_response(
                "invalid_request",
                "Invalid request.",
                StatusCode::BAD_REQUEST,
            ))
        }
    }
}

pub(super) async fn check_auth_action_rate_limit(
    app_state: &AppState,
    action: AuthAction,
    ip: IpAddr,
    user_key: Option<String>,
    config: &ValidatedConfig,
    context: &str,
) -> Result<(), HttpResponse> {
    if let Err(err) = app_state
        .auth_action_limiter
        .check(action, ip, user_key, &config.security.login_sessions)
        .await
    {
        log::warn!("{} rate limited for IP {}", context, ip);
        return Err(login_error_response(
            err.code(),
            err.message(),
            StatusCode::TOO_MANY_REQUESTS,
        ));
    }
    Ok(())
}

pub(super) fn default_return_path(is_admin: bool, config: &ValidatedConfig) -> String {
    if is_admin {
        config.admin.path.clone()
    } else {
        "/".to_string()
    }
}

pub(super) fn initial_workflow_id() -> Result<u32, String> {
    WorkflowCounter::new()
        .next_id()
        .map_err(|err| err.to_string())
}

pub(super) fn login_error_response(code: &str, message: &str, status: StatusCode) -> HttpResponse {
    HttpResponse::build(status).json(LoginErrorResponse {
        code: code.to_string(),
        message: message.to_string(),
    })
}

pub(super) fn login_session_error_response(error: LoginSessionError) -> HttpResponse {
    let status = match error {
        LoginSessionError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        LoginSessionError::InvalidSession => StatusCode::UNAUTHORIZED,
    };
    login_error_response(error.code(), error.message(), status)
}

pub(super) fn validate_login_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty() {
        return Err("login_session_id is required".to_string());
    }
    if !session_id.starts_with(LOGIN_SESSION_PREFIX) {
        return Err("login_session_id is invalid".to_string());
    }
    if session_id.chars().count() > MAX_LOGIN_SESSION_CHARS {
        return Err("login_session_id is too long".to_string());
    }
    Ok(())
}

pub(super) fn validate_email_field(email: &str) -> Result<(), String> {
    security::validate_email_field(email)
}

pub(super) fn validate_front_end_hash(hash: &str, config: &ValidatedConfig) -> Result<(), String> {
    let expected_len = config
        .users
        .local()
        .map(|local| local.password.front_end.output_len as usize * 2)
        .unwrap_or(64);
    validate_hex_field("front_end_hash", hash, expected_len).map_err(|err| err.to_string())
}

pub(super) fn validate_front_end_salt(salt: &str, config: &ValidatedConfig) -> Result<(), String> {
    let expected_len = config
        .users
        .local()
        .map(|local| local.password.front_end.salt_len as usize * 2)
        .unwrap_or(32);
    validate_hex_field("front_end_salt", salt, expected_len).map_err(|err| err.to_string())
}

pub(super) fn sanitize_return_path(return_path: Option<&str>) -> Option<String> {
    return_path.and_then(|value| {
        let cleaned = value.trim().replace(['\r', '\n'], "");
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    })
}

pub(super) fn decode_message_response(payload: ResponsePayload) -> Option<String> {
    match payload {
        ResponsePayload::Message(message) => Some(message.message),
        _ => None,
    }
}
