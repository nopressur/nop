// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::types::{
    PasswordSaltPayload, ProfilePasswordChangeRequest, ProfilePasswordSaltResponse,
    ProfileUpdateRequest, StatusResponse,
};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use nop_config::ValidatedConfig;
use nop_iam_passwords::{PasswordProviderBlock, derive_back_end_hash, generate_salt_hex};
use nop_rt_iam::{AuthRequest, UserServices};
use nop_rt_security::AuthAction;
use nop_rt_security::SecurityTools;
use std::time::Duration;

use super::helpers::{
    check_auth_action_rate_limit, login_error_response, require_client_ip, validate_front_end_hash,
    validate_front_end_salt,
};

pub(super) async fn profile_update(
    req: HttpRequest,
    payload: web::Json<ProfileUpdateRequest>,
    user_services: web::Data<UserServices>,
) -> Result<HttpResponse> {
    let user = match req.user_info() {
        Some(user) => user,
        None => {
            return Ok(login_error_response(
                "unauthorized",
                "Authentication required.",
                StatusCode::UNAUTHORIZED,
            ));
        }
    };

    let sanitized_name = match nop_library::validate_and_sanitize_user_name(&payload.name) {
        Ok(name) => name,
        Err(err) => {
            log::warn!("Profile update rejected: {}", err);
            return Ok(login_error_response(
                "invalid_request",
                "Invalid profile data.",
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    if let Err(err) = user_services
        .update_user_complete(&user.email, Some(&sanitized_name), None, None)
        .await
    {
        log::error!("Profile update failed: {}", err);
        return Ok(login_error_response(
            "profile_update_failed",
            "Profile update failed.",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let mut updated = user.clone();
    updated.name = sanitized_name;
    let jwt_service = match user_services.jwt_service() {
        Some(service) => service,
        None => {
            log::error!("JWT service unavailable during profile update");
            return Ok(login_error_response(
                "profile_update_failed",
                "Profile update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let token = match jwt_service.create_token(&updated.email, &updated) {
        Ok(token) => token,
        Err(err) => {
            log::error!("Failed to refresh session token: {}", err);
            return Ok(login_error_response(
                "profile_update_failed",
                "Profile update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let cookie = jwt_service.create_auth_cookie(&token);

    Ok(HttpResponse::Ok().cookie(cookie).json(StatusResponse {
        success: true,
        message: "Profile updated successfully".to_string(),
    }))
}

pub(super) async fn profile_password_salt(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    security_tools: web::Data<SecurityTools>,
    user_services: web::Data<UserServices>,
) -> Result<HttpResponse> {
    let user = match req.user_info() {
        Some(user) => user,
        None => {
            return Ok(login_error_response(
                "unauthorized",
                "Authentication required.",
                StatusCode::UNAUTHORIZED,
            ));
        }
    };

    let ip = match require_client_ip(&req, &config, "Profile password salt") {
        Ok(ip) => ip,
        Err(response) => return Ok(response),
    };
    if let Err(response) = check_auth_action_rate_limit(
        security_tools.as_ref(),
        AuthAction::ProfilePasswordSalt,
        ip,
        Some(user.email.clone()),
        config.as_ref(),
        "Profile password salt",
    )
    .await
    {
        return Ok(response);
    }

    let salt_payload = match user_services
        .issue_password_change_salt(&user.email, Duration::from_secs(300))
        .await
    {
        Ok(payload) => payload,
        Err(err) => {
            log::error!("Password salt request failed: {}", err);
            return Ok(login_error_response(
                "password_salt_failed",
                "Unable to fetch password salts.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    Ok(HttpResponse::Ok().json(ProfilePasswordSaltResponse {
        change_token: salt_payload.change_token,
        current: PasswordSaltPayload {
            front_end_salt: salt_payload.current_front_end_salt,
        },
        next: PasswordSaltPayload {
            front_end_salt: salt_payload.next_front_end_salt,
        },
        expires_in_seconds: salt_payload.expires_in_seconds,
    }))
}

pub(super) async fn profile_password_change(
    req: HttpRequest,
    payload: web::Json<ProfilePasswordChangeRequest>,
    config: web::Data<ValidatedConfig>,
    security_tools: web::Data<SecurityTools>,
    user_services: web::Data<UserServices>,
) -> Result<HttpResponse> {
    let user = match req.user_info() {
        Some(user) => user,
        None => {
            return Ok(login_error_response(
                "unauthorized",
                "Authentication required.",
                StatusCode::UNAUTHORIZED,
            ));
        }
    };

    let ip = match require_client_ip(&req, &config, "Profile password change") {
        Ok(ip) => ip,
        Err(response) => return Ok(response),
    };
    if let Err(response) = check_auth_action_rate_limit(
        security_tools.as_ref(),
        AuthAction::ProfilePasswordChange,
        ip,
        Some(user.email.clone()),
        config.as_ref(),
        "Profile password change",
    )
    .await
    {
        return Ok(response);
    }

    if let Err(err) = validate_front_end_hash(&payload.current_front_end_hash, &config) {
        log::warn!("Profile password change rejected: {}", err);
        return Ok(login_error_response(
            "invalid_request",
            "Invalid password data.",
            StatusCode::BAD_REQUEST,
        ));
    }
    if let Err(err) = validate_front_end_hash(&payload.new_front_end_hash, &config) {
        log::warn!("Profile password change rejected: {}", err);
        return Ok(login_error_response(
            "invalid_request",
            "Invalid password data.",
            StatusCode::BAD_REQUEST,
        ));
    }
    if let Err(err) = validate_front_end_salt(&payload.new_front_end_salt, &config) {
        log::warn!("Profile password change rejected: {}", err);
        return Ok(login_error_response(
            "invalid_request",
            "Invalid password data.",
            StatusCode::BAD_REQUEST,
        ));
    }

    if let Err(err) = user_services
        .validate_password_change_token(
            &user.email,
            &payload.change_token,
            &payload.new_front_end_salt,
        )
        .await
    {
        log::warn!("Profile password update rejected: {}", err);
        return Ok(login_error_response(
            "password_update_failed",
            &err.to_string(),
            StatusCode::BAD_REQUEST,
        ));
    }

    let user_services_for_validate = user_services.clone();
    let current_email = user.email.clone();
    let current_front_end_hash = payload.current_front_end_hash.clone();
    let valid = match web::block(move || {
        user_services_for_validate
            .password_validate(&current_email, &current_front_end_hash)
            .map_err(|err| err.to_string())
    })
    .await
    {
        Ok(Ok(valid)) => valid,
        Ok(Err(err)) => {
            log::error!("Profile password update validation failed: {}", err);
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
        Err(err) => {
            log::error!("Profile password update validation failed: {}", err);
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    if !valid {
        return Ok(login_error_response(
            "password_update_failed",
            "Current password is invalid",
            StatusCode::BAD_REQUEST,
        ));
    }

    let params = user_services.password_params().clone();
    let new_front_end_hash = payload.new_front_end_hash.clone();
    let new_front_end_salt = payload.new_front_end_salt.clone();
    let password_block = match web::block(move || {
        let back_end_salt =
            generate_salt_hex(params.back_end.salt_len).map_err(|err| err.to_string())?;
        let stored_hash =
            derive_back_end_hash(&new_front_end_hash, &back_end_salt, &params.back_end)
                .map_err(|err| err.to_string())?;
        Ok::<PasswordProviderBlock, String>(PasswordProviderBlock {
            front_end_salt: new_front_end_salt,
            back_end_salt,
            stored_hash,
        })
    })
    .await
    {
        Ok(Ok(block)) => block,
        Ok(Err(err)) => {
            log::error!("Profile password update hash derivation failed: {}", err);
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
        Err(err) => {
            log::error!("Profile password update hash derivation failed: {}", err);
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    if let Err(err) = user_services
        .update_user_complete(&user.email, None, Some(password_block), None)
        .await
    {
        log::error!("Profile password update failed: {}", err);
        return Ok(login_error_response(
            "password_update_failed",
            "Password update failed.",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }
    if let Err(err) = user_services
        .invalidate_password_change_token(&payload.change_token)
        .await
    {
        log::warn!("Password change token invalidate failed: {}", err);
    };

    let mut updated = user.clone();
    updated.password_version = updated.password_version.saturating_add(1);
    let jwt_service = match user_services.jwt_service() {
        Some(service) => service,
        None => {
            log::error!("JWT service unavailable during password update");
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let token = match jwt_service.create_token(&updated.email, &updated) {
        Ok(token) => token,
        Err(err) => {
            log::error!("Failed to refresh session token: {}", err);
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let cookie = jwt_service.create_auth_cookie(&token);

    Ok(HttpResponse::Ok().cookie(cookie).json(StatusResponse {
        success: true,
        message: "Password updated successfully".to_string(),
    }))
}
