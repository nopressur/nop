// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::iam::{AuthRequest, UserServices};
use crate::login::types::{
    PasswordSaltPayload, ProfilePasswordChangeRequest, ProfilePasswordSaltResponse,
    ProfileUpdateRequest, StatusResponse,
};
use crate::management::{
    ManagementCommand, ResponsePayload, USER_ACTION_CHANGE_ERR, USER_ACTION_CHANGE_OK,
    USER_ACTION_PASSWORD_UPDATE_ERR, USER_ACTION_PASSWORD_UPDATE_OK, UserChangeRequest,
    UserCommand, UserPasswordSaltRequest, UserPasswordUpdateRequest,
};
use crate::security::{self, AuthAction};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Result, web};

use super::helpers::{
    check_auth_action_rate_limit, decode_message_response, initial_workflow_id,
    login_error_response, require_client_ip, validate_front_end_hash, validate_front_end_salt,
};

pub(super) async fn profile_update(
    req: HttpRequest,
    payload: web::Json<ProfileUpdateRequest>,
    app_state: web::Data<AppState>,
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

    let sanitized_name = match security::validate_and_sanitize_user_name(&payload.name) {
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

    let connection_id = crate::management::next_connection_id();
    let workflow_id = match initial_workflow_id() {
        Ok(workflow_id) => workflow_id,
        Err(err) => {
            log::error!("Profile update workflow id error: {}", err);
            return Ok(login_error_response(
                "profile_update_failed",
                "Profile update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let response = app_state
        .management_bus
        .send(
            connection_id,
            workflow_id,
            ManagementCommand::Users(UserCommand::Change(UserChangeRequest {
                email: user.email.clone(),
                name: Some(sanitized_name.clone()),
                roles: None,
            })),
        )
        .await;
    match response {
        Ok(response) => match response.action_id {
            USER_ACTION_CHANGE_OK => {}
            USER_ACTION_CHANGE_ERR => {
                log::warn!("Profile update rejected");
                return Ok(login_error_response(
                    "profile_update_failed",
                    "Profile update failed.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
            _ => {
                log::error!("Unexpected response payload for profile update");
                return Ok(login_error_response(
                    "profile_update_failed",
                    "Profile update failed.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        },
        Err(err) => {
            log::error!("Profile update failed: {}", err);
            return Ok(login_error_response(
                "profile_update_failed",
                "Profile update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
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
    app_state: web::Data<AppState>,
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
        app_state.as_ref(),
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

    let connection_id = crate::management::next_connection_id();
    let workflow_id = match initial_workflow_id() {
        Ok(workflow_id) => workflow_id,
        Err(err) => {
            log::error!("Profile password salt workflow id error: {}", err);
            return Ok(login_error_response(
                "password_salt_failed",
                "Unable to fetch password salts.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let response = app_state
        .management_bus
        .send(
            connection_id,
            workflow_id,
            ManagementCommand::Users(UserCommand::PasswordSalt(UserPasswordSaltRequest {
                email: user.email.clone(),
            })),
        )
        .await;

    let salt_payload = match response {
        Ok(response) => match response.payload {
            ResponsePayload::UserPasswordSalt(payload) => payload,
            ResponsePayload::Message(message) => {
                log::warn!("Profile password salt rejected: {}", message.message);
                return Ok(login_error_response(
                    "password_salt_failed",
                    "Unable to fetch password salts.",
                    StatusCode::BAD_REQUEST,
                ));
            }
            _ => {
                log::error!("Unexpected response payload for profile password salt");
                return Ok(login_error_response(
                    "password_salt_failed",
                    "Unable to fetch password salts.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        },
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
    app_state: web::Data<AppState>,
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
        app_state.as_ref(),
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

    let connection_id = crate::management::next_connection_id();
    let workflow_id = match initial_workflow_id() {
        Ok(workflow_id) => workflow_id,
        Err(err) => {
            log::error!("Profile password update workflow id error: {}", err);
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let response = app_state
        .management_bus
        .send(
            connection_id,
            workflow_id,
            ManagementCommand::Users(UserCommand::PasswordUpdate(UserPasswordUpdateRequest {
                email: user.email.clone(),
                current_front_end_hash: payload.current_front_end_hash.clone(),
                new_front_end_hash: payload.new_front_end_hash.clone(),
                new_front_end_salt: payload.new_front_end_salt.clone(),
                change_token: payload.change_token.clone(),
            })),
        )
        .await;

    let message = match response {
        Ok(response) => match response.action_id {
            USER_ACTION_PASSWORD_UPDATE_OK => decode_message_response(response.payload)
                .unwrap_or_else(|| "Password updated.".to_string()),
            USER_ACTION_PASSWORD_UPDATE_ERR => {
                let message = decode_message_response(response.payload)
                    .unwrap_or_else(|| "Password update failed.".to_string());
                log::warn!("Profile password update rejected: {}", message);
                return Ok(login_error_response(
                    "password_update_failed",
                    &message,
                    StatusCode::BAD_REQUEST,
                ));
            }
            _ => {
                log::error!("Unexpected response payload for password update");
                return Ok(login_error_response(
                    "password_update_failed",
                    "Password update failed.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        },
        Err(err) => {
            log::error!("Password update failed: {}", err);
            return Ok(login_error_response(
                "password_update_failed",
                "Password update failed.",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
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
        message,
    }))
}
