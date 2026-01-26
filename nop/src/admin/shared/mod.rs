// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::app_state::AppState;
use crate::config::{PasswordHashingParams, ValidatedConfig, ValidatedUsersConfig};
use crate::headers::{generate_csp_nonce, set_strict_csp};
use crate::iam::AuthRequest;
use crate::templates::AdminSpaShellContext;
use crate::templates::render_minijinja_template;
use actix_web::Result;
use actix_web::{HttpRequest, HttpResponse, http::StatusCode};
use log;
use serde::Serialize;
use serde_json::{Value, json};

pub mod file_utils;

pub fn json_error_response(message: &str, status_code: StatusCode) -> HttpResponse {
    let mut builder = HttpResponse::build(status_code);
    builder.content_type("application/json");
    builder.body(format!(
        "{{\"success\": false, \"message\": \"{}\"}}",
        message
    ))
}

/// Log detailed error server-side and return generic JSON error response to client
pub fn log_and_return_generic_error(
    operation: &str,
    error: &dyn std::fmt::Display,
    status_code: StatusCode,
) -> HttpResponse {
    // Log the detailed error for debugging
    log::error!("Failed to {}: {}", operation, error);

    // Return generic error message based on status code
    let generic_message = match status_code {
        StatusCode::BAD_REQUEST => "Invalid input provided",
        StatusCode::CONFLICT => "Resource already exists",
        StatusCode::NOT_FOUND => "Resource not found",
        StatusCode::FORBIDDEN => "Operation not permitted",
        StatusCode::INTERNAL_SERVER_ERROR => "An internal error occurred",
        _ => "An error occurred",
    };

    json_error_response(generic_message, status_code)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminSpaRuntimeConfig {
    admin_path: String,
    app_name: String,
    csrf_token_path: String,
    ws_path: String,
    ws_ticket_path: String,
    user_management_enabled: bool,
    password_front_end: AdminPasswordFrontEndParams,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminPasswordFrontEndParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: u32,
    salt_len: u32,
}

pub async fn render_admin_spa_shell_html(
    config: &ValidatedConfig,
    app_state: &AppState,
    bootstrap: Option<serde_json::Value>,
    csp_nonce: &str,
) -> Result<String> {
    let front_end_params = match config.users.local() {
        Some(local) => local.password.front_end.clone(),
        None => PasswordHashingParams::default().front_end,
    };
    let runtime_config = AdminSpaRuntimeConfig {
        admin_path: config.admin.path.clone(),
        app_name: config.app.name.clone(),
        csrf_token_path: format!("{}/csrf-token-api", config.admin.path),
        ws_path: format!("{}/ws", config.admin.path),
        ws_ticket_path: format!("{}/ws-ticket", config.admin.path),
        user_management_enabled: !matches!(config.users, ValidatedUsersConfig::Oidc(_)),
        password_front_end: AdminPasswordFrontEndParams {
            memory_kib: front_end_params.memory_kib,
            iterations: front_end_params.iterations,
            parallelism: front_end_params.parallelism,
            output_len: front_end_params.output_len,
            salt_len: front_end_params.salt_len,
        },
    };

    let runtime_config_json = serde_json::to_string(&runtime_config).map_err(|err| {
        log::error!("Failed to serialize admin runtime config: {}", err);
        actix_web::error::ErrorInternalServerError("Template rendering failed")
    })?;

    let bootstrap_json = match bootstrap {
        Some(value) => serde_json::to_string(&value).map_err(|err| {
            log::error!("Failed to serialize admin bootstrap data: {}", err);
            actix_web::error::ErrorInternalServerError("Template rendering failed")
        })?,
        None => "null".to_string(),
    };

    let context = AdminSpaShellContext::new(
        &config.app.name,
        &config.admin.path,
        &runtime_config_json,
        &bootstrap_json,
        csp_nonce,
    )
    .to_value();
    render_minijinja_template(
        app_state.templates.as_ref(),
        "admin/spa_shell.html",
        context,
    )
    .map_err(|err| {
        log::error!("Failed to render admin SPA shell template: {}", err);
        actix_web::error::ErrorInternalServerError("Template rendering failed")
    })
}

pub async fn render_admin_spa_shell_response(
    req: &HttpRequest,
    config: &ValidatedConfig,
    app_state: &AppState,
    bootstrap: Option<serde_json::Value>,
) -> Result<HttpResponse> {
    let current_email = req.user_info().map(|user| user.email);
    let bootstrap = merge_bootstrap_with_current_user(bootstrap, current_email);
    let csp_nonce = generate_csp_nonce();
    set_strict_csp(req, &csp_nonce);
    let html = render_admin_spa_shell_html(config, app_state, bootstrap, &csp_nonce).await?;
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

fn merge_bootstrap_with_current_user(
    bootstrap: Option<Value>,
    current_email: Option<String>,
) -> Option<Value> {
    let current_email = current_email?;
    let mut value = bootstrap.unwrap_or_else(|| json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("currentUserEmail".to_string(), Value::String(current_email));
        return Some(value);
    }
    let mut wrapped = serde_json::Map::new();
    wrapped.insert("currentUserEmail".to_string(), Value::String(current_email));
    wrapped.insert("bootstrap".to_string(), value);
    Some(Value::Object(wrapped))
}
