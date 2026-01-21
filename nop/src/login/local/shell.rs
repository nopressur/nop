// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::headers::{generate_csp_nonce, set_strict_csp};
use crate::iam::AuthRequest;
use crate::public::page_meta_cache::PageMetaCache;
use crate::security;
use crate::templates::{LoginSpaShellContext, render_minijinja_template};
use actix_web::{HttpRequest, HttpResponse, Result, web};
use serde::{Deserialize, Serialize};

use super::helpers::sanitize_return_path;

#[derive(Debug, Deserialize)]
pub(super) struct LoginQuery {
    pub return_path: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginProviderConfig {
    id: String,
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginPasswordParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: u32,
    salt_len: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LoginSpaUser {
    email: String,
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginSpaRuntimeConfig {
    app_name: String,
    login_path: String,
    profile_path: String,
    profile_api_path: String,
    csrf_token_path: String,
    initial_route: String,
    return_path: Option<String>,
    providers: Vec<LoginProviderConfig>,
    password_front_end: LoginPasswordParams,
    user: Option<LoginSpaUser>,
}

pub(super) async fn login_shell(
    req: HttpRequest,
    query: web::Query<LoginQuery>,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let return_path = sanitize_return_path(query.return_path.as_deref());
    let csp_nonce = generate_csp_nonce();
    set_strict_csp(&req, &csp_nonce);
    render_login_shell(
        "login",
        return_path,
        None,
        &csp_nonce,
        config.as_ref(),
        app_state.as_ref(),
    )
}

pub(super) async fn profile_shell(
    req: HttpRequest,
    query: web::Query<LoginQuery>,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
    page_cache: web::Data<PageMetaCache>,
) -> Result<HttpResponse> {
    let user = match req.user_info() {
        Some(user) => user,
        None => {
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/login?return_path=/login/profile"))
                .finish());
        }
    };
    let shell_user = LoginSpaUser {
        email: user.email,
        name: user.name,
    };
    if shell_user.email.is_empty() {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/login?return_path=/login/profile"))
            .finish());
    }
    let is_admin = user.roles.iter().any(|role| role == "admin");
    let return_path = sanitize_return_path(query.return_path.as_deref()).and_then(|path| {
        security::validate_login_return_path(&path, page_cache.as_ref(), &config, is_admin)
    });
    let csp_nonce = generate_csp_nonce();
    set_strict_csp(&req, &csp_nonce);
    render_login_shell(
        "profile",
        return_path,
        Some(shell_user),
        &csp_nonce,
        config.as_ref(),
        app_state.as_ref(),
    )
}

fn render_login_shell(
    initial_route: &str,
    return_path: Option<String>,
    user: Option<LoginSpaUser>,
    csp_nonce: &str,
    config: &ValidatedConfig,
    app_state: &AppState,
) -> Result<HttpResponse> {
    let local_config = match config.users.local() {
        Some(local) => local,
        None => {
            return Ok(HttpResponse::InternalServerError()
                .content_type("text/html; charset=utf-8")
                .body("Authentication configuration not available"));
        }
    };

    let runtime_config = LoginSpaRuntimeConfig {
        app_name: config.app.name.clone(),
        login_path: "/login".to_string(),
        profile_path: "/login/profile".to_string(),
        profile_api_path: "/profile".to_string(),
        csrf_token_path: "/login/csrf-token-api".to_string(),
        initial_route: initial_route.to_string(),
        return_path,
        providers: vec![LoginProviderConfig {
            id: "password".to_string(),
            label: "Password".to_string(),
        }],
        password_front_end: LoginPasswordParams {
            memory_kib: local_config.password.front_end.memory_kib,
            iterations: local_config.password.front_end.iterations,
            parallelism: local_config.password.front_end.parallelism,
            output_len: local_config.password.front_end.output_len,
            salt_len: local_config.password.front_end.salt_len,
        },
        user,
    };

    let runtime_config_json = serde_json::to_string(&runtime_config).map_err(|err| {
        log::error!("Failed to serialize login runtime config: {}", err);
        actix_web::error::ErrorInternalServerError("Template rendering failed")
    })?;

    let context =
        LoginSpaShellContext::new(&config.app.name, &runtime_config_json, csp_nonce).to_value();
    let html = render_minijinja_template(
        app_state.templates.as_ref(),
        "login/login_page.html",
        context,
    )
    .map_err(|err| {
        log::error!("Failed to render login SPA shell template: {}", err);
        actix_web::error::ErrorInternalServerError("Template rendering failed")
    })?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .append_header(("Cache-Control", "no-store"))
        .body(html))
}
