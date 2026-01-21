// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::admin::shared;
use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::headers::{generate_csp_nonce, set_strict_csp};
use crate::security;
use crate::util::ReleaseTracker;
use actix_web::{HttpRequest, HttpResponse, Result, http::StatusCode, web};
use serde_json::json;
use std::path::{Path, PathBuf};
use tokio::fs;

fn build_theme_path(theme_name: &str, themes_dir: &Path) -> std::result::Result<PathBuf, String> {
    security::validate_new_file_name(theme_name)?;
    let filename = format!("{}.html", theme_name);
    security::validate_new_file_path(&filename, themes_dir)
}

async fn render_theme_error(
    req: &HttpRequest,
    config: &ValidatedConfig,
    app_state: &AppState,
    theme_name: &str,
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<HttpResponse> {
    let bootstrap = json!({
        "error": {
            "code": code,
            "message": message,
            "theme": theme_name
        }
    });
    let csp_nonce = generate_csp_nonce();
    set_strict_csp(req, &csp_nonce);
    let html =
        shared::render_admin_spa_shell_html(config, app_state, Some(bootstrap), &csp_nonce).await?;

    Ok(HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .body(html))
}

/// Create a new theme with a name input field
pub async fn themes_new(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // Read the default theme content to use as template
    let default_theme_path = app_state.runtime_paths.themes_dir.join("default.html");
    let default_theme_content = match fs::read_to_string(&default_theme_path).await {
        Ok(content) => content,
        Err(e) => {
            // Log detailed error for debugging but don't include in HTML output
            log::error!(
                "Failed to read default theme file '{}': {}",
                default_theme_path.display(),
                e
            );

            // Fallback to a basic template - completely static, no error details
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
</head>
<body>
    <section class="section">
        <div class="container">
            <h1 class="title">{{title}}</h1>
            <div class="content">
                {{content}}
            </div>
        </div>
    </section>
</body>
</html>"#
                .to_string()
        }
    };

    let bootstrap = json!({
        "theme": {
            "mode": "new",
            "name": null,
            "content": default_theme_content
        }
    });

    shared::render_admin_spa_shell_response(
        &req,
        config.as_ref(),
        app_state.as_ref(),
        Some(bootstrap),
    )
    .await
}

/// Create a new theme with the submitted content and name
pub async fn themes_create(
    payload: web::Json<NewThemePayload>,
    config: web::Data<ValidatedConfig>,
    release_tracker: web::Data<ReleaseTracker>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let theme_path = match build_theme_path(&payload.name, &app_state.runtime_paths.themes_dir) {
        Ok(path) => path,
        Err(error_msg) => {
            log::warn!("Invalid theme name '{}': {}", payload.name, error_msg);
            return Ok(shared::json_error_response(
                "Invalid theme name",
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    // Check if theme already exists
    match fs::try_exists(&theme_path).await {
        Ok(true) => {
            return Ok(shared::json_error_response(
                "Theme already exists",
                StatusCode::CONFLICT,
            ));
        }
        Ok(false) => {}
        Err(e) => {
            return Ok(shared::log_and_return_generic_error(
                "create theme",
                &e,
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }

    // Write the new theme content to the file
    match fs::write(&theme_path, &payload.content).await {
        Ok(_) => {
            release_tracker.bump(&format!("theme created ({})", payload.name));
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(format!("{{\"success\": true, \"message\": \"Theme created successfully\", \"redirect\": \"{}/themes/customize/{}\"}}", 
                    config.admin.path, payload.name)))
        }
        Err(e) => Ok(shared::log_and_return_generic_error(
            "create theme",
            &e,
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

pub async fn themes_customize(
    req: HttpRequest,
    path: web::Path<String>,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let theme_name = path.into_inner();
    let theme_path = match build_theme_path(&theme_name, &app_state.runtime_paths.themes_dir) {
        Ok(path) => path,
        Err(error_msg) => {
            log::warn!("Invalid theme name '{}': {}", theme_name, error_msg);
            return render_theme_error(
                &req,
                config.as_ref(),
                app_state.as_ref(),
                &theme_name,
                StatusCode::BAD_REQUEST,
                "invalid_theme",
                "Invalid theme name",
            )
            .await;
        }
    };
    let canonical_path = match security::canonical_path_checks(
        &theme_path,
        &app_state.runtime_paths.themes_dir.to_string_lossy(),
        Some(&config.app.name),
    ) {
        Ok(path) => path,
        Err(_) => {
            return render_theme_error(
                &req,
                config.as_ref(),
                app_state.as_ref(),
                &theme_name,
                StatusCode::NOT_FOUND,
                "theme_not_found",
                "Theme file could not be accessed",
            )
            .await;
        }
    };

    // Read the theme file content
    let theme_content = match fs::read_to_string(&canonical_path).await {
        Ok(content) => content,
        Err(e) => {
            log::error!("Failed to read theme file '{}': {}", theme_name, e);
            return render_theme_error(
                &req,
                config.as_ref(),
                app_state.as_ref(),
                &theme_name,
                StatusCode::NOT_FOUND,
                "theme_not_found",
                "Theme file could not be accessed",
            )
            .await;
        }
    };

    let bootstrap = json!({
        "theme": {
            "mode": "customize",
            "name": theme_name,
            "content": theme_content
        }
    });

    shared::render_admin_spa_shell_response(
        &req,
        config.as_ref(),
        app_state.as_ref(),
        Some(bootstrap),
    )
    .await
}

pub async fn themes_save(
    path: web::Path<String>,
    payload: web::Json<ThemePayload>,
    config: web::Data<ValidatedConfig>,
    release_tracker: web::Data<ReleaseTracker>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let theme_name = path.into_inner();
    let theme_path = match build_theme_path(&theme_name, &app_state.runtime_paths.themes_dir) {
        Ok(path) => path,
        Err(error_msg) => {
            log::warn!("Invalid theme name '{}': {}", theme_name, error_msg);
            return Ok(shared::json_error_response(
                "Invalid theme name",
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    let canonical_path = match security::canonical_path_checks(
        &theme_path,
        &app_state.runtime_paths.themes_dir.to_string_lossy(),
        Some(&config.app.name),
    ) {
        Ok(path) => path,
        Err(_) => {
            return Ok(shared::json_error_response(
                "Theme not found",
                StatusCode::NOT_FOUND,
            ));
        }
    };

    // Write the updated theme content to the file
    match fs::write(&canonical_path, &payload.content).await {
        Ok(_) => {
            release_tracker.bump(&format!("theme saved ({})", theme_name));
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body("{\"success\": true, \"message\": \"Theme saved successfully\"}"))
        }
        Err(e) => Ok(shared::log_and_return_generic_error(
            "save theme",
            &e,
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

#[derive(serde::Deserialize)]
pub struct ThemePayload {
    content: String,
}

#[derive(serde::Deserialize)]
pub struct NewThemePayload {
    name: String,
    content: String,
}

#[derive(serde::Deserialize)]
pub struct DeleteQuery {
    theme: String,
}

/// Delete a theme file
pub async fn themes_delete(
    query: web::Query<DeleteQuery>,
    config: web::Data<ValidatedConfig>,
    release_tracker: web::Data<ReleaseTracker>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let theme_name = &query.theme;

    // Security check: prevent deletion of default theme
    if theme_name == "default" {
        return Ok(shared::json_error_response(
            "Cannot delete the default theme",
            StatusCode::FORBIDDEN,
        ));
    }

    let theme_path = match build_theme_path(theme_name, &app_state.runtime_paths.themes_dir) {
        Ok(path) => path,
        Err(error_msg) => {
            log::warn!(
                "Invalid theme delete request '{}': {}",
                theme_name,
                error_msg
            );
            return Ok(shared::json_error_response(
                "Invalid theme name",
                StatusCode::BAD_REQUEST,
            ));
        }
    };

    // Use existing security canonical path checks for validation
    let canonical_path = match security::canonical_path_checks(
        &theme_path,
        &app_state.runtime_paths.themes_dir.to_string_lossy(),
        Some(&config.app.name),
    ) {
        Ok(path) => path,
        Err(err) => {
            return err;
        }
    };

    // Check if the file exists and is a file (not a directory)
    let metadata = match tokio::fs::metadata(&canonical_path).await {
        Ok(metadata) => metadata,
        Err(_) => {
            return Ok(shared::json_error_response(
                "Theme not found",
                StatusCode::NOT_FOUND,
            ));
        }
    };

    if !metadata.is_file() {
        return Ok(shared::json_error_response(
            "Invalid theme",
            StatusCode::BAD_REQUEST,
        ));
    }

    // Delete the theme file
    match tokio::fs::remove_file(&canonical_path).await {
        Ok(_) => {
            log::info!("Successfully deleted theme: {}", theme_name);
            release_tracker.bump(&format!("theme deleted ({})", theme_name));

            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body("{\"success\": true, \"message\": \"Theme deleted successfully\"}"))
        }
        Err(e) => Ok(shared::log_and_return_generic_error(
            "delete theme",
            &e,
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}
