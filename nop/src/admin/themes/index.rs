// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::admin::shared;
use crate::admin::shared::file_utils::{format_file_size, scan_themes_directory};
use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use serde::Serialize;
use serde_json::json;

#[derive(Serialize)]
struct ThemeListItem {
    name: String,
    is_default: bool,
    file_size: u64,
    file_size_formatted: String,
    customize_url: String,
}

#[derive(Serialize)]
struct ThemeListSummary {
    name: String,
    is_default: bool,
}

pub async fn themes_index(
    req: HttpRequest,
    config: web::Data<ValidatedConfig>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    log::info!("Admin themes index requested");
    let theme_files = scan_themes_directory(&app_state.runtime_paths.themes_dir);
    let themes: Vec<ThemeListItem> = theme_files
        .iter()
        .map(|theme| ThemeListItem {
            name: theme.name.clone(),
            is_default: theme.is_default,
            file_size: theme.file_size,
            file_size_formatted: format_file_size(theme.file_size),
            customize_url: format!("{}/themes/customize/{}", config.admin.path, theme.name),
        })
        .collect();

    let bootstrap = json!({
        "themes": themes
    });

    shared::render_admin_spa_shell_response(
        &req,
        config.as_ref(),
        app_state.as_ref(),
        Some(bootstrap),
    )
    .await
}

pub async fn themes_list_api(app_state: web::Data<AppState>) -> Result<HttpResponse> {
    let theme_files = scan_themes_directory(&app_state.runtime_paths.themes_dir);
    let themes: Vec<ThemeListSummary> = theme_files
        .iter()
        .map(|theme| ThemeListSummary {
            name: theme.name.clone(),
            is_default: theme.is_default,
        })
        .collect();

    Ok(HttpResponse::Ok().json(json!({ "themes": themes })))
}
