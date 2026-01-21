// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig, base_path: &str) {
    cfg.route(base_path, web::get().to(super::index::themes_index))
        .route(
            &format!("{}/list-api", base_path),
            web::get().to(super::index::themes_list_api),
        )
        .route(
            &format!("{}/new", base_path),
            web::get().to(super::edit::themes_new),
        )
        .route(
            &format!("{}/create-api", base_path),
            web::post().to(super::edit::themes_create),
        )
        .route(
            &format!("{}/customize/{{theme}}", base_path),
            web::get().to(super::edit::themes_customize),
        )
        .route(
            &format!("{}/save-api/{{theme}}", base_path),
            web::post().to(super::edit::themes_save),
        )
        .route(
            &format!("{}/delete-api", base_path),
            web::delete().to(super::edit::themes_delete),
        );
}
