// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::web;

mod helpers;
mod password;
mod profile;
mod session;
mod shell;

/// Configure local authentication login routes
pub fn configure_login(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(shell::login_shell))
        .route("/profile", web::get().to(shell::profile_shell))
        .route("/bootstrap", web::post().to(session::login_bootstrap))
        .route("/pwd/email", web::post().to(password::password_email))
        .route("/pwd/password", web::post().to(password::password_login))
        .route("/csrf-token-api", web::post().to(session::login_csrf_token))
        .route("/logout-api", web::post().to(session::handle_logout));
}

/// Configure profile endpoints (JWT + CSRF)
pub fn configure_profile(cfg: &mut web::ServiceConfig) {
    cfg.route("/profile/update", web::post().to(profile::profile_update))
        .route(
            "/profile/pwd/salt",
            web::post().to(profile::profile_password_salt),
        )
        .route(
            "/profile/pwd/change",
            web::post().to(profile::profile_password_change),
        );
}

#[cfg(test)]
mod tests;
