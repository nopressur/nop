// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::web;
use nop_config::ValidatedConfig;
use std::sync::Arc;

pub mod local;
pub mod oidc;
mod sessions;
mod state;
pub mod types;

pub use sessions::LoginSessionStore;
pub use state::LoginState;

/// Configure login routes - delegates to appropriate module based on config
pub fn configure(cfg: &mut web::ServiceConfig, config: &Arc<ValidatedConfig>) {
    match &config.users {
        nop_config::ValidatedUsersConfig::Local(_) => {
            cfg.service(web::scope("/login").configure(local::configure_login));
            local::configure_profile(cfg);
        }
        nop_config::ValidatedUsersConfig::Oidc(_) => {
            cfg.service(web::scope("/login/oidc").configure(oidc::configure));
        }
    }
}
