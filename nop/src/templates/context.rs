// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use minijinja::{Value, context};

const BULMA_CSS: &str = "/builtin/bulma.min.css";
const ADMIN_SPA_CSS: &str = "/builtin/admin/admin-spa.css";
const ADMIN_SPA_JS: &str = "/builtin/admin/admin-spa.js";

include!(concat!(env!("OUT_DIR"), "/login_spa_version.rs"));

fn login_spa_css_path() -> String {
    format!("/builtin/{}/login.css", LOGIN_SPA_DIR)
}

fn login_spa_js_path() -> String {
    format!("/builtin/{}/login.js", LOGIN_SPA_DIR)
}

#[derive(Debug, Clone)]
pub struct ErrorPageContext {
    app_name: String,
}

impl ErrorPageContext {
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
        }
    }

    pub fn to_value(&self) -> Value {
        context! {
            bulma_css => BULMA_CSS,
            app_name => &self.app_name
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdminSpaShellContext {
    app_name: String,
    admin_path: String,
    runtime_config_json: String,
    bootstrap_json: String,
    csp_nonce: String,
}

impl AdminSpaShellContext {
    pub fn new(
        app_name: &str,
        admin_path: &str,
        runtime_config_json: &str,
        bootstrap_json: &str,
        csp_nonce: &str,
    ) -> Self {
        Self {
            app_name: app_name.to_string(),
            admin_path: admin_path.to_string(),
            runtime_config_json: runtime_config_json.to_string(),
            bootstrap_json: bootstrap_json.to_string(),
            csp_nonce: csp_nonce.to_string(),
        }
    }

    pub fn to_value(&self) -> Value {
        context! {
            admin_path => &self.admin_path,
            admin_spa_css => ADMIN_SPA_CSS,
            admin_spa_js => ADMIN_SPA_JS,
            app_name => &self.app_name,
            runtime_config_json => &self.runtime_config_json,
            bootstrap_json => &self.bootstrap_json,
            csp_nonce => &self.csp_nonce
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoginSpaShellContext {
    app_name: String,
    runtime_config_json: String,
    csp_nonce: String,
}

impl LoginSpaShellContext {
    pub fn new(app_name: &str, runtime_config_json: &str, csp_nonce: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            runtime_config_json: runtime_config_json.to_string(),
            csp_nonce: csp_nonce.to_string(),
        }
    }

    pub fn to_value(&self) -> Value {
        let login_spa_css = login_spa_css_path();
        let login_spa_js = login_spa_js_path();
        context! {
            app_name => &self.app_name,
            login_spa_css => login_spa_css,
            login_spa_js => login_spa_js,
            runtime_config_json => &self.runtime_config_json,
            csp_nonce => &self.csp_nonce
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct OidcAuthContext {
    app_name: String,
    admin_path: String,
}

#[allow(dead_code)]
impl OidcAuthContext {
    pub fn new(app_name: &str, admin_path: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            admin_path: admin_path.to_string(),
        }
    }

    pub fn to_value(&self) -> Value {
        context! {
            bulma_css => BULMA_CSS,
            app_name => &self.app_name,
            admin_path => &self.admin_path
        }
    }
}

#[cfg(test)]
mod tests {}
