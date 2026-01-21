// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use minijinja::{Environment, Value, default_auto_escape_callback};

pub trait TemplateEngine: Send + Sync {
    fn render(&self, template_name: &str, context: Value) -> Result<String, minijinja::Error>;
}

pub struct MiniJinjaEngine {
    env: Environment<'static>,
}

impl MiniJinjaEngine {
    pub fn new() -> Self {
        let mut env = Environment::new();
        env.set_auto_escape_callback(default_auto_escape_callback);
        env.set_loader(embedded_template_loader);
        Self { env }
    }
}

impl Default for MiniJinjaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateEngine for MiniJinjaEngine {
    fn render(&self, template_name: &str, context: Value) -> Result<String, minijinja::Error> {
        let tmpl = self.env.get_template(template_name)?;
        tmpl.render(context)
    }
}

/// Template loader for minijinja that loads from embedded sources
fn embedded_template_loader(name: &str) -> Result<Option<String>, minijinja::Error> {
    let template_content = match name {
        // Error pages
        "error_404.html" => Some(include_str!("../public/templates/error_404.html")),
        "error_500.html" => Some(include_str!("../public/templates/error_500.html")),

        // Login templates
        "login/login_page.html" => Some(include_str!("../login/templates/login_page.html")),
        "login/profile_page.html" => Some(include_str!("../login/templates/profile_page.html")),
        "login/oidc_auth.html" => Some(include_str!("../login/templates/oidc_auth.html")),

        // Admin SPA shell
        "admin/spa_shell.html" => Some(include_str!("../admin/templates/spa_shell.html")),

        // Public user navigation templates
        "public/user_nav_local.html" => {
            Some(include_str!("../public/templates/user_nav_local.html"))
        }
        "public/user_nav_oidc.html" => Some(include_str!("../public/templates/user_nav_oidc.html")),
        "public/nav.html" => Some(include_str!("../public/templates/nav.html")),

        // Public shortcode templates
        "public/shortcode/video.html" => {
            Some(include_str!("../public/shortcode/templates/video.html"))
        }
        "public/shortcode/link_card.html" => {
            Some(include_str!("../public/shortcode/templates/link_card.html"))
        }
        "public/shortcode/start_unibox.html" => Some(include_str!(
            "../public/shortcode/templates/start_unibox.html"
        )),

        _ => None,
    };

    Ok(template_content.map(|s| s.to_string()))
}
