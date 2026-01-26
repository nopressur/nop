// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use minijinja::Value;
use std::collections::HashMap;
use uuid::Uuid;

mod context;
mod engine;

pub use context::{AdminSpaShellContext, ErrorPageContext, LoginSpaShellContext};
pub use engine::{MiniJinjaEngine, TemplateEngine};

/// Simple template rendering utility that replaces placeholders with values
pub fn render_template(template_content: &str, vars: &HashMap<&str, String>) -> String {
    let mut result = template_content.to_string();
    let mut replacements = Vec::new();

    for (key, value) in vars {
        let placeholder = format!("{{{}}}", key);
        let token = Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(16)
            .collect::<String>();
        let token_placeholder = format!("{{{}}}", token);
        result = result.replace(&placeholder, &token_placeholder);
        replacements.push((token_placeholder, value));
    }

    // Replace randomized placeholders last to avoid collisions with rendered content.
    for (token_placeholder, value) in replacements {
        result = result.replace(&token_placeholder, value);
    }

    result
}

/// Load legacy string-based templates.
pub fn load_template(template_name: &str) -> Result<String, std::io::Error> {
    match template_name {
        // Public templates
        "public/main_layout" => Ok(include_str!("public/templates/main_layout.html").to_string()),

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Template '{}' not found", template_name),
        )),
    }
}

/// Render a minijinja template with the given context
pub fn render_minijinja_template(
    engine: &dyn TemplateEngine,
    template_name: &str,
    context: Value,
) -> Result<String, minijinja::Error> {
    engine.render(template_name, context)
}

/// Helper macro to create template variables map more easily
#[macro_export]
macro_rules! template_vars {
    ($($key:expr => $value:expr),* $(,)?) => {
        {
            let mut map = std::collections::HashMap::new();
            $(
                map.insert($key, $value.to_string());
            )*
            map
        }
    };
}
