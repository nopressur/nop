// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use minijinja::Value;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

mod context;
mod engine;
pub mod error;

pub use context::{AdminSpaShellContext, ErrorPageContext, LoginSpaShellContext};
pub use engine::{MiniJinjaEngine, TemplateEngine};
use error::ErrorRenderer;

#[derive(Clone)]
pub struct RequestTools {
    pub templates: Arc<dyn TemplateEngine>,
    pub error_renderer: ErrorRenderer,
}

impl RequestTools {
    pub fn new(app_name: &str) -> Self {
        Self {
            templates: Arc::new(MiniJinjaEngine::new()),
            error_renderer: ErrorRenderer::new(app_name.to_string()),
        }
    }
}

/// Simple template rendering utility that replaces placeholders with values.
///
/// Leading HTML comment blocks at the top of the template (such as the SPDX
/// license header that lives in every template source file) are stripped
/// before substitution, so they do not reach the rendered output.
pub fn render_template(template_content: &str, vars: &HashMap<&str, String>) -> String {
    let mut result = strip_leading_html_comments(template_content).to_string();
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

/// Strip any HTML comment blocks at the very start of the template, along with
/// the whitespace that surrounds them. Used to keep SPDX/license headers in
/// the template source file without rendering them to the wire.
fn strip_leading_html_comments(content: &str) -> &str {
    let mut remaining = content.trim_start();
    while remaining.starts_with("<!--") {
        match remaining.find("-->") {
            Some(end) => {
                remaining = remaining[end + "-->".len()..].trim_start();
            }
            None => break,
        }
    }
    remaining
}

/// Load legacy string-based templates.
pub fn load_template(template_name: &str) -> Result<String, std::io::Error> {
    match template_name {
        // Public templates
        "public/main_layout" => {
            Ok(include_str!("../../nop-public/src/templates/main_layout.html").to_string())
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_template_strips_leading_html_comment() {
        let template =
            "<!--\nSPDX-FileCopyrightText: 2025 Test\n-->\n<!DOCTYPE html><title>{title}</title>";
        let vars = template_vars! { "title" => "Hello" };
        let rendered = render_template(template, &vars);
        assert!(!rendered.contains("<!--"));
        assert!(!rendered.contains("SPDX"));
        assert!(rendered.starts_with("<!DOCTYPE html>"));
        assert!(rendered.contains("<title>Hello</title>"));
    }

    #[test]
    fn render_template_strips_multiple_leading_comments() {
        let template = "<!-- one --><!-- two -->\n<p>{x}</p>";
        let vars = template_vars! { "x" => "y" };
        let rendered = render_template(template, &vars);
        assert_eq!(rendered, "<p>y</p>");
    }

    #[test]
    fn render_template_preserves_non_leading_comments() {
        let template = "<p>{x}</p>\n<!-- inline comment -->\n<p>after</p>";
        let vars = template_vars! { "x" => "before" };
        let rendered = render_template(template, &vars);
        assert!(rendered.contains("<!-- inline comment -->"));
        assert!(rendered.contains("<p>before</p>"));
    }

    #[test]
    fn render_template_handles_template_without_comment() {
        let template = "<p>{x}</p>";
        let vars = template_vars! { "x" => "ok" };
        let rendered = render_template(template, &vars);
        assert_eq!(rendered, "<p>ok</p>");
    }
}
