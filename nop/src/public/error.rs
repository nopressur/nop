// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::templates::{ErrorPageContext, TemplateEngine, render_minijinja_template};
use actix_web::http::header::{ACCEPT, CONTENT_TYPE};
use actix_web::{HttpRequest, HttpResponse, Result};
use serde_json::json;

#[derive(Clone)]
pub struct ErrorRenderer {
    app_name: String,
}

impl ErrorRenderer {
    pub fn new(app_name: String) -> Self {
        Self { app_name }
    }

    pub fn app_name(&self) -> &str {
        &self.app_name
    }
}

pub fn serve_404(
    renderer: &ErrorRenderer,
    template_engine: Option<&dyn TemplateEngine>,
) -> Result<HttpResponse> {
    serve_404_with_app_name(renderer.app_name(), template_engine)
}

pub fn serve_404_for_request(
    req: &HttpRequest,
    renderer: &ErrorRenderer,
    template_engine: Option<&dyn TemplateEngine>,
) -> Result<HttpResponse> {
    serve_404_for_request_with_app_name(req, renderer.app_name(), template_engine)
}

pub fn serve_404_for_request_with_app_name(
    req: &HttpRequest,
    app_name: &str,
    template_engine: Option<&dyn TemplateEngine>,
) -> Result<HttpResponse> {
    if request_wants_json(req) {
        Ok(HttpResponse::NotFound().json(json!({ "error": "Not Found" })))
    } else {
        serve_404_with_app_name(app_name, template_engine)
    }
}

pub fn serve_404_with_app_name(
    app_name: &str,
    template_engine: Option<&dyn TemplateEngine>,
) -> Result<HttpResponse> {
    let context = ErrorPageContext::new(app_name).to_value();

    let html = match template_engine {
        Some(engine) => match render_minijinja_template(engine, "error_404.html", context) {
            Ok(html) => html,
            Err(e) => {
                log::error!("Failed to render 404 error template: {}", e);
                fallback_404_html(app_name)
            }
        },
        None => fallback_404_html(app_name),
    };

    Ok(HttpResponse::NotFound()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .body(html))
}

pub fn serve_500(
    renderer: &ErrorRenderer,
    template_engine: Option<&dyn TemplateEngine>,
) -> Result<HttpResponse> {
    serve_500_with_app_name(renderer.app_name(), template_engine)
}

pub fn serve_500_with_app_name(
    app_name: &str,
    template_engine: Option<&dyn TemplateEngine>,
) -> Result<HttpResponse> {
    let context = ErrorPageContext::new(app_name).to_value();

    let html = match template_engine {
        Some(engine) => match render_minijinja_template(engine, "error_500.html", context) {
            Ok(html) => html,
            Err(e) => {
                log::error!("Failed to render 500 error template: {}", e);
                fallback_500_html(app_name)
            }
        },
        None => fallback_500_html(app_name),
    };

    Ok(HttpResponse::InternalServerError()
        .content_type("text/html; charset=utf-8")
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .body(html))
}

fn fallback_404_html(app_name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><title>404 - File Not Found | {}</title></head>
<body><h1>404 - Page Not Found</h1></body></html>"#,
        app_name
    )
}

fn fallback_500_html(app_name: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html><head><title>500 - Internal Server Error | {}</title></head>
<body><h1>500 - Internal Server Error</h1></body></html>"#,
        app_name
    )
}

fn request_wants_json(req: &HttpRequest) -> bool {
    fn header_has_json(value: &str) -> bool {
        let value = value.to_ascii_lowercase();
        value.contains("application/json") || value.contains("+json") || value.contains("text/json")
    }

    if let Some(value) = req
        .headers()
        .get(ACCEPT)
        .and_then(|header| header.to_str().ok())
        && header_has_json(value)
    {
        return true;
    }

    if let Some(value) = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|header| header.to_str().ok())
        && header_has_json(value)
    {
        return true;
    }

    let path = req.path();
    if path.starts_with("/api") || path.contains("-api") {
        return true;
    }

    false
}
