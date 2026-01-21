// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::admin::{middleware, pages, roles, system, tags, themes, users, ws};
use crate::config::ValidatedConfig;
use crate::management::ws::WS_MAX_MESSAGE_BYTES;
use crate::util::{CsrfTokenOutcome, CsrfTokenStore, issue_csrf_token};
use actix_web::{HttpRequest, HttpResponse, Result, web};
use serde_json::json;
use std::sync::Arc;

pub fn configure(cfg: &mut web::ServiceConfig, admin_path: &str, config: &Arc<ValidatedConfig>) {
    let admin_path_for_redirect = admin_path.to_string();

    // Apply authentication middleware to all admin routes
    cfg.service(
        web::scope(admin_path)
            .wrap(middleware::RequireAdminMiddleware::new(config.clone()))
            .route(
                "",
                web::get().to(move || admin_redirect_to_pages(admin_path_for_redirect.clone())),
            )
            .route("/csrf-token-api", web::post().to(get_csrf_token))
            .route("/ws-ticket", web::post().to(ws::ws_ticket))
            .service(
                web::resource("/ws")
                    .app_data(web::PayloadConfig::new(WS_MAX_MESSAGE_BYTES))
                    .route(web::get().to(ws::management_ws)),
            )
            .configure(|cfg| {
                pages::configure(cfg, "/pages");
                roles::configure(cfg, "/roles");
                system::configure(cfg, "/system");
                tags::configure(cfg, "/tags");
                themes::configure(cfg, "/themes");
                users::configure(cfg, "/users");
            }),
    );
}

async fn admin_redirect_to_pages(admin_path: String) -> Result<HttpResponse> {
    Ok(HttpResponse::Found()
        .insert_header(("Location", format!("{}/pages", admin_path)))
        .finish())
}

/// Get or refresh a CSRF token for the authenticated user
async fn get_csrf_token(
    req: HttpRequest,
    csrf_store: web::Data<CsrfTokenStore>,
    config: web::Data<ValidatedConfig>,
) -> Result<HttpResponse> {
    match issue_csrf_token(&req, csrf_store.as_ref(), config.as_ref()) {
        CsrfTokenOutcome::Authorized { jwt_id, token } => {
            log::debug!("CSRF token provided for JWT ID: {}", jwt_id);
            Ok(HttpResponse::Ok().json(json!({
                "csrf_token": token,
                "expires_in_seconds": csrf_store.expiry_seconds(),
            })))
        }
        CsrfTokenOutcome::DevMode { jwt_id, token } => {
            log::debug!(
                "🔧 DEV MODE: CSRF token provided for localhost JWT ID: {}",
                jwt_id
            );
            Ok(HttpResponse::Ok().json(json!({
                "csrf_token": token,
                "expires_in_seconds": csrf_store.expiry_seconds(),
            })))
        }
        CsrfTokenOutcome::Unauthorized => {
            log::warn!("CSRF token requested without valid JWT claims");
            Ok(HttpResponse::Unauthorized().json(json!({
                "error": "Authentication required"
            })))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DevMode;
    use crate::util::test_config::TestConfigBuilder;
    use actix_web::body::to_bytes;
    use actix_web::test;
    use serde_json::Value;

    fn create_test_config_with_dev_mode(dev_mode: Option<DevMode>) -> ValidatedConfig {
        TestConfigBuilder::new().with_dev_mode(dev_mode).build()
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn test_get_csrf_token_localhost_dev_mode() {
        let config = web::Data::new(create_test_config_with_dev_mode(Some(DevMode::Localhost)));
        let csrf_store = web::Data::new(CsrfTokenStore::new(&config));

        // Create a test request from localhost without JWT authentication
        let req = test::TestRequest::post()
            .uri("/admin/csrf-token-api")
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .to_http_request();

        // Call the function
        let result = get_csrf_token(req, csrf_store.clone(), config).await;

        // Verify it returns a successful response with a CSRF token
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body()).await.expect("body bytes");
        let payload: Value = serde_json::from_slice(&body).expect("json payload");
        assert_eq!(
            payload
                .get("expires_in_seconds")
                .and_then(|value| value.as_u64()),
            Some(csrf_store.expiry_seconds())
        );

        // Verify that a token was created for the "localhost" JWT ID
        let localhost_token = csrf_store.get_or_refresh_token("localhost");
        assert!(!localhost_token.is_empty());
    }

    #[actix_web::test]
    async fn test_get_csrf_token_no_dev_mode_requires_auth() {
        let config = web::Data::new(create_test_config_with_dev_mode(None));
        let csrf_store = web::Data::new(CsrfTokenStore::new(&config));

        // Create a test request from localhost without JWT authentication and no dev mode
        let req = test::TestRequest::post()
            .uri("/admin/csrf-token-api")
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .to_http_request();

        // Call the function
        let result = get_csrf_token(req, csrf_store, config).await;

        // Verify it returns unauthorized response
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 401);
    }
}
