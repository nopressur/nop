// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::Error;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::web::Data;
use actix_web::{HttpMessage, HttpResponse};

use std::future::{Ready, ready};
use std::pin::Pin;
use std::rc::Rc;

use crate::config::ValidatedConfig;
use crate::iam::middleware::AuthRequest;
use crate::util::CsrfTokenStore;
use crate::util::csrf_validation::{CSRF_HEADER_NAME, mark_csrf_validated, validate_csrf_token};

/// CSRF validation middleware factory
pub struct CsrfValidationMiddlewareFactory;

impl<S, B> Transform<S, ServiceRequest> for CsrfValidationMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CsrfValidationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfValidationMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct CsrfValidationMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for CsrfValidationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            let path = req.path();
            let method = req.method().as_str();

            // Get CSRF store from app data to check exempt endpoints
            let csrf_store = match req.app_data::<Data<CsrfTokenStore>>() {
                Some(store) => store,
                None => {
                    log::error!("CSRF store not found in app data for path: {}", req.path());
                    return Err(actix_web::error::ErrorInternalServerError(
                        "CSRF store not found in app data",
                    ));
                }
            };

            // Check if endpoint is exempt from CSRF validation
            if csrf_store.is_exempt(path, method) {
                log::debug!(
                    "CSRF validation skipped for exempt endpoint: {} {}",
                    method,
                    path
                );
                return service.call(req).await;
            }

            // Convert ServiceRequest to HttpRequest to access our auth extensions
            let http_req = req.request();

            // Determine JWT ID for CSRF validation
            let jwt_id = if let Some(jwt_id) = http_req.jwt_id() {
                // Normal authenticated request
                jwt_id
            } else {
                // Check if this is a localhost dev mode request
                if let Some(config) = req.app_data::<Data<ValidatedConfig>>() {
                    if crate::security::is_dev_mode_bypass_allowed(http_req, config.get_ref()) {
                        // Use "localhost" as JWT ID for dev mode
                        log::debug!(
                            "🔧 DEV MODE: Using 'localhost' as JWT ID for CSRF validation on {}",
                            req.path()
                        );
                        "localhost".to_string()
                    } else {
                        // Skip CSRF validation for unauthenticated requests (not in dev mode)
                        log::debug!(
                            "Skipping CSRF validation for unauthenticated request to {}",
                            req.path()
                        );
                        return service.call(req).await;
                    }
                } else {
                    // No config available, skip CSRF validation
                    log::debug!(
                        "Skipping CSRF validation for unauthenticated request to {} (no config)",
                        req.path()
                    );
                    return service.call(req).await;
                }
            };

            // Extract CSRF token from header
            let csrf_token = match http_req
                .headers()
                .get(CSRF_HEADER_NAME)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
            {
                Some(token) => token,
                None => {
                    log::warn!(
                        "Missing CSRF token for {} request to {} from user with JWT ID: {}",
                        method,
                        req.path(),
                        jwt_id
                    );
                    return Err(actix_web::error::ErrorBadRequest("CSRF token required"));
                }
            };

            // Validate CSRF token against JWT ID
            if !validate_csrf_token(csrf_store, &csrf_token, &jwt_id) {
                log::warn!(
                    "Invalid CSRF token for {} request to {} from user with JWT ID: {}",
                    method,
                    req.path(),
                    jwt_id
                );
                return Err(actix_web::error::ErrorForbidden(
                    "CSRF token validation failed",
                ));
            }

            // Mark request as having validated CSRF token
            mark_csrf_validated(http_req);
            log::debug!(
                "CSRF token validated for {} request to {} from user with JWT ID: {}",
                method,
                req.path(),
                jwt_id
            );

            // Continue with the request
            service.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DevMode;
    use crate::iam::User;
    use crate::iam::jwt::Claims;
    use crate::util::test_config::TestConfigBuilder;
    use actix_web::http::{Method, StatusCode};
    use actix_web::{App, HttpResponse, Result, test, web};

    async fn test_endpoint() -> Result<HttpResponse> {
        Ok(HttpResponse::Ok().json(serde_json::json!({"success": true})))
    }

    fn create_test_config_with_dev_mode(dev_mode: Option<DevMode>) -> ValidatedConfig {
        TestConfigBuilder::new().with_dev_mode(dev_mode).build()
    }

    #[actix_web::test]
    async fn test_csrf_middleware_skips_get_requests() {
        let config = create_test_config_with_dev_mode(None);
        let csrf_store = Data::new(CsrfTokenStore::new(&config));

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/test", web::get().to(test_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_csrf_middleware_skips_unauthenticated_requests() {
        let config = create_test_config_with_dev_mode(None);
        let csrf_store = Data::new(CsrfTokenStore::new(&config));

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/test", web::post().to(test_endpoint)),
        )
        .await;

        let req = test::TestRequest::post().uri("/test").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_csrf_exempt_endpoints() {
        let config = create_test_config_with_dev_mode(None);
        let csrf_store = CsrfTokenStore::new(&config);

        assert!(csrf_store.is_exempt("/login", "POST"));
        assert!(csrf_store.is_exempt("/login/csrf-token-api", "POST"));
        assert!(csrf_store.is_exempt("/admin/csrf-token-api", "POST")); // Uses default /admin path
        assert!(csrf_store.is_exempt("/login/logout-api", "POST"));
        assert!(csrf_store.is_exempt("/login/oidc/callback", "POST"));
        assert!(!csrf_store.is_exempt("/admin/themes/create-api", "POST"));
        assert!(csrf_store.is_exempt("/any-endpoint", "GET")); // All GET exempt

        // Test with custom admin path
        let mut custom_config = config.clone();
        custom_config.admin.path = "/custom-admin".to_string();
        let custom_csrf_store = CsrfTokenStore::new(&custom_config);
        assert!(custom_csrf_store.is_exempt("/custom-admin/csrf-token-api", "POST"));
        assert!(!custom_csrf_store.is_exempt("/admin/csrf-token-api", "POST")); // Old path no longer exempt
    }

    #[actix_web::test]
    async fn test_csrf_middleware_skips_exempt_endpoints() {
        let config = create_test_config_with_dev_mode(None);
        let csrf_store = Data::new(CsrfTokenStore::new(&config));

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/login", web::post().to(test_endpoint))
                .route("/login/csrf-token-api", web::post().to(test_endpoint))
                .route("/admin/csrf-token-api", web::post().to(test_endpoint)),
        )
        .await;

        // Test /login endpoint is exempt
        let req = test::TestRequest::post().uri("/login").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Test /login/csrf-token-api endpoint is exempt
        let req = test::TestRequest::post()
            .uri("/login/csrf-token-api")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Test /admin/csrf-token-api endpoint is exempt
        let req = test::TestRequest::post()
            .uri("/admin/csrf-token-api")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_csrf_middleware_requires_token_for_authenticated_post() {
        let config = create_test_config_with_dev_mode(None);
        let csrf_store = Data::new(CsrfTokenStore::new(&config));

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/test", web::post().to(test_endpoint)),
        )
        .await;

        // Create a test request with authenticated user but no CSRF token
        let req = test::TestRequest::post().uri("/test").to_request();

        // Manually add user and claims to extensions to simulate authentication
        req.extensions_mut().insert(User {
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: 1,
        });
        req.extensions_mut().insert(Claims {
            sub: "test@example.com".to_string(),
            name: "Test User".to_string(),
            groups: vec!["admin".to_string()],
            iat: 0,
            exp: 0,
            iss: "test".to_string(),
            aud: "test".to_string(),
            jti: "test-jwt-id".to_string(),
            password_version: 1,
        });

        let result = test::try_call_service(&app, req).await;

        // The middleware should return an error for missing CSRF token
        assert!(result.is_err());

        // We can also check that the error is the expected type
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), "CSRF token required");
    }

    #[actix_web::test]
    async fn test_csrf_middleware_validates_token() {
        let config = create_test_config_with_dev_mode(None);
        let csrf_store = Data::new(CsrfTokenStore::new(&config));
        let jwt_id = "test-jwt-id";

        // Pre-create a valid CSRF token
        let valid_token = csrf_store.get_new_token(jwt_id);

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/test", web::post().to(test_endpoint)),
        )
        .await;

        // Create a test request with authenticated user and valid CSRF token
        let req = test::TestRequest::post()
            .uri("/test")
            .insert_header((CSRF_HEADER_NAME, valid_token))
            .to_request();

        // Manually add user and claims to extensions to simulate authentication
        req.extensions_mut().insert(User {
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: 1,
        });
        req.extensions_mut().insert(Claims {
            sub: "test@example.com".to_string(),
            name: "Test User".to_string(),
            groups: vec!["admin".to_string()],
            iat: 0,
            exp: 0,
            iss: "test".to_string(),
            aud: "test".to_string(),
            jti: jwt_id.to_string(),
            password_version: 1,
        });

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn test_csrf_middleware_localhost_dev_mode() {
        let config = Data::new(create_test_config_with_dev_mode(Some(DevMode::Localhost)));
        let csrf_store = Data::new(CsrfTokenStore::new(&config));

        // Pre-create a valid CSRF token for "localhost" JWT ID
        let valid_token = csrf_store.get_new_token("localhost");

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .app_data(config)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/test", web::post().to(test_endpoint)),
        )
        .await;

        // Create a test request from localhost without JWT authentication but with valid CSRF token
        let req = test::TestRequest::post()
            .uri("/test")
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .insert_header((CSRF_HEADER_NAME, valid_token))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn test_csrf_middleware_localhost_dev_mode_missing_token() {
        let config = Data::new(create_test_config_with_dev_mode(Some(DevMode::Localhost)));
        let csrf_store = Data::new(CsrfTokenStore::new(&config));

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .app_data(config)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/test", web::post().to(test_endpoint)),
        )
        .await;

        // Create a test request from localhost without JWT authentication and without CSRF token
        let req = test::TestRequest::post()
            .uri("/test")
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .to_request();

        let result = test::try_call_service(&app, req).await;

        // Should fail because CSRF token is required even in dev mode
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), "CSRF token required");
    }

    #[actix_web::test]
    async fn test_csrf_middleware_no_dev_mode_still_skips_unauth() {
        let config = Data::new(create_test_config_with_dev_mode(None));
        let csrf_store = Data::new(CsrfTokenStore::new(&config));

        let app = test::init_service(
            App::new()
                .app_data(csrf_store)
                .app_data(config)
                .wrap(CsrfValidationMiddlewareFactory)
                .route("/test", web::post().to(test_endpoint)),
        )
        .await;

        // Create a test request from localhost without JWT authentication and no dev mode
        let req = test::TestRequest::post()
            .uri("/test")
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
