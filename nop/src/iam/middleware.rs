// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::Error;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::web::Data;
use actix_web::{HttpMessage, HttpRequest};
use std::future::{Ready, ready};
use std::pin::Pin;
use std::rc::Rc; // Changed from Arc as services are per-thread

use super::jwt::Claims;
use super::types::User;
use crate::config::ValidatedConfig;
use crate::iam::user_services::UserServices; // Using crate::iam path

/// Trait to add authentication methods to HttpRequest
pub trait AuthRequest {
    fn user_info(&self) -> Option<User>;
    fn jwt_claims(&self) -> Option<Claims>;
    fn jwt_id(&self) -> Option<String>;
    fn has_group(&self, group: &str) -> bool;

    fn is_authenticated(&self) -> bool;
}

impl AuthRequest for HttpRequest {
    fn user_info(&self) -> Option<User> {
        self.extensions().get::<User>().cloned()
    }

    fn jwt_claims(&self) -> Option<Claims> {
        self.extensions().get::<Claims>().cloned()
    }

    fn jwt_id(&self) -> Option<String> {
        self.jwt_claims().map(|claims| claims.jti)
    }

    fn has_group(&self, group: &str) -> bool {
        self.user_info()
            .map(|info| info.roles.contains(&group.to_string()))
            .unwrap_or(false)
    }

    fn is_authenticated(&self) -> bool {
        self.user_info().is_some()
    }
}

// JWT Authentication Middleware
pub struct JwtAuthMiddlewareFactory;

impl<S, B> Transform<S, ServiceRequest> for JwtAuthMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct JwtAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
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
        let user_services_data = req.app_data::<Data<UserServices>>().cloned();
        let config_data = req.app_data::<Data<ValidatedConfig>>().cloned();
        let is_logout_request =
            req.path() == "/login/logout-api" && req.method() == actix_web::http::Method::POST;
        let service = self.service.clone();

        Box::pin(async move {
            let mut refresh_cookie: Option<actix_web::cookie::Cookie> = None;

            if let (Some(user_services), Some(config)) = (user_services_data, config_data) {
                // Proceed only if local authentication is configured
                if let Some(local_config) = config.users.local() {
                    let cookie_name = &local_config.jwt.cookie_name;
                    if let Some(cookie) = req.cookie(cookie_name) {
                        let token_str = cookie.value();

                        // First validate the JWT and get claims
                        if let Some(jwt_service) = user_services.get_ref().jwt_service()
                            && let Ok(claims) = jwt_service.verify_token(token_str)
                            && let Some(user) = user_services.get_ref().validate_jwt_claims(&claims)
                        {
                            req.extensions_mut().insert(user);
                            req.extensions_mut().insert(claims.clone());

                            // Check if token should be refreshed
                            if !is_logout_request && jwt_service.should_refresh_token(&claims) {
                                match jwt_service.create_refreshed_token(&claims) {
                                    Ok(new_token) => {
                                        // Create new cookie with refreshed token
                                        refresh_cookie =
                                            Some(jwt_service.create_auth_cookie(&new_token));
                                        log::debug!(
                                            "JWT token refreshed for user: {}",
                                            claims.sub
                                        );
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "Failed to create refreshed token for user {}: {}",
                                            claims.sub,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut res = service.call(req).await?;

            // Set the refresh cookie if one was generated
            if let Some(cookie) = refresh_cookie {
                res.response_mut().add_cookie(&cookie).map_err(|e| {
                    log::error!("Failed to set refresh cookie: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to set refresh cookie")
                })?;
            }

            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::store::MemoryUserStore;
    use crate::iam::types::{DEFAULT_PASSWORD_VERSION, User};
    use crate::util::test_config::TestConfigBuilder;
    use actix_http::Request;
    use actix_web::body::BoxBody;
    use actix_web::dev::ServiceResponse;
    use actix_web::{App, HttpResponse, test, web};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::Value;
    use std::sync::Arc;

    async fn test_endpoint(req: HttpRequest) -> Result<HttpResponse, Error> {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "has_user": req.user_info().is_some(),
            "has_claims": req.jwt_claims().is_some()
        })))
    }

    fn build_user(email: &str, password_version: u32) -> User {
        User {
            email: email.to_string(),
            name: "Test User".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version,
        }
    }

    fn build_token(
        config: &ValidatedConfig,
        email: &str,
        password_version: u32,
        iat: i64,
        exp: i64,
    ) -> String {
        let jwt = config.users.local().expect("local auth config");
        let claims = Claims {
            sub: email.to_string(),
            name: "Test User".to_string(),
            groups: vec!["admin".to_string()],
            iat,
            exp,
            iss: jwt.jwt.issuer.clone(),
            aud: jwt.jwt.audience.clone(),
            jti: "test-jti".to_string(),
            password_version,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt.jwt.secret.as_ref()),
        )
        .expect("encode token")
    }

    async fn call_with_token<S>(
        app: &S,
        config: &ValidatedConfig,
        token: &str,
    ) -> ServiceResponse<BoxBody>
    where
        S: actix_web::dev::Service<Request, Response = ServiceResponse<BoxBody>, Error = Error>,
    {
        let cookie_name = &config
            .users
            .local()
            .expect("local auth config")
            .jwt
            .cookie_name;
        let cookie = actix_web::cookie::Cookie::build(cookie_name.clone(), token.to_string())
            .path("/")
            .finish();
        let req = test::TestRequest::get()
            .uri("/test")
            .cookie(cookie)
            .to_request();
        test::call_service(app, req).await
    }

    #[actix_web::test]
    async fn jwt_middleware_skips_claims_when_user_missing() {
        let config = TestConfigBuilder::new().build();
        let store = Arc::new(MemoryUserStore::new(Default::default()));
        let user_services = UserServices::new_with_store(&config, store).expect("user services");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config.clone()))
                .app_data(web::Data::new(user_services))
                .wrap(JwtAuthMiddlewareFactory)
                .route("/test", web::get().to(test_endpoint)),
        )
        .await;

        let now = Utc::now();
        let token = build_token(
            &config,
            "missing@example.com",
            DEFAULT_PASSWORD_VERSION,
            now.timestamp(),
            (now + Duration::hours(12)).timestamp(),
        );
        let resp = call_with_token(&app, &config, &token).await;
        assert!(resp.status().is_success());

        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["has_user"], false);
        assert_eq!(body["has_claims"], false);
    }

    #[actix_web::test]
    async fn jwt_middleware_sets_refresh_cookie_for_old_token() {
        let config = TestConfigBuilder::new().build();
        let user = build_user("user@example.com", DEFAULT_PASSWORD_VERSION);
        let store = Arc::new(MemoryUserStore::from_users(vec![user]));
        let user_services = UserServices::new_with_store(&config, store).expect("user services");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config.clone()))
                .app_data(web::Data::new(user_services))
                .wrap(JwtAuthMiddlewareFactory)
                .route("/test", web::get().to(test_endpoint)),
        )
        .await;

        let now = Utc::now();
        let token = build_token(
            &config,
            "user@example.com",
            DEFAULT_PASSWORD_VERSION,
            (now - Duration::hours(2)).timestamp(),
            (now + Duration::hours(10)).timestamp(),
        );
        let resp = call_with_token(&app, &config, &token).await;
        assert!(resp.status().is_success());
        assert!(resp.headers().contains_key("set-cookie"));
    }

    #[actix_web::test]
    async fn jwt_middleware_does_not_refresh_fresh_token() {
        let config = TestConfigBuilder::new().build();
        let user = build_user("user@example.com", DEFAULT_PASSWORD_VERSION);
        let store = Arc::new(MemoryUserStore::from_users(vec![user]));
        let user_services = UserServices::new_with_store(&config, store).expect("user services");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config.clone()))
                .app_data(web::Data::new(user_services))
                .wrap(JwtAuthMiddlewareFactory)
                .route("/test", web::get().to(test_endpoint)),
        )
        .await;

        let now = Utc::now();
        let token = build_token(
            &config,
            "user@example.com",
            DEFAULT_PASSWORD_VERSION,
            now.timestamp(),
            (now + Duration::hours(12)).timestamp(),
        );
        let resp = call_with_token(&app, &config, &token).await;
        assert!(resp.status().is_success());
        assert!(!resp.headers().contains_key("set-cookie"));
    }
}
