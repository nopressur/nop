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
                        if let Some(jwt_service) = user_services.get_ref().jwt_service() {
                            match jwt_service.verify_token(token_str) {
                                Ok(claims) => {
                                    // Store the claims in request extensions for CSRF token binding
                                    req.extensions_mut().insert(claims.clone());

                                    // Check if user still exists and validate
                                    if let Some(user) =
                                        user_services.get_ref().validate_jwt(token_str).await
                                    {
                                        req.extensions_mut().insert(user);

                                        // Check if token should be refreshed
                                        if !is_logout_request
                                            && jwt_service.should_refresh_token(&claims)
                                        {
                                            match jwt_service.create_refreshed_token(&claims) {
                                                Ok(new_token) => {
                                                    // Create new cookie with refreshed token
                                                    refresh_cookie = Some(
                                                        jwt_service.create_auth_cookie(&new_token),
                                                    );
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
                                Err(_) => {
                                    // Token verification failed, let normal validation handle it
                                    if let Some(user) =
                                        user_services.get_ref().validate_jwt(token_str).await
                                    {
                                        req.extensions_mut().insert(user);
                                    }
                                }
                            }
                        } else {
                            // Fallback to normal validation if JWT service not available
                            if let Some(user) =
                                user_services.get_ref().validate_jwt(token_str).await
                            {
                                req.extensions_mut().insert(user);
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
