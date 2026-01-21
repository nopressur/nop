// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::ValidatedConfig;
use crate::iam::AuthRequest;
use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::LOCATION,
};
use futures_util::future::LocalBoxFuture;
use std::future::{Ready, ready};
use std::sync::Arc;
use urlencoding;

/// Middleware that requires admin role - redirects to /login if user not authenticated, or to / if authenticated but not admin
pub struct RequireAdminMiddleware {
    config: Arc<ValidatedConfig>,
}

impl RequireAdminMiddleware {
    pub fn new(config: Arc<ValidatedConfig>) -> Self {
        Self { config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireAdminMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RequireAdminMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireAdminMiddlewareService {
            service,
            config: self.config.clone(),
        }))
    }
}

pub struct RequireAdminMiddlewareService<S> {
    service: S,
    config: Arc<ValidatedConfig>,
}

impl<S, B> Service<ServiceRequest> for RequireAdminMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Check for development mode bypass first
        if crate::security::is_dev_mode_bypass_allowed(req.request(), &self.config) {
            log::debug!("🔧 DEV MODE: Bypassing admin authentication");
            let fut = self.service.call(req);
            return Box::pin(async move {
                // Map normal responses to left body
                fut.await.map(ServiceResponse::map_into_left_body)
            });
        }

        // Check if user is authenticated and has admin role
        let is_authenticated = req.request().is_authenticated();
        let has_admin_role = req.request().has_group("admin");

        if !has_admin_role {
            // Create redirect response properly
            let (req, _) = req.into_parts();

            // If user is authenticated but doesn't have admin role, redirect to homepage
            // If user is not authenticated, redirect to login
            let redirect_location = if is_authenticated {
                "/".to_string() // Authenticated non-admin user - go to homepage
            } else {
                // Not authenticated - go to login with return path
                let current_path = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or(req.uri().path());
                format!("/login?return_path={}", urlencoding::encode(current_path))
            };

            let response = HttpResponse::Found()
                .insert_header((LOCATION, redirect_location))
                .finish()
                .map_into_right_body();

            return Box::pin(async move { Ok(ServiceResponse::new(req, response)) });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            // Map normal responses to left body
            fut.await.map(ServiceResponse::map_into_left_body)
        })
    }
}
