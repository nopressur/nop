// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::acme::AcmeTokenStore;
use crate::config::ValidatedConfig;
use crate::public::error;
use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use log::warn;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub type WellKnownHandler =
    Arc<dyn Fn(&str, &HttpRequest, &ValidatedConfig) -> Option<HttpResponse> + Send + Sync>;

pub struct WellKnownRegistry {
    exact: RwLock<HashMap<String, WellKnownHandler>>,
    prefixes: RwLock<Vec<(String, WellKnownHandler)>>,
}

impl WellKnownRegistry {
    pub fn new() -> Self {
        Self {
            exact: RwLock::new(HashMap::new()),
            prefixes: RwLock::new(Vec::new()),
        }
    }

    // Remove once other well-known endpoints register exact handlers.
    #[allow(dead_code)]
    pub fn register_exact(&self, path: impl Into<String>, handler: WellKnownHandler) {
        match self.exact.write() {
            Ok(mut guard) => {
                guard.insert(path.into(), handler);
            }
            Err(_) => {
                warn!("well-known exact handler registry lock poisoned; insert skipped");
            }
        }
    }

    pub fn register_prefix(&self, prefix: impl Into<String>, handler: WellKnownHandler) {
        let prefix = prefix.into();
        match self.prefixes.write() {
            Ok(mut guard) => {
                guard.push((prefix, handler));
                guard.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
            }
            Err(_) => {
                warn!("well-known prefix handler registry lock poisoned; insert skipped");
            }
        }
    }

    // Remove once static well-known endpoints are registered.
    #[allow(dead_code)]
    pub fn register_static(
        &self,
        path: impl Into<String>,
        content_type: &str,
        body: impl Into<String>,
    ) {
        let content_type = content_type.to_string();
        let body = body.into();
        self.register_exact(
            path,
            Arc::new(move |_path, _req, _config| {
                Some(
                    HttpResponse::Ok()
                        .insert_header((header::CONTENT_TYPE, content_type.clone()))
                        .body(body.clone()),
                )
            }),
        );
    }

    fn handle(
        &self,
        path: &str,
        req: &HttpRequest,
        config: &ValidatedConfig,
    ) -> Option<HttpResponse> {
        if let Ok(guard) = self.exact.read() {
            if let Some(handler) = guard.get(path) {
                return handler(path, req, config);
            }
        } else {
            warn!("well-known exact handler registry lock poisoned; lookup skipped");
        }

        if let Ok(guard) = self.prefixes.read() {
            for (prefix, handler) in guard.iter() {
                if path.starts_with(prefix) {
                    return handler(path, req, config);
                }
            }
        } else {
            warn!("well-known prefix handler registry lock poisoned; lookup skipped");
        }

        None
    }
}

pub fn register_acme_http01_handler(registry: &WellKnownRegistry, store: AcmeTokenStore) {
    let handler: WellKnownHandler = Arc::new(move |path, _req, _config| {
        let token = path.strip_prefix("acme-challenge/")?;
        if token.is_empty() || token.contains('/') {
            return None;
        }
        store.get_key_authorization(token).map(|value| {
            HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, "text/plain"))
                .body(value)
        })
    });
    registry.register_prefix("acme-challenge/", handler);
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/.well-known/{path:.*}", web::get().to(serve_well_known))
        .route("/{path:.*}", web::get().to(redirect_to_https));
}

async fn serve_well_known(
    req: HttpRequest,
    path: web::Path<String>,
    config: web::Data<ValidatedConfig>,
    registry: web::Data<WellKnownRegistry>,
) -> Result<HttpResponse> {
    let relative_path = path.into_inner();
    if relative_path.is_empty() {
        return error::serve_404_with_app_name(&config.app.name, None);
    }

    if let Some(response) = registry.handle(&relative_path, &req, &config) {
        return Ok(response);
    }

    error::serve_404_with_app_name(&config.app.name, None)
}

async fn redirect_to_https(req: HttpRequest, config: web::Data<ValidatedConfig>) -> HttpResponse {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let base = config
        .tls
        .as_ref()
        .and_then(|tls| tls.redirect_base_url.as_deref());

    let location = match base {
        Some(base) => format!("{}{}", base.trim_end_matches('/'), path_and_query),
        None => {
            let host = req.connection_info().host().to_string();
            format!("https://{}{}", host, path_and_query)
        }
    };

    HttpResponse::MovedPermanently()
        .insert_header((header::LOCATION, location))
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config,
    };
    use actix_web::http::StatusCode;
    use actix_web::{App, test};

    fn build_test_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: Vec::new(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: test_local_users_config(),
            navigation: NavigationConfig {
                max_dropdown_items: 7,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                rotation: LoggingRotationConfig::default(),
            },
            security: SecurityConfig {
                max_violations: 2,
                cooldown_seconds: 30,
                use_forwarded_for: false,
                login_sessions: crate::config::LoginSessionConfig::default(),
                hsts_enabled: false,
                hsts_max_age: 31536000,
                hsts_include_subdomains: true,
                hsts_preload: false,
            },
            tls: Some(crate::config::TlsConfig {
                mode: crate::config::TlsMode::SelfSigned,
                domains: vec!["example.com".to_string()],
                redirect_base_url: None,
                acme: None,
            }),
            app: AppConfig {
                name: "Test App".to_string(),
                description: "Test Description".to_string(),
            },
            upload: UploadConfig {
                max_file_size_mb: 100,
                allowed_extensions: vec!["jpg".to_string()],
            },
            streaming: StreamingConfig { enabled: true },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            dev_mode: None,
        }
    }

    #[actix_web::test]
    async fn serves_acme_token_from_store() {
        let config_for_app = build_test_config();
        let store = AcmeTokenStore::new();
        store.insert(
            "token123".to_string(),
            "token123.keyauth".to_string(),
            "example.com".to_string(),
        );

        let registry = WellKnownRegistry::new();
        register_acme_http01_handler(&registry, store);

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config_for_app))
                .app_data(web::Data::new(registry))
                .configure(configure),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/.well-known/acme-challenge/token123")
            .to_request();
        let body = test::call_and_read_body(&app, req).await;
        assert_eq!(body, "token123.keyauth");
    }

    #[actix_web::test]
    async fn redirect_uses_base_url_when_configured() {
        let mut config = build_test_config();
        if let Some(tls) = config.tls.as_mut() {
            tls.redirect_base_url = Some("https://example.com".to_string());
        }
        let req = test::TestRequest::get().uri("/docs?x=1").to_http_request();

        let response = redirect_to_https(req, web::Data::new(config)).await;
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "https://example.com/docs?x=1");
    }

    #[actix_web::test]
    async fn redirect_uses_request_host_by_default() {
        let config = build_test_config();
        let req = test::TestRequest::get()
            .uri("/docs")
            .insert_header((header::HOST, "example.net:8080"))
            .to_http_request();

        let response = redirect_to_https(req, web::Data::new(config)).await;
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, "https://example.net:8080/docs");
    }
}
