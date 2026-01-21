// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::ValidatedConfig;
use crate::public::page_meta_cache::PageMetaCache;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_SECURITY_POLICY, HeaderMap, HeaderName, HeaderValue,
    PRAGMA, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use actix_web::{Error, HttpMessage, HttpRequest};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::future::{Ready, ok};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

const PUBLIC_ASSET_CACHE_CONTROL: &str = "public, max-age=86400";
const STATIC_HTML_CACHE_CONTROL: &str = "public, s-maxage=300, max-age=0, must-revalidate, stale-while-revalidate=30, stale-if-error=86400";
const DYNAMIC_CACHE_CONTROL: &str = "no-cache, no-store, must-revalidate";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheDirective {
    Default,
    StaticHtml,
    NoStore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderOverride {
    Default,
    // Reserved for per-route header customization.
    #[allow(dead_code)]
    Override(HeaderValue),
    #[allow(dead_code)]
    Disable,
}

#[derive(Clone, Debug)]
pub struct HeaderDirectives {
    pub cache: CacheDirective,
    pub content_security_policy: HeaderOverride,
    pub frame_options: HeaderOverride,
    pub content_type_options: HeaderOverride,
    pub referrer_policy: HeaderOverride,
    pub permissions_policy: HeaderOverride,
    pub strict_transport_security: HeaderOverride,
    pub accept_ranges: HeaderOverride,
}

impl Default for HeaderDirectives {
    fn default() -> Self {
        Self {
            cache: CacheDirective::Default,
            content_security_policy: HeaderOverride::Default,
            frame_options: HeaderOverride::Default,
            content_type_options: HeaderOverride::Default,
            referrer_policy: HeaderOverride::Default,
            permissions_policy: HeaderOverride::Default,
            strict_transport_security: HeaderOverride::Default,
            accept_ranges: HeaderOverride::Default,
        }
    }
}

pub fn update_header_directives(req: &HttpRequest, update: impl FnOnce(&mut HeaderDirectives)) {
    let mut extensions = req.extensions_mut();
    if let Some(existing) = extensions.get_mut::<HeaderDirectives>() {
        update(existing);
    } else {
        let mut directives = HeaderDirectives::default();
        update(&mut directives);
        extensions.insert(directives);
    }
}

pub fn set_cache_directive(req: &HttpRequest, directive: CacheDirective) {
    update_header_directives(req, |directives| {
        directives.cache = directive;
    });
}

pub fn generate_csp_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn set_strict_csp(req: &HttpRequest, nonce: &str) {
    let policy = format!(
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'nonce-{}'; script-src 'self' 'nonce-{}' 'wasm-unsafe-eval'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';",
        nonce, nonce
    );
    if let Ok(value) = HeaderValue::from_str(&policy) {
        update_header_directives(req, |directives| {
            directives.content_security_policy = HeaderOverride::Override(value);
        });
    } else {
        log::warn!("Failed to build strict CSP header");
    }
}

pub struct Headers {
    config: Arc<ValidatedConfig>,
    cache: Arc<PageMetaCache>,
}

impl Headers {
    pub fn new(config: Arc<ValidatedConfig>, cache: Arc<PageMetaCache>) -> Self {
        Headers { config, cache }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Headers
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = HeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(HeadersMiddleware {
            service: Arc::new(service),
            config: self.config.clone(),
            cache: self.cache.clone(),
        })
    }
}

pub struct HeadersMiddleware<S> {
    service: Arc<S>,
    config: Arc<ValidatedConfig>,
    cache: Arc<PageMetaCache>,
}

impl<S, B> Service<ServiceRequest> for HeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        let config = self.config.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            let mut res = fut.await?;

            let directives = res
                .request()
                .extensions()
                .get::<HeaderDirectives>()
                .cloned()
                .unwrap_or_default();

            // X-Content-Type-Options: nosniff
            apply_header_override(
                res.headers_mut(),
                X_CONTENT_TYPE_OPTIONS,
                &directives.content_type_options,
                Some(HeaderValue::from_static("nosniff")),
            );

            // X-Frame-Options: SAMEORIGIN
            apply_header_override(
                res.headers_mut(),
                X_FRAME_OPTIONS,
                &directives.frame_options,
                Some(HeaderValue::from_static("SAMEORIGIN")),
            );

            // Referrer-Policy
            apply_header_override(
                res.headers_mut(),
                HeaderName::from_static("referrer-policy"),
                &directives.referrer_policy,
                Some(HeaderValue::from_static("strict-origin-when-cross-origin")),
            );

            // Permissions-Policy
            apply_header_override(
                res.headers_mut(),
                HeaderName::from_static("permissions-policy"),
                &directives.permissions_policy,
                Some(HeaderValue::from_static(
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), xr-spatial-tracking=()",
                )),
            );

            // Content-Security-Policy (Basic default - consider making this configurable)
            // This is a very restrictive basic policy. You'll likely need to expand it based on your site's needs (e.g., for inline styles/scripts if any, CDNs, etc.)
            apply_header_override(
                res.headers_mut(),
                CONTENT_SECURITY_POLICY,
                &directives.content_security_policy,
                Some(HeaderValue::from_static(
                    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';",
                )),
            );

            // HTTP Strict Transport Security (HSTS)
            let default_hsts = if config.security.hsts_enabled {
                let mut hsts_val = format!("max-age={}", config.security.hsts_max_age);
                if config.security.hsts_include_subdomains {
                    hsts_val.push_str("; includeSubDomains");
                }
                if config.security.hsts_preload {
                    hsts_val.push_str("; preload");
                }
                HeaderValue::from_str(&hsts_val).ok()
            } else {
                None
            };
            apply_header_override(
                res.headers_mut(),
                STRICT_TRANSPORT_SECURITY,
                &directives.strict_transport_security,
                default_hsts,
            );

            // Accept-Ranges: bytes
            apply_header_override(
                res.headers_mut(),
                ACCEPT_RANGES,
                &directives.accept_ranges,
                Some(HeaderValue::from_static("bytes")),
            );

            // Cache-Control headers based on content access requirements
            let cache_directive = directives.cache;
            let path = res.request().path();
            let is_admin_path = path.starts_with(&config.admin.path);
            let is_admin_builtin = path.starts_with("/builtin/admin/");

            if is_admin_path || is_admin_builtin {
                apply_no_cache_headers(&mut res);
            } else {
                match cache_directive {
                    CacheDirective::NoStore => apply_no_cache_headers(&mut res),
                    CacheDirective::StaticHtml => {
                        if is_public_content(&res, &cache, &config) {
                            apply_static_html_cache_headers(&mut res);
                        } else {
                            apply_no_cache_headers(&mut res);
                        }
                    }
                    CacheDirective::Default => {
                        if is_public_content(&res, &cache, &config) {
                            res.headers_mut().insert(
                                CACHE_CONTROL,
                                HeaderValue::from_static(PUBLIC_ASSET_CACHE_CONTROL),
                            );
                        } else {
                            apply_no_cache_headers(&mut res);
                        }
                    }
                }
            }

            Ok(res)
        })
    }
}

fn apply_static_html_cache_headers<B>(res: &mut ServiceResponse<B>) {
    res.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static(STATIC_HTML_CACHE_CONTROL),
    );
}

fn apply_no_cache_headers<B>(res: &mut ServiceResponse<B>) {
    res.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static(DYNAMIC_CACHE_CONTROL),
    );
    res.headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

fn apply_header_override(
    headers: &mut HeaderMap,
    header_name: HeaderName,
    directive: &HeaderOverride,
    default_value: Option<HeaderValue>,
) {
    match directive {
        HeaderOverride::Default => {
            if let Some(value) = default_value {
                headers.insert(header_name, value);
            } else {
                headers.remove(header_name);
            }
        }
        HeaderOverride::Override(value) => {
            headers.insert(header_name, value.clone());
        }
        HeaderOverride::Disable => {
            headers.remove(header_name);
        }
    }
}

/// Determine if the content being served is public (doesn't require authentication)
fn is_public_content<B>(
    res: &ServiceResponse<B>,
    cache: &PageMetaCache,
    config: &ValidatedConfig,
) -> bool {
    // Get the request path from the response
    let path = res.request().path();

    // Admin paths are never public
    if path.starts_with(&config.admin.path) {
        return false;
    }

    // Login paths are public
    if path.starts_with("/login") {
        return true;
    }

    // Theme assets are public
    if path.starts_with("/theme/") {
        return true;
    }

    // Builtin assets (CSS, JS, etc.) are public
    if path.starts_with("/builtin/") {
        return true;
    }

    let alias = determine_alias(path);
    if alias.is_empty() {
        return false;
    }

    match cache.resolved_roles(&alias) {
        Some(crate::public::page_meta_cache::ResolvedRoles::Public) => true,
        Some(crate::public::page_meta_cache::ResolvedRoles::Restricted(_)) => false,
        Some(crate::public::page_meta_cache::ResolvedRoles::Deny) => false,
        None => false,
    }
}

/// Convert a request path to an alias used by the cache.
fn determine_alias(path: &str) -> String {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return "index".to_string();
    }

    crate::content::flat_storage::canonicalize_alias(path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };
    use crate::runtime_paths::RuntimePaths;
    use crate::util::test_config::test_config;
    use crate::util::test_fixtures::TestFixtureRoot;
    use actix_web::{App, HttpRequest, HttpResponse, test, web};
    use std::fs;

    struct CacheHarness {
        _fixture: TestFixtureRoot,
        cache: Arc<PageMetaCache>,
    }

    fn write_object(
        runtime_paths: &RuntimePaths,
        content_id: ContentId,
        alias: &str,
        tags: Vec<String>,
    ) {
        let content_version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, content_version);
        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent).expect("create shard dir");
        }
        fs::write(&blob, b"test").expect("write blob");
        let sidecar = ContentSidecar {
            alias: alias.to_string(),
            title: Some(alias.to_string()),
            mime: "text/markdown".to_string(),
            tags,
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            theme: None,
        };
        let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, content_version);
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
    }

    async fn build_cache() -> CacheHarness {
        let fixture = TestFixtureRoot::new_unique("headers-cache").expect("fixture root");
        fixture.init_runtime_layout().expect("runtime layout");
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");

        let tags_yaml = r#"members:
  name: members
  roles:
    - members
"#;
        fs::write(runtime_paths.state_sys_dir.join("tags.yaml"), tags_yaml).expect("write tags");

        write_object(&runtime_paths, ContentId(1), "about", Vec::new());
        write_object(
            &runtime_paths,
            ContentId(2),
            "secret",
            vec!["members".to_string()],
        );

        let cache = Arc::new(PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            crate::content::reserved_paths::ReservedPaths::default(),
        ));
        cache.rebuild_cache(true).await.expect("cache rebuild");

        CacheHarness {
            _fixture: fixture,
            cache,
        }
    }

    async fn handler_default() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    async fn handler_static(req: HttpRequest) -> HttpResponse {
        set_cache_directive(&req, CacheDirective::StaticHtml);
        HttpResponse::Ok().finish()
    }

    async fn handler_no_store(req: HttpRequest) -> HttpResponse {
        set_cache_directive(&req, CacheDirective::NoStore);
        HttpResponse::Ok().finish()
    }

    async fn handler_disable_csp(req: HttpRequest) -> HttpResponse {
        update_header_directives(&req, |directives| {
            directives.content_security_policy = HeaderOverride::Disable;
        });
        HttpResponse::Ok().finish()
    }

    async fn handler_override_frame(req: HttpRequest) -> HttpResponse {
        update_header_directives(&req, |directives| {
            directives.frame_options = HeaderOverride::Override(HeaderValue::from_static("DENY"));
        });
        HttpResponse::Ok().finish()
    }

    async fn handler_strict_csp(req: HttpRequest) -> HttpResponse {
        set_strict_csp(&req, "nonce-test");
        HttpResponse::Ok().finish()
    }

    #[actix_web::test]
    async fn test_cache_control_static_html_public() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/about", web::get().to(handler_static)),
        )
        .await;

        let req = test::TestRequest::get().uri("/about").to_request();
        let resp = test::call_service(&app, req).await;
        let cache_control = resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap();
        assert_eq!(cache_control, STATIC_HTML_CACHE_CONTROL);
    }

    #[actix_web::test]
    async fn test_default_security_headers() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/about", web::get().to(handler_default)),
        )
        .await;

        let req = test::TestRequest::get().uri("/about").to_request();
        let resp = test::call_service(&app, req).await;
        let referrer = resp
            .headers()
            .get(HeaderName::from_static("referrer-policy"))
            .unwrap()
            .to_str()
            .unwrap();
        let permissions = resp
            .headers()
            .get(HeaderName::from_static("permissions-policy"))
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(referrer, "strict-origin-when-cross-origin");
        assert!(permissions.contains("geolocation=()"));
        assert!(permissions.contains("microphone=()"));
    }

    #[actix_web::test]
    async fn test_strict_csp_override() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/about", web::get().to(handler_strict_csp)),
        )
        .await;

        let req = test::TestRequest::get().uri("/about").to_request();
        let resp = test::call_service(&app, req).await;
        let csp = resp
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();

        assert!(csp.contains("'nonce-nonce-test'"));
        assert!(csp.contains("'wasm-unsafe-eval'"));
        assert!(!csp.contains("unsafe-inline"));
    }

    #[actix_web::test]
    async fn test_cache_control_no_store_directive() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/about", web::get().to(handler_no_store)),
        )
        .await;

        let req = test::TestRequest::get().uri("/about").to_request();
        let resp = test::call_service(&app, req).await;
        let cache_control = resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap();
        let pragma = resp.headers().get(PRAGMA).unwrap().to_str().unwrap();
        assert_eq!(cache_control, DYNAMIC_CACHE_CONTROL);
        assert_eq!(pragma, "no-cache");
    }

    #[actix_web::test]
    async fn test_cache_control_default_public_asset() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/theme/app.css", web::get().to(handler_default)),
        )
        .await;

        let req = test::TestRequest::get().uri("/theme/app.css").to_request();
        let resp = test::call_service(&app, req).await;
        let cache_control = resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap();
        assert_eq!(cache_control, PUBLIC_ASSET_CACHE_CONTROL);
    }

    #[actix_web::test]
    async fn test_cache_control_default_private_content() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/secret", web::get().to(handler_default)),
        )
        .await;

        let req = test::TestRequest::get().uri("/secret").to_request();
        let resp = test::call_service(&app, req).await;
        let cache_control = resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap();
        let pragma = resp.headers().get(PRAGMA).unwrap().to_str().unwrap();
        assert_eq!(cache_control, DYNAMIC_CACHE_CONTROL);
        assert_eq!(pragma, "no-cache");
    }

    #[actix_web::test]
    async fn test_cache_control_admin_forces_no_store() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/admin/dashboard", web::get().to(handler_static)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/admin/dashboard")
            .to_request();
        let resp = test::call_service(&app, req).await;
        let cache_control = resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap();
        assert_eq!(cache_control, DYNAMIC_CACHE_CONTROL);
    }

    #[actix_web::test]
    async fn test_header_override_disables_csp() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/about", web::get().to(handler_disable_csp)),
        )
        .await;

        let req = test::TestRequest::get().uri("/about").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.headers().get(CONTENT_SECURITY_POLICY).is_none());
    }

    #[actix_web::test]
    async fn test_header_override_sets_frame_options() {
        let config = Arc::new(test_config());
        let harness = build_cache().await;
        let cache = harness.cache.clone();
        let app = test::init_service(
            App::new()
                .wrap(Headers::new(config, cache))
                .route("/about", web::get().to(handler_override_frame)),
        )
        .await;

        let req = test::TestRequest::get().uri("/about").to_request();
        let resp = test::call_service(&app, req).await;
        let frame_options = resp
            .headers()
            .get(X_FRAME_OPTIONS)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(frame_options, "DENY");
    }
}
