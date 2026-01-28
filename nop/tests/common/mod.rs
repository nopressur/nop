// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#![allow(dead_code)]

pub mod ws;

use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{App, HttpRequest, HttpResponse, Result, web};
use nop::admin;
use nop::api;
use nop::app_state::AppState;
use nop::builtin;
use nop::config::{
    AdminConfig, AppConfig, JwtConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
    PasswordHashingParams, RenderingConfig, SecurityConfig, ServerConfig, ServerListenerConfig,
    ServerProtocol, ServerRole, ShortcodeConfig, StreamingConfig, UploadConfig, ValidatedConfig,
    ValidatedLocalAuthConfig, ValidatedUsersConfig,
};
use nop::headers;
use nop::iam::UserServices;
use nop::iam::middleware::JwtAuthMiddlewareFactory;
use nop::iam::{PasswordProviderBlock, User, build_password_provider_block};
use nop::login;
use nop::management::{ManagementBus, ManagementContext, UploadRegistry, build_default_registry};
use nop::public;
use nop::public::page_meta_cache::PageMetaCache;
use nop::public::shortcode::create_default_registry_with_config;
use nop::runtime_paths::RuntimePaths;
use nop::util::CsrfValidationMiddlewareFactory;
use nop::util::csrf_validation::CSRF_HEADER_NAME;
use nop::util::test_fixtures::TestFixtureRoot;
use nop::util::{CsrfTokenStore, ReleaseTracker, WsTicketStore};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

pub const ADMIN_EMAIL: &str = "admin@example.com";
const ADMIN_NAME: &str = "Admin User";
const ADMIN_PASSWORD: &str = "admin-password";

pub struct TestHarness {
    pub fixture: TestFixtureRoot,
    pub config: Arc<ValidatedConfig>,
    pub runtime_paths: RuntimePaths,
    pub app_state: Arc<AppState>,
    pub page_cache: Arc<PageMetaCache>,
    pub user_services: Arc<UserServices>,
    pub csrf_store: Arc<CsrfTokenStore>,
    pub ws_ticket_store: Arc<WsTicketStore>,
    pub release_tracker: Arc<ReleaseTracker>,
    pub shortcode_registry: Arc<nop::public::shortcode::ShortcodeRegistry>,
    pub admin_user: User,
    pub admin_password_plaintext: String,
}

pub struct AuthSession {
    pub user: User,
    pub jwt_token: String,
    pub jwt_id: String,
    pub cookie: actix_web::cookie::Cookie<'static>,
    pub csrf_token: String,
}

#[derive(Clone)]
pub struct AppBundle {
    pub config: Arc<ValidatedConfig>,
    pub app_state: Arc<AppState>,
    pub page_cache: Arc<PageMetaCache>,
    pub user_services: Arc<UserServices>,
    pub csrf_store: Arc<CsrfTokenStore>,
    pub ws_ticket_store: Arc<WsTicketStore>,
    pub release_tracker: Arc<ReleaseTracker>,
    pub shortcode_registry: Arc<nop::public::shortcode::ShortcodeRegistry>,
    pub admin_path: String,
}

impl TestHarness {
    pub async fn new() -> Self {
        let fixture = TestFixtureRoot::new_unique("api-test-suite").expect("fixture root");
        fixture.init_runtime_layout().expect("fixture layout");

        let config = Arc::new(build_config());
        let admin_password_plaintext = ADMIN_PASSWORD.to_string();
        let password_params = config
            .users
            .local()
            .expect("local auth config")
            .password
            .clone();
        let admin_password_block =
            build_password_provider_block(&admin_password_plaintext, &password_params)
                .expect("password block");
        let admin_user = User {
            email: ADMIN_EMAIL.to_string(),
            name: ADMIN_NAME.to_string(),
            password: Some(admin_password_block.clone()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: 1,
        };

        seed_config_files(&fixture, &admin_password_block);

        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        seed_content(&runtime_paths);
        seed_themes(&fixture);

        let page_cache = Arc::new(PageMetaCache::new(
            runtime_paths.content_dir.clone(),
            runtime_paths.state_sys_dir.clone(),
            nop::content::reserved_paths::ReservedPaths::from_config(&config),
        ));
        page_cache.rebuild_cache(true).await.expect("cache rebuild");

        let mut user_services =
            UserServices::new(&config, runtime_paths.users_file.clone()).expect("user services");
        user_services.set_page_cache(page_cache.clone());
        let user_services = Arc::new(user_services);

        let upload_registry = Arc::new(UploadRegistry::new());
        let management_bus = build_management_bus(
            &config,
            &runtime_paths,
            user_services.clone(),
            page_cache.clone(),
            upload_registry.clone(),
        );
        let app_state = Arc::new(AppState::new(
            &config.app.name,
            runtime_paths.clone(),
            management_bus,
            upload_registry,
        ));
        let release_tracker = Arc::new(ReleaseTracker::new());
        let shortcode_registry = Arc::new(create_default_registry_with_config(
            &config,
            &release_tracker,
            app_state.templates.clone(),
        ));
        app_state
            .runtime_paths
            .ensure_shortcode_dirs(&shortcode_registry.registered_names())
            .expect("shortcode dirs");

        let csrf_store = Arc::new(CsrfTokenStore::new(&config));
        let ws_ticket_store = Arc::new(WsTicketStore::new());

        Self {
            fixture,
            config,
            runtime_paths,
            app_state,
            page_cache,
            user_services,
            csrf_store,
            ws_ticket_store,
            release_tracker,
            shortcode_registry,
            admin_user,
            admin_password_plaintext,
        }
    }

    pub fn admin_auth(&self) -> AuthSession {
        let jwt_service = self.user_services.jwt_service().expect("jwt service");
        let token = jwt_service
            .create_token(&self.admin_user.email, &self.admin_user)
            .expect("jwt token");
        let claims = jwt_service.verify_token(&token).expect("jwt claims");
        let cookie = jwt_service.create_auth_cookie(&token).into_owned();
        let csrf_token = self.csrf_store.get_or_refresh_token(&claims.jti);

        AuthSession {
            user: self.admin_user.clone(),
            jwt_token: token,
            jwt_id: claims.jti,
            cookie,
            csrf_token,
        }
    }

    pub fn app_bundle(&self) -> AppBundle {
        AppBundle {
            config: self.config.clone(),
            app_state: self.app_state.clone(),
            page_cache: self.page_cache.clone(),
            user_services: self.user_services.clone(),
            csrf_store: self.csrf_store.clone(),
            ws_ticket_store: self.ws_ticket_store.clone(),
            release_tracker: self.release_tracker.clone(),
            shortcode_registry: self.shortcode_registry.clone(),
            admin_path: self.config.admin.path.clone(),
        }
    }
}

fn build_management_bus(
    config: &Arc<ValidatedConfig>,
    runtime_paths: &RuntimePaths,
    user_services: Arc<UserServices>,
    page_cache: Arc<PageMetaCache>,
    upload_registry: Arc<UploadRegistry>,
) -> ManagementBus {
    let registry = build_default_registry().expect("management registry");
    let context = ManagementContext::from_components_with_user_services_and_cache(
        runtime_paths.root.clone(),
        config.clone(),
        runtime_paths.clone(),
        Some(user_services),
        Some(page_cache),
    )
    .expect("management context");
    let context = context.with_upload_registry(upload_registry);
    ManagementBus::start(registry, context)
}

pub fn build_test_app(
    bundle: AppBundle,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let admin_path = bundle.admin_path;
    let config_for_app = bundle.config.clone();
    let config_for_security = bundle.config.clone();
    let config_for_admin = bundle.config.clone();
    let config_for_login = bundle.config.clone();

    App::new()
        .app_data(web::Data::from(config_for_app))
        .app_data(web::Data::from(bundle.app_state))
        .app_data(web::Data::from(bundle.user_services))
        .app_data(web::Data::from(bundle.page_cache.clone()))
        .app_data(web::Data::from(bundle.shortcode_registry))
        .app_data(web::Data::from(bundle.csrf_store))
        .app_data(web::Data::from(bundle.ws_ticket_store))
        .app_data(web::Data::from(bundle.release_tracker))
        .wrap(headers::Headers::new(
            config_for_security,
            bundle.page_cache,
        ))
        .wrap(CsrfValidationMiddlewareFactory)
        .wrap(JwtAuthMiddlewareFactory)
        .configure(move |cfg| admin::configure(cfg, &admin_path, &config_for_admin))
        .configure(move |cfg| login::configure(cfg, &config_for_login))
        .configure(api::configure)
        .configure(builtin::configure)
        .configure(public::configure)
        .default_service(web::route().to(test_default_not_found))
}

async fn test_default_not_found(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse> {
    nop::public::error::serve_404_for_request(
        &req,
        &app_state.error_renderer,
        Some(app_state.templates.as_ref()),
    )
}

pub fn add_auth_headers(
    req: actix_web::test::TestRequest,
    session: &AuthSession,
    include_csrf: bool,
) -> actix_web::test::TestRequest {
    let req = req.cookie(session.cookie.clone());
    if include_csrf {
        req.insert_header((CSRF_HEADER_NAME, session.csrf_token.clone()))
    } else {
        req
    }
}

fn build_config() -> ValidatedConfig {
    ValidatedConfig {
        servers: vec![ServerListenerConfig {
            name: Some("main".to_string()),
            role: ServerRole::Main,
            host: "127.0.0.1".to_string(),
            port: 8081,
            protocol: ServerProtocol::Http,
        }],
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8081,
            http_port: None,
            workers: 1,
        },
        admin: AdminConfig {
            path: "/admin".to_string(),
        },
        users: ValidatedUsersConfig::Local(ValidatedLocalAuthConfig {
            jwt: JwtConfig {
                secret: "test-secret".to_string(),
                issuer: "nopressure".to_string(),
                audience: "nopressure-users".to_string(),
                expiration_hours: 12,
                cookie_name: "nop_auth".to_string(),
                disable_refresh: false,
                refresh_threshold_percentage: 10,
                refresh_threshold_hours: 24,
            },
            password: PasswordHashingParams::default(),
        }),
        navigation: NavigationConfig {
            max_dropdown_items: 7,
        },
        logging: LoggingConfig {
            level: "info".to_string(),
            rotation: LoggingRotationConfig::default(),
        },
        security: SecurityConfig {
            max_violations: 10,
            cooldown_seconds: 60,
            use_forwarded_for: false,
            login_sessions: nop::config::LoginSessionConfig::default(),
            hsts_enabled: false,
            hsts_max_age: 31536000,
            hsts_include_subdomains: true,
            hsts_preload: false,
        },
        tls: None,
        app: AppConfig {
            name: "Test App".to_string(),
            description: "Test Description".to_string(),
        },
        upload: UploadConfig {
            max_file_size_mb: 25,
            allowed_extensions: vec![
                "jpg".to_string(),
                "png".to_string(),
                "md".to_string(),
                "txt".to_string(),
                "bin".to_string(),
            ],
        },
        streaming: StreamingConfig { enabled: true },
        shortcodes: ShortcodeConfig::default(),
        rendering: RenderingConfig::default(),
        dev_mode: None,
    }
}

fn seed_config_files(fixture: &TestFixtureRoot, admin_password_block: &PasswordProviderBlock) {
    let config_path = fixture.path().join("config.yaml");
    let users_path = fixture.path().join("users.yaml");

    let _ = fs::write(
        &config_path,
        "# test config (integration tests own the config struct)\n",
    );

    let mut users = HashMap::new();
    users.insert(
        ADMIN_EMAIL.to_string(),
        serde_yaml::Value::Mapping({
            let mut map = serde_yaml::Mapping::new();
            map.insert(
                serde_yaml::Value::String("name".to_string()),
                serde_yaml::Value::String(ADMIN_NAME.to_string()),
            );
            let mut password_map = serde_yaml::Mapping::new();
            password_map.insert(
                serde_yaml::Value::String("front_end_salt".to_string()),
                serde_yaml::Value::String(admin_password_block.front_end_salt.clone()),
            );
            password_map.insert(
                serde_yaml::Value::String("back_end_salt".to_string()),
                serde_yaml::Value::String(admin_password_block.back_end_salt.clone()),
            );
            password_map.insert(
                serde_yaml::Value::String("stored_hash".to_string()),
                serde_yaml::Value::String(admin_password_block.stored_hash.clone()),
            );
            map.insert(
                serde_yaml::Value::String("password".to_string()),
                serde_yaml::Value::Mapping(password_map),
            );
            map.insert(
                serde_yaml::Value::String("password_version".to_string()),
                serde_yaml::Value::Number(1.into()),
            );
            map.insert(
                serde_yaml::Value::String("roles".to_string()),
                serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("admin".to_string())]),
            );
            map
        }),
    );

    let yaml = serde_yaml::to_string(&users).expect("users yaml");
    fs::write(&users_path, yaml).expect("users file");
}

fn seed_content(runtime_paths: &RuntimePaths) {
    use nop::content::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
    };

    let tags_yaml = r#"admin:
  name: admin
  roles:
    - admin
"#;
    fs::write(runtime_paths.state_sys_dir.join("tags.yaml"), tags_yaml).expect("tags");
    fs::write(
        runtime_paths.state_sys_dir.join("roles.yaml"),
        "- admin\n- editor\n- writer\n",
    )
    .expect("roles");

    fn write_object(
        runtime_paths: &RuntimePaths,
        content_id: ContentId,
        alias: &str,
        title: Option<&str>,
        mime: &str,
        tags: Vec<String>,
        content: &[u8],
    ) {
        let version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, version);
        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent).expect("create shard dir");
        }
        fs::write(&blob, content).expect("write blob");
        let sidecar = ContentSidecar {
            alias: alias.to_string(),
            title: title.map(|value| value.to_string()),
            mime: mime.to_string(),
            tags,
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            theme: None,
        };
        let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, version);
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
    }

    write_object(
        runtime_paths,
        ContentId(1),
        "index",
        Some("Home"),
        "text/markdown",
        Vec::new(),
        b"# Home\n\nWelcome to the test site.\n",
    );
    write_object(
        runtime_paths,
        ContentId(2),
        "docs/intro",
        Some("Intro"),
        "text/markdown",
        Vec::new(),
        b"# Intro\n\nDocs intro page.\n",
    );
    write_object(
        runtime_paths,
        ContentId(3),
        "secret",
        Some("Secret"),
        "text/markdown",
        vec!["admin".to_string()],
        b"# Secret\n\nHidden page.\n",
    );
    write_object(
        runtime_paths,
        ContentId(4),
        "assets/sample.bin",
        None,
        "application/octet-stream",
        Vec::new(),
        b"abcdefghijklmnopqrstuvwxyz012345",
    );
    write_object(
        runtime_paths,
        ContentId(5),
        "assets/sample.png",
        None,
        "image/png",
        Vec::new(),
        b"\x89PNG\r\n\x1a\nNOP",
    );
    write_object(
        runtime_paths,
        ContentId(6),
        "assets/sample.mp4",
        None,
        "video/mp4",
        Vec::new(),
        b"\x00\x00\x00\x18ftypmp42",
    );
}

fn seed_themes(fixture: &TestFixtureRoot) {
    let themes_dir = fixture.themes_dir();
    let default_theme = r#"<style>
.test-theme { color: #222; }
</style>"#;
    fs::write(themes_dir.join("default.html"), default_theme).expect("default theme");

    let alt_theme = r#"<style>
.alt-theme { color: #3366ff; }
</style>"#;
    fs::write(themes_dir.join("alt.html"), alt_theme).expect("alt theme");
}
