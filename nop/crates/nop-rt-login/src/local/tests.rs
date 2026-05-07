// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::password::fetch_front_end_salt;
use nop_config::{
    AdminConfig, AppConfig, DEFAULT_ARGON2_BACK_END_PARAMS, DEFAULT_ARGON2_FRONT_END_PARAMS,
    JwtConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig, PasswordHashingParams,
    RenderingConfig, SearchConfig, SecurityConfig, ServerConfig, ServerListenerConfig,
    ServerProtocol, ServerRole, ShortcodeConfig, StreamingConfig, UploadConfig, ValidatedConfig,
    ValidatedLocalAuthConfig, ValidatedUsersConfig,
};
use nop_iam_passwords::build_password_provider_block;
use nop_rt_iam::DEFAULT_PASSWORD_VERSION;
use nop_rt_iam::types::User;
use nop_rt_iam::{MemoryUserStore, UserServices};
use std::sync::Arc;

fn build_test_config() -> ValidatedConfig {
    TestConfigBuilder::new().build()
}

#[derive(Debug, Clone)]
struct TestConfigBuilder {
    config: ValidatedConfig,
}

impl TestConfigBuilder {
    fn new() -> Self {
        Self {
            config: ValidatedConfig {
                servers: build_test_server_list(),
                server: ServerConfig {
                    host: "127.0.0.1".to_string(),
                    port: 5466,
                    http_port: None,
                    workers: 1,
                },
                admin: AdminConfig {
                    path: "/admin".to_string(),
                },
                users: build_test_local_users_config(),
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
                    login_sessions: nop_config::LoginSessionConfig::default(),
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
                    max_file_size_mb: 100,
                    allowed_extensions: vec!["jpg".to_string()],
                },
                streaming: StreamingConfig { enabled: true },
                shortcodes: ShortcodeConfig::default(),
                rendering: RenderingConfig::default(),
                search: SearchConfig::default(),
                dev_mode: None,
            },
        }
    }

    fn build(self) -> ValidatedConfig {
        self.config
    }
}

fn build_test_server_list() -> Vec<ServerListenerConfig> {
    vec![ServerListenerConfig {
        name: Some("main".to_string()),
        role: ServerRole::Main,
        host: "127.0.0.1".to_string(),
        port: 5466,
        protocol: ServerProtocol::Http,
    }]
}

fn build_test_local_users_config() -> ValidatedUsersConfig {
    ValidatedUsersConfig::Local(ValidatedLocalAuthConfig {
        jwt: JwtConfig {
            secret: "test-secret".to_string(),
            issuer: "nopressure".to_string(),
            audience: "nopressure-users".to_string(),
            expiration_hours: 12,
            cookie_name: "nop_auth".to_string(),
            force_secure_cookie: false,
            disable_refresh: false,
            refresh_threshold_percentage: 10,
            refresh_threshold_hours: 24,
        },
        password: PasswordHashingParams {
            front_end: DEFAULT_ARGON2_FRONT_END_PARAMS,
            back_end: DEFAULT_ARGON2_BACK_END_PARAMS,
        },
        password_complexity_enabled: true,
    })
}

fn build_user_services() -> UserServices {
    let config = build_test_config();
    let password = build_password_provider_block(
        "correct-password",
        &config.users.local().expect("local").password,
    )
    .expect("password block");
    let store = Arc::new(MemoryUserStore::from_users(vec![User {
        email: "user@example.com".to_string(),
        name: "User".to_string(),
        password: Some(password),
        legacy_password_hash: None,
        roles: vec!["admin".to_string()],
        password_version: DEFAULT_PASSWORD_VERSION,
    }]));
    UserServices::new_with_store(&config, store).expect("user services")
}

#[actix_web::test]
async fn fetch_front_end_salt_returns_existing_password_salt() {
    let config = build_test_config();
    let user_services = build_user_services();

    let salt = fetch_front_end_salt("user@example.com", &user_services, &config);

    assert!(!salt.is_empty());
}

#[actix_web::test]
async fn fetch_front_end_salt_falls_back_for_unknown_user() {
    let config = build_test_config();
    let user_services = build_user_services();

    let salt = fetch_front_end_salt("missing@example.com", &user_services, &config);

    assert!(!salt.is_empty());
}
