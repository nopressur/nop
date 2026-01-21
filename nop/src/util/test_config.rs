// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#![allow(dead_code)]

use crate::config::{
    AdminConfig, AppConfig, DEFAULT_ARGON2_BACK_END_PARAMS, DEFAULT_ARGON2_FRONT_END_PARAMS,
    DevMode, JwtConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
    PasswordHashingParams, RenderingConfig, SecurityConfig, ServerConfig, ServerListenerConfig,
    ServerProtocol, ServerRole, ShortcodeConfig, StreamingConfig, UploadConfig, ValidatedConfig,
    ValidatedLocalAuthConfig, ValidatedUsersConfig,
};

#[derive(Debug, Clone)]
pub struct TestConfigBuilder {
    config: ValidatedConfig,
}

impl Default for TestConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestConfigBuilder {
    pub fn new() -> Self {
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
                    login_sessions: crate::config::LoginSessionConfig::default(),
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
                dev_mode: None,
            },
        }
    }

    pub fn with_dev_mode(mut self, dev_mode: Option<DevMode>) -> Self {
        self.config.dev_mode = dev_mode;
        self
    }

    pub fn with_streaming(mut self, enabled: bool) -> Self {
        self.config.streaming.enabled = enabled;
        self
    }

    pub fn with_admin_path(mut self, path: &str) -> Self {
        self.config.admin.path = path.to_string();
        self
    }

    pub fn build(self) -> ValidatedConfig {
        self.config
    }
}

pub fn test_config() -> ValidatedConfig {
    TestConfigBuilder::new().build()
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
            disable_refresh: false,
            refresh_threshold_percentage: 10,
            refresh_threshold_hours: 24,
        },
        password: PasswordHashingParams {
            front_end: DEFAULT_ARGON2_FRONT_END_PARAMS,
            back_end: DEFAULT_ARGON2_BACK_END_PARAMS,
        },
    })
}
