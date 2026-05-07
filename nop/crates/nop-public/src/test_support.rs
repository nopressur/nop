// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#![allow(dead_code)]

use nop_config::{
    AdminConfig, AppConfig, DEFAULT_ARGON2_BACK_END_PARAMS, DEFAULT_ARGON2_FRONT_END_PARAMS,
    DevMode, JwtConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
    PasswordHashingParams, RenderingConfig, SearchConfig, SecurityConfig, ServerConfig,
    ServerListenerConfig, ServerProtocol, ServerRole, ShortcodeConfig, StreamingConfig,
    UploadConfig, ValidatedConfig, ValidatedLocalAuthConfig, ValidatedUsersConfig,
};
use nop_rt_paths::RuntimePaths;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(crate) struct TestConfigBuilder {
    config: ValidatedConfig,
}

impl Default for TestConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestConfigBuilder {
    pub(crate) fn new() -> Self {
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

    pub(crate) fn with_dev_mode(mut self, dev_mode: Option<DevMode>) -> Self {
        self.config.dev_mode = dev_mode;
        self
    }

    pub(crate) fn with_streaming(mut self, enabled: bool) -> Self {
        self.config.streaming.enabled = enabled;
        self
    }

    pub(crate) fn with_admin_path(mut self, path: &str) -> Self {
        self.config.admin.path = path.to_string();
        self
    }

    pub(crate) fn build(self) -> ValidatedConfig {
        self.config
    }
}

pub(crate) fn test_config() -> ValidatedConfig {
    TestConfigBuilder::new().build()
}

#[derive(Debug)]
pub(crate) struct TestFixtureRoot {
    path: PathBuf,
}

impl TestFixtureRoot {
    pub(crate) fn new_fixed(name: &str) -> std::io::Result<Self> {
        let root = fixtures_root().join(name);
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { path: root })
    }

    pub(crate) fn new_unique(prefix: &str) -> std::io::Result<Self> {
        let name = format!("{}-{}", prefix, Uuid::new_v4());
        Self::new_fixed(&name)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn content_dir(&self) -> PathBuf {
        self.path.join("content")
    }

    pub(crate) fn themes_dir(&self) -> PathBuf {
        self.path.join("themes")
    }

    pub(crate) fn state_dir(&self) -> PathBuf {
        self.path.join("state")
    }

    pub(crate) fn init_runtime_layout(&self) -> std::io::Result<()> {
        fs::create_dir_all(self.content_dir())?;
        fs::create_dir_all(self.themes_dir())?;
        fs::create_dir_all(self.state_dir().join("sys"))?;
        fs::create_dir_all(self.state_dir().join("sc"))?;
        fs::create_dir_all(self.state_dir().join("sys").join("search").join("index"))?;
        Ok(())
    }

    pub(crate) fn runtime_paths(&self) -> std::io::Result<RuntimePaths> {
        self.init_runtime_layout()?;
        let root = self.path.canonicalize()?;
        let content_dir = self.content_dir().canonicalize()?;
        let themes_dir = self.themes_dir().canonicalize()?;
        let state_dir = self.state_dir().canonicalize()?;
        let state_sys_dir = self.state_dir().join("sys").canonicalize()?;
        let state_sc_dir = self.state_dir().join("sc").canonicalize()?;
        let state_search_dir = self.state_dir().join("sys").join("search").canonicalize()?;
        let state_search_index_dir = self
            .state_dir()
            .join("sys")
            .join("search")
            .join("index")
            .canonicalize()?;

        Ok(RuntimePaths {
            root,
            config_file: self.path.join("config.yaml"),
            users_file: self.path.join("users.yaml"),
            content_dir,
            themes_dir,
            state_dir,
            state_sys_dir,
            state_sc_dir,
            state_search_dir: state_search_dir.clone(),
            state_search_index_dir,
            state_search_failed_ids_file: state_search_dir.join("failed-ids.yaml"),
            logs_dir: self.path.join("logs"),
        })
    }
}

impl Drop for TestFixtureRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn fixtures_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap_or(&manifest_dir);
    repo_root.join("target").join("test-fixtures")
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
