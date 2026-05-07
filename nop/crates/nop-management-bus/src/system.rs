// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::RegistryError;
use crate::core::ManagementContext;
use crate::registry::{ManagementHandler, ManagementRegistry};
use nop_management_contract::registry::{ActionDescriptor, DomainActionKey, DomainDescriptor};
use nop_management_contract::system::{
    SYSTEM_ACTION_LOGGING_CLEAR, SYSTEM_ACTION_LOGGING_CLEAR_ERR, SYSTEM_ACTION_LOGGING_CLEAR_OK,
    SYSTEM_ACTION_LOGGING_GET, SYSTEM_ACTION_LOGGING_GET_ERR, SYSTEM_ACTION_LOGGING_GET_OK,
    SYSTEM_ACTION_LOGGING_SET, SYSTEM_ACTION_LOGGING_SET_ERR, SYSTEM_ACTION_LOGGING_SET_OK,
    SYSTEM_ACTION_PING, SYSTEM_ACTION_PONG, SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID,
};
use nop_management_system::{
    LoggingClearErrResponseCodec, LoggingClearOkResponseCodec, LoggingClearRequestCodec,
    LoggingGetErrResponseCodec, LoggingGetOkResponseCodec, LoggingGetRequestCodec,
    LoggingSetErrResponseCodec, LoggingSetOkResponseCodec, LoggingSetRequestCodec,
    PingRequestCodec, PongErrorResponseCodec, PongResponseCodec, handle_system_request,
};
use std::sync::Arc;

impl nop_management_system::SystemContext for ManagementContext {
    fn version(&self) -> (u16, u16, u16) {
        (self.version.major, self.version.minor, self.version.patch)
    }

    fn runtime_root(&self) -> &std::path::Path {
        self.runtime_root.as_path()
    }

    fn log_controller(&self) -> &nop_rt_logging::LogController {
        &self.log_controller
    }

    fn config(&self) -> &nop_config::ValidatedConfig {
        self.config.as_ref()
    }
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(DomainDescriptor {
        name: "system",
        id: SYSTEM_DOMAIN_ID,
        actions: vec![
            ActionDescriptor {
                name: "ping",
                id: SYSTEM_ACTION_PING,
            },
            ActionDescriptor {
                name: "pong",
                id: SYSTEM_ACTION_PONG,
            },
            ActionDescriptor {
                name: "pong_error",
                id: SYSTEM_ACTION_PONG_ERROR,
            },
            ActionDescriptor {
                name: "logging_get",
                id: SYSTEM_ACTION_LOGGING_GET,
            },
            ActionDescriptor {
                name: "logging_get_ok",
                id: SYSTEM_ACTION_LOGGING_GET_OK,
            },
            ActionDescriptor {
                name: "logging_get_err",
                id: SYSTEM_ACTION_LOGGING_GET_ERR,
            },
            ActionDescriptor {
                name: "logging_set",
                id: SYSTEM_ACTION_LOGGING_SET,
            },
            ActionDescriptor {
                name: "logging_set_ok",
                id: SYSTEM_ACTION_LOGGING_SET_OK,
            },
            ActionDescriptor {
                name: "logging_set_err",
                id: SYSTEM_ACTION_LOGGING_SET_ERR,
            },
            ActionDescriptor {
                name: "logging_clear",
                id: SYSTEM_ACTION_LOGGING_CLEAR,
            },
            ActionDescriptor {
                name: "logging_clear_ok",
                id: SYSTEM_ACTION_LOGGING_CLEAR_OK,
            },
            ActionDescriptor {
                name: "logging_clear_err",
                id: SYSTEM_ACTION_LOGGING_CLEAR_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_system_request(request, context.as_ref()).await })
    });
    registry.register_handler(
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PING),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR),
        handler,
    )?;

    registry.register_request_codec(Arc::new(PingRequestCodec))?;
    registry.register_request_codec(Arc::new(LoggingGetRequestCodec))?;
    registry.register_request_codec(Arc::new(LoggingSetRequestCodec))?;
    registry.register_request_codec(Arc::new(LoggingClearRequestCodec))?;
    registry.register_response_codec(Arc::new(PongResponseCodec))?;
    registry.register_response_codec(Arc::new(PongErrorResponseCodec))?;
    registry.register_response_codec(Arc::new(LoggingGetOkResponseCodec))?;
    registry.register_response_codec(Arc::new(LoggingGetErrResponseCodec))?;
    registry.register_response_codec(Arc::new(LoggingSetOkResponseCodec))?;
    registry.register_response_codec(Arc::new(LoggingSetErrResponseCodec))?;
    registry.register_response_codec(Arc::new(LoggingClearOkResponseCodec))?;
    registry.register_response_codec(Arc::new(LoggingClearErrResponseCodec))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ManagementBus, ManagementContext, build_default_registry};
    use nop_config::{
        AdminConfig, AppConfig, AuthMethod, Config, JwtConfig, LocalAuthConfig, LoggingConfig,
        LoggingRotationConfig, LoginSessionConfig, NavigationConfig, PasswordHashingConfig,
        RenderingConfig, SearchConfig, SecurityConfig, ServerConfig, ShortcodeConfig,
        StreamingConfig, UploadConfig, UsersConfig, ValidatedConfig, test_local_users_config,
        test_server_list,
    };
    use nop_management_contract::ManagementCommand;
    use nop_management_contract::system::{
        ClearLogsRequest, GetLoggingConfigRequest, SetLoggingConfigRequest, SystemCommand,
    };
    use nop_rt_logging::DEFAULT_LOG_FILE_NAME;
    use nop_testing::test_fixtures::TestFixtureRoot;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    fn build_config() -> Config {
        Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: UsersConfig {
                auth_method: AuthMethod::Local,
                local: Some(LocalAuthConfig {
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
                    password: PasswordHashingConfig::default(),
                    password_complexity_disabled: false,
                }),
                oidc: None,
            },
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
                login_sessions: LoginSessionConfig::default(),
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
                allowed_extensions: vec!["md".to_string()],
            },
            streaming: StreamingConfig { enabled: false },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            search: SearchConfig::default(),
            dev_mode: None,
        }
    }

    fn build_validated_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: test_server_list(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
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
                max_violations: 10,
                cooldown_seconds: 60,
                use_forwarded_for: false,
                login_sessions: LoginSessionConfig::default(),
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
                allowed_extensions: vec!["md".to_string()],
            },
            streaming: StreamingConfig { enabled: false },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            search: SearchConfig::default(),
            dev_mode: None,
        }
    }

    fn write_config(root: &Path) {
        let config = build_config();
        let content = serde_yaml::to_string(&config).expect("serialize config");
        fs::write(root.join("config.yaml"), content).expect("write config");
        fs::write(root.join("users.yaml"), "{}\n").expect("write users");
    }

    #[tokio::test]
    async fn system_logging_get_set_and_clear() {
        let fixture = TestFixtureRoot::new_unique("system-logging").unwrap();
        fixture.init_runtime_layout().unwrap();
        write_config(fixture.path());
        let runtime_paths = fixture.runtime_paths().unwrap();

        fs::create_dir_all(&runtime_paths.logs_dir).unwrap();
        fs::write(runtime_paths.logs_dir.join(DEFAULT_LOG_FILE_NAME), "hello").unwrap();
        fs::write(
            runtime_paths
                .logs_dir
                .join(format!("{}.1", DEFAULT_LOG_FILE_NAME)),
            "world",
        )
        .unwrap();

        let registry = build_default_registry().expect("registry");
        let config = Arc::new(build_validated_config());
        let context =
            ManagementContext::from_components(fixture.path().to_path_buf(), config, runtime_paths)
                .expect("context");

        let bus = ManagementBus::start(registry, context);

        let response = bus
            .send(
                1,
                1,
                ManagementCommand::System(SystemCommand::GetLoggingConfig(
                    GetLoggingConfigRequest {},
                )),
            )
            .await
            .expect("logging get");
        assert_eq!(response.action_id, SYSTEM_ACTION_LOGGING_GET_OK);

        let response = bus
            .send(
                1,
                2,
                ManagementCommand::System(SystemCommand::SetLoggingConfig(
                    SetLoggingConfigRequest {
                        rotation_max_size_mb: 2,
                        rotation_max_files: 4,
                    },
                )),
            )
            .await
            .expect("logging set");
        assert_eq!(response.action_id, SYSTEM_ACTION_LOGGING_SET_OK);

        let response = bus
            .send(
                1,
                3,
                ManagementCommand::System(SystemCommand::ClearLogs(ClearLogsRequest {})),
            )
            .await
            .expect("logging clear");
        assert_eq!(response.action_id, SYSTEM_ACTION_LOGGING_CLEAR_OK);
    }
}
