// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse,
};
use crate::management::errors::{DomainError, DomainResult, ManagementError, ManagementErrorKind};
use crate::management::registry::{DomainActionKey, ManagementRegistry};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

const BUS_CHANNEL_DEPTH: usize = 64;

#[derive(Clone)]
pub struct ManagementBus {
    sender: mpsc::Sender<BusMessage>,
    registry: Arc<ManagementRegistry>,
}

struct BusMessage {
    request: ManagementRequest,
    reply: oneshot::Sender<Result<ManagementResponse, ManagementError>>,
}

impl ManagementBus {
    pub fn start(registry: ManagementRegistry, context: ManagementContext) -> Self {
        let (sender, mut receiver) = mpsc::channel::<BusMessage>(BUS_CHANNEL_DEPTH);
        let registry = Arc::new(registry);
        let registry_for_task = registry.clone();
        let context = Arc::new(context);

        tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                let result = dispatch(&registry_for_task, &context, message.request).await;
                let _ = message.reply.send(result);
            }
        });

        Self { sender, registry }
    }

    pub fn registry(&self) -> Arc<ManagementRegistry> {
        self.registry.clone()
    }

    pub async fn send(
        &self,
        connection_id: u32,
        workflow_id: u32,
        command: ManagementCommand,
    ) -> Result<ManagementResponse, ManagementError> {
        if connection_id == 0 {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "connection_id must be non-zero",
            ));
        }
        if workflow_id == 0 {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "workflow_id must be non-zero",
            ));
        }
        self.send_request(ManagementRequest {
            workflow_id,
            connection_id,
            command,
        })
        .await
    }

    pub async fn send_request(
        &self,
        request: ManagementRequest,
    ) -> Result<ManagementResponse, ManagementError> {
        if request.connection_id == 0 {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "connection_id must be non-zero",
            ));
        }
        if request.workflow_id == 0 {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                "workflow_id must be non-zero",
            ));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let message = BusMessage {
            request,
            reply: reply_tx,
        };

        self.sender.send(message).await.map_err(|_| {
            ManagementError::new(
                ManagementErrorKind::Internal,
                None,
                None,
                "Management bus is unavailable",
            )
        })?;

        reply_rx.await.map_err(|_| {
            ManagementError::new(
                ManagementErrorKind::Internal,
                None,
                None,
                "Management bus dropped response",
            )
        })?
    }
}

async fn dispatch(
    registry: &Arc<ManagementRegistry>,
    context: &Arc<ManagementContext>,
    request: ManagementRequest,
) -> Result<ManagementResponse, ManagementError> {
    log::trace!(
        "Management bus request (domain={}, action={}, connection_id={}, workflow_id={})",
        request.domain_id(),
        request.action_id(),
        request.connection_id,
        request.workflow_id
    );
    let key = DomainActionKey::new(request.domain_id(), request.action_id());
    let handler = registry.handler(&key).ok_or_else(|| {
        ManagementError::new(
            ManagementErrorKind::NotFound,
            Some(key.domain_id),
            Some(key.action_id),
            "No handler registered for command",
        )
    })?;

    let result: DomainResult<ManagementResponse> = handler(request, context.clone()).await;
    result.map_err(|err| normalize_error(err.as_ref(), key.domain_id, key.action_id))
}

fn normalize_error(err: &dyn DomainError, domain_id: u32, action_id: u32) -> ManagementError {
    ManagementError::new(
        err.kind(),
        Some(domain_id),
        Some(action_id),
        err.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config, test_server_list,
    };
    use crate::management::system::{
        PingRequest, SYSTEM_ACTION_PONG, SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID, SystemCommand,
    };
    use crate::management::{
        ManagementContext, ManagementResponse, VersionInfo, build_default_registry,
    };
    use crate::util::test_fixtures::TestFixtureRoot;

    fn build_test_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: test_server_list(),
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
                max_violations: 10,
                cooldown_seconds: 60,
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
                allowed_extensions: vec!["md".to_string()],
            },
            streaming: StreamingConfig { enabled: false },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            dev_mode: None,
        }
    }

    #[tokio::test]
    async fn bus_dispatches_system_ping() {
        let fixture = TestFixtureRoot::new_unique("bus-ping").unwrap();
        fixture.init_runtime_layout().unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let registry = build_default_registry().expect("registry");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);

        let version = VersionInfo::from_pkg_version().expect("version");
        let response = bus
            .send(
                crate::management::next_connection_id(),
                1,
                ManagementCommand::System(SystemCommand::Ping(PingRequest {
                    version_major: version.major,
                    version_minor: version.minor,
                    version_patch: version.patch,
                })),
            )
            .await
            .expect("response");

        assert_eq!(response.domain_id, SYSTEM_DOMAIN_ID);
        assert_eq!(response.action_id, SYSTEM_ACTION_PONG);
        assert_message_response(&response);
    }

    #[tokio::test]
    async fn bus_returns_pong_error_on_version_mismatch() {
        let fixture = TestFixtureRoot::new_unique("bus-pong-error").unwrap();
        fixture.init_runtime_layout().unwrap();
        let runtime_paths = fixture.runtime_paths().unwrap();
        let registry = build_default_registry().expect("registry");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);

        let response = bus
            .send(
                crate::management::next_connection_id(),
                1,
                ManagementCommand::System(SystemCommand::Ping(PingRequest {
                    version_major: 9,
                    version_minor: 9,
                    version_patch: 9,
                })),
            )
            .await
            .expect("response");

        assert_eq!(response.domain_id, SYSTEM_DOMAIN_ID);
        assert_eq!(response.action_id, SYSTEM_ACTION_PONG_ERROR);
        assert_message_response(&response);
    }

    fn assert_message_response(response: &ManagementResponse) {
        match &response.payload {
            crate::management::ResponsePayload::Message(payload) => {
                assert!(!payload.message.is_empty());
            }
            _ => panic!("Expected message response"),
        }
    }
}
