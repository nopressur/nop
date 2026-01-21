// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

pub mod client;
mod listener;
mod peer;
mod protocol;

use crate::management::ManagementBus;
use crate::management::codec::{decode_payload, encode_payload};
use crate::management::core::VersionInfo;
use crate::management::system::{
    PingRequest, PongErrorResponse, PongResponse, SYSTEM_ACTION_PING, SYSTEM_ACTION_PONG,
    SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID,
};
use crate::runtime_paths::RuntimePaths;
use listener::{ListenerHandle, bind_listener, spawn_listener};
use protocol::{RequestEnvelope, ResponseEnvelope, read_envelope, write_envelope};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};

const SOCKET_FILENAME: &str = "management.sock";
const PROBE_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketErrorKind {
    Io,
    Codec,
    Protocol,
    Unauthorized,
    Active,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct SocketError {
    kind: SocketErrorKind,
    message: String,
}

impl SocketError {
    pub fn new(kind: SocketErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> SocketErrorKind {
        self.kind
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for SocketError {}

pub type SocketResult<T> = Result<T, SocketError>;

#[derive(Debug)]
pub struct ManagementSocket {
    path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ManagementSocket {
    pub async fn start(runtime_paths: &RuntimePaths, bus: ManagementBus) -> SocketResult<Self> {
        let socket_path = runtime_paths.state_sys_dir.join(SOCKET_FILENAME);
        let registry = bus.registry();

        if socket_path.exists() {
            match probe_existing_socket(&socket_path).await? {
                ProbeResult::Active(message) => {
                    return Err(SocketError::new(
                        SocketErrorKind::Active,
                        format!(
                            "Management socket already active at {}: {}",
                            socket_path.display(),
                            message
                        ),
                    ));
                }
                ProbeResult::Stale => {
                    std::fs::remove_file(&socket_path).map_err(|err| {
                        SocketError::new(
                            SocketErrorKind::Io,
                            format!("Failed to remove stale socket: {}", err),
                        )
                    })?;
                }
            }
        }

        let listener = bind_listener(&socket_path)?;
        let ListenerHandle { shutdown, task } =
            spawn_listener(listener, socket_path.clone(), bus, registry);

        Ok(Self {
            path: socket_path,
            shutdown: Some(shutdown),
            task,
        })
    }
}

impl Drop for ManagementSocket {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take()
            && shutdown.send(()).is_err()
        {
            log::warn!("Failed to send management socket shutdown signal");
        }
        if self.path.exists()
            && let Err(err) = std::fs::remove_file(&self.path)
        {
            log::warn!(
                "Failed to remove management socket {}: {}",
                self.path.display(),
                err
            );
        }
    }
}

enum ProbeResult {
    Active(String),
    Stale,
}

async fn probe_existing_socket(path: &Path) -> SocketResult<ProbeResult> {
    let mut stream = match UnixStream::connect(path).await {
        Ok(stream) => stream,
        Err(_) => return Ok(ProbeResult::Stale),
    };

    let version = VersionInfo::from_pkg_version().map_err(|err| {
        SocketError::new(SocketErrorKind::Protocol, format!("Version error: {}", err))
    })?;

    let payload = encode_payload(&PingRequest {
        version_major: version.major,
        version_minor: version.minor,
        version_patch: version.patch,
    })
    .map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to encode ping: {}", err),
        )
    })?;

    let request = RequestEnvelope {
        domain: SYSTEM_DOMAIN_ID,
        action: SYSTEM_ACTION_PING,
        workflow_id: 1,
        payload,
    };

    let send = write_envelope(&mut stream, &request);
    match timeout(PROBE_TIMEOUT, send).await {
        Ok(Ok(())) => {}
        _ => return Ok(ProbeResult::Stale),
    }

    let receive = read_envelope::<ResponseEnvelope>(&mut stream);
    let response = match timeout(PROBE_TIMEOUT, receive).await {
        Ok(Ok(response)) => response,
        _ => return Ok(ProbeResult::Stale),
    };

    if response.domain != SYSTEM_DOMAIN_ID {
        return Ok(ProbeResult::Stale);
    }

    let message = match response.action {
        SYSTEM_ACTION_PONG => match decode_message::<PongResponse>(&response.payload) {
            Ok(decoded) => decoded.message,
            Err(_) => return Ok(ProbeResult::Stale),
        },
        SYSTEM_ACTION_PONG_ERROR => match decode_message::<PongErrorResponse>(&response.payload) {
            Ok(decoded) => decoded.message,
            Err(_) => return Ok(ProbeResult::Stale),
        },
        _ => return Ok(ProbeResult::Stale),
    };

    Ok(ProbeResult::Active(message))
}

fn decode_message<T: crate::management::WireDecode>(payload: &[u8]) -> SocketResult<T> {
    decode_payload(payload).map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to decode response payload: {}", err),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config, test_server_list,
    };
    use crate::management::{ManagementBus, ManagementContext, build_default_registry};
    use crate::util::short_runtime_paths;

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
    async fn start_rejects_active_socket() {
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-active");

        let registry = build_default_registry().expect("registry");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);

        let first = ManagementSocket::start(&runtime_paths, bus.clone())
            .await
            .expect("first socket");
        let err = ManagementSocket::start(&runtime_paths, bus.clone())
            .await
            .expect_err("second should fail");
        assert_eq!(err.kind(), SocketErrorKind::Active);

        drop(first);
    }
}
