// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::protocol::{RequestEnvelope, ResponseEnvelope, read_envelope, write_envelope};
use super::{SocketError, SocketErrorKind, SocketResult, peer};
use crate::management::core::{ManagementRequest, ManagementResponse, MessageResponse};
use crate::management::registry::{DomainActionKey, ManagementRegistry};
use crate::management::system::{SYSTEM_ACTION_PING, SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID};
use crate::management::{ManagementBus, WorkflowTracker, next_connection_id};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

const SOCKET_PERMISSIONS: u32 = 0o600;
#[cfg(test)]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const IDLE_TIMEOUT: Duration = Duration::from_millis(200);
#[cfg(not(test))]
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub struct ListenerHandle {
    pub shutdown: oneshot::Sender<()>,
    pub task: tokio::task::JoinHandle<()>,
}

pub fn bind_listener(path: &Path) -> SocketResult<UnixListener> {
    let listener = UnixListener::bind(path).map_err(|err| {
        SocketError::new(
            SocketErrorKind::Io,
            format!(
                "Failed to bind management socket {}: {}",
                path.display(),
                err
            ),
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(SOCKET_PERMISSIONS);
        if let Err(err) = std::fs::set_permissions(path, perms) {
            return Err(SocketError::new(
                SocketErrorKind::Io,
                format!("Failed to set socket permissions: {}", err),
            ));
        }
    }

    Ok(listener)
}

pub fn spawn_listener(
    listener: UnixListener,
    path: PathBuf,
    bus: ManagementBus,
    registry: Arc<ManagementRegistry>,
) -> ListenerHandle {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let bus = bus.clone();
                            let registry = registry.clone();
                            let connection_id = next_connection_id();
                            tokio::spawn(async move {
                                if let Err(err) =
                                    handle_connection(stream, bus, registry, connection_id).await
                                {
                                    log::warn!("Management socket connection closed: {}", err);
                                }
                            });
                        }
                        Err(err) => {
                            log::error!("Management socket accept failed: {}", err);
                            break;
                        }
                    }
                }
            }
        }

        if path.exists()
            && let Err(err) = std::fs::remove_file(&path)
        {
            log::warn!(
                "Failed to remove management socket {}: {}",
                path.display(),
                err
            );
        }
    });

    ListenerHandle {
        shutdown: shutdown_tx,
        task,
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    bus: ManagementBus,
    registry: Arc<ManagementRegistry>,
    connection_id: u32,
) -> SocketResult<()> {
    let expected_uid = unsafe { libc::geteuid() as u32 };
    peer::validate_peer_uid(&stream, expected_uid)?;

    let mut workflow_tracker = WorkflowTracker::new();
    let handshake_ok = handle_handshake(
        &mut stream,
        &bus,
        &registry,
        &mut workflow_tracker,
        connection_id,
    )
    .await?;
    if !handshake_ok {
        return Ok(());
    }

    loop {
        let envelope: RequestEnvelope =
            match read_envelope_with_timeout(&mut stream, IDLE_TIMEOUT).await {
                Ok(envelope) => envelope,
                Err(err) => {
                    if matches!(err.kind(), SocketErrorKind::Io | SocketErrorKind::Timeout) {
                        break;
                    }
                    return Err(err);
                }
            };

        if let Err(err) = validate_workflow_id(&mut workflow_tracker, envelope.workflow_id) {
            let response = error_response(envelope.workflow_id, &err.to_string(), &registry)?;
            write_envelope(&mut stream, &response).await?;
            return Err(err);
        }

        let response = handle_request(envelope, &bus, &registry, connection_id).await?;
        write_envelope(&mut stream, &response).await?;
    }

    Ok(())
}

async fn handle_handshake(
    stream: &mut UnixStream,
    bus: &ManagementBus,
    registry: &Arc<ManagementRegistry>,
    workflow_tracker: &mut WorkflowTracker,
    connection_id: u32,
) -> SocketResult<bool> {
    let envelope: RequestEnvelope =
        match read_envelope_with_timeout(stream, HANDSHAKE_TIMEOUT).await {
            Ok(envelope) => envelope,
            Err(err) => {
                if err.kind() == SocketErrorKind::Timeout {
                    return Ok(false);
                }
                return Err(err);
            }
        };
    if let Err(err) = validate_workflow_id(workflow_tracker, envelope.workflow_id) {
        let response = error_response(envelope.workflow_id, &err.to_string(), registry)?;
        write_envelope(stream, &response).await?;
        return Err(err);
    }
    if envelope.domain != SYSTEM_DOMAIN_ID || envelope.action != SYSTEM_ACTION_PING {
        let response = error_response(
            envelope.workflow_id,
            "First request must be system Ping",
            registry,
        )?;
        write_envelope(stream, &response).await?;
        return Err(SocketError::new(
            SocketErrorKind::Protocol,
            "Handshake required system Ping",
        ));
    }

    let response = handle_request(envelope, bus, registry, connection_id).await?;
    write_envelope(stream, &response).await?;

    Ok(response.action != SYSTEM_ACTION_PONG_ERROR)
}

async fn handle_request(
    envelope: RequestEnvelope,
    bus: &ManagementBus,
    registry: &Arc<ManagementRegistry>,
    connection_id: u32,
) -> SocketResult<ResponseEnvelope> {
    let request = match decode_request(
        envelope.domain,
        envelope.action,
        envelope.workflow_id,
        connection_id,
        &envelope.payload,
        registry,
    ) {
        Ok(request) => request,
        Err(err) => {
            return error_response(envelope.workflow_id, &format!("{}", err), registry);
        }
    };
    let response = match bus.send_request(request).await {
        Ok(response) => response,
        Err(err) => {
            let message = format!("{}", err);
            let error_response = error_response(envelope.workflow_id, &message, registry)?;
            return Ok(error_response);
        }
    };

    encode_response(&response, registry)
}

async fn read_envelope_with_timeout(
    stream: &mut UnixStream,
    timeout_duration: Duration,
) -> SocketResult<RequestEnvelope> {
    match timeout(timeout_duration, read_envelope::<RequestEnvelope>(stream)).await {
        Ok(result) => result,
        Err(_) => Err(SocketError::new(
            SocketErrorKind::Timeout,
            format!(
                "Socket read timed out after {}ms",
                timeout_duration.as_millis()
            ),
        )),
    }
}

fn decode_request(
    domain: u32,
    action: u32,
    workflow_id: u32,
    connection_id: u32,
    payload: &[u8],
    registry: &ManagementRegistry,
) -> SocketResult<ManagementRequest> {
    let key = DomainActionKey::new(domain, action);
    let codec = registry
        .codec_registry()
        .request_codec(&key)
        .ok_or_else(|| {
            SocketError::new(
                SocketErrorKind::Protocol,
                format!("No request codec for domain {} action {}", domain, action),
            )
        })?;
    let command = codec.decode(payload).map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to decode request payload: {}", err),
        )
    })?;
    codec.validate(&command).map_err(|err| {
        SocketError::new(
            SocketErrorKind::Protocol,
            format!("Request validation failed: {}", err),
        )
    })?;
    Ok(ManagementRequest {
        workflow_id,
        connection_id,
        command,
        actor_email: None,
    })
}

fn validate_workflow_id(tracker: &mut WorkflowTracker, workflow_id: u32) -> SocketResult<()> {
    tracker
        .accept(workflow_id)
        .map_err(|err| SocketError::new(SocketErrorKind::Protocol, err.to_string()))
}

fn encode_response(
    response: &ManagementResponse,
    registry: &ManagementRegistry,
) -> SocketResult<ResponseEnvelope> {
    let key = DomainActionKey::new(response.domain_id, response.action_id);
    let codec = registry
        .codec_registry()
        .response_codec(&key)
        .ok_or_else(|| {
            SocketError::new(
                SocketErrorKind::Protocol,
                format!(
                    "No response codec for domain {} action {}",
                    response.domain_id, response.action_id
                ),
            )
        })?;
    codec.validate(response).map_err(|err| {
        SocketError::new(
            SocketErrorKind::Protocol,
            format!("Response validation failed: {}", err),
        )
    })?;
    let payload = codec.encode(response).map_err(|err| {
        SocketError::new(
            SocketErrorKind::Codec,
            format!("Failed to encode response payload: {}", err),
        )
    })?;
    Ok(ResponseEnvelope {
        domain: response.domain_id,
        action: response.action_id,
        workflow_id: response.workflow_id,
        payload,
    })
}

fn error_response(
    workflow_id: u32,
    message: &str,
    registry: &ManagementRegistry,
) -> SocketResult<ResponseEnvelope> {
    let message = truncate_message(message);
    let response = ManagementResponse {
        domain_id: SYSTEM_DOMAIN_ID,
        action_id: SYSTEM_ACTION_PONG_ERROR,
        workflow_id,
        payload: crate::management::ResponsePayload::Message(
            MessageResponse::new(message).map_err(|err| {
                SocketError::new(
                    SocketErrorKind::Protocol,
                    format!("Failed to build error message: {}", err),
                )
            })?,
        ),
    };
    encode_response(&response, registry)
}

fn truncate_message(message: &str) -> String {
    const MAX_CHARS: usize = 1024;
    if message.chars().count() <= MAX_CHARS {
        return message.to_string();
    }
    message.chars().take(MAX_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config, test_server_list,
    };
    use crate::management::codec::encode_payload;
    use crate::management::system::{PingRequest, SYSTEM_ACTION_PONG};
    use crate::management::{ManagementContext, VersionInfo, build_default_registry};
    use crate::util::short_runtime_paths;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

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
    async fn listener_handles_ping() {
        let registry = build_default_registry().expect("registry");
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-listener");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);
        let registry = bus.registry();

        let socket_path = runtime_paths.state_sys_dir.join("management.sock");
        let listener = bind_listener(&socket_path).expect("bind");
        let handle = spawn_listener(listener, socket_path.clone(), bus.clone(), registry);

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let version = VersionInfo::from_pkg_version().unwrap();
        let ping_payload = encode_payload(&PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        })
        .unwrap();
        let ping = RequestEnvelope {
            domain: SYSTEM_DOMAIN_ID,
            action: SYSTEM_ACTION_PING,
            workflow_id: 1,
            payload: ping_payload,
        };
        write_envelope(&mut stream, &ping).await.unwrap();
        let response: ResponseEnvelope = read_envelope(&mut stream).await.unwrap();
        assert_eq!(response.domain, SYSTEM_DOMAIN_ID);
        assert_eq!(response.action, SYSTEM_ACTION_PONG);

        let _ = handle.shutdown.send(());
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn listener_rejects_version_mismatch() {
        let registry = build_default_registry().expect("registry");
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-version-mismatch");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);
        let registry = bus.registry();

        let socket_path = runtime_paths.state_sys_dir.join("management.sock");
        let listener = bind_listener(&socket_path).expect("bind");
        let handle = spawn_listener(listener, socket_path.clone(), bus.clone(), registry);

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let version = VersionInfo::from_pkg_version().unwrap();
        let ping_payload = encode_payload(&PingRequest {
            version_major: version.major + 1,
            version_minor: version.minor,
            version_patch: version.patch,
        })
        .unwrap();
        let ping = RequestEnvelope {
            domain: SYSTEM_DOMAIN_ID,
            action: SYSTEM_ACTION_PING,
            workflow_id: 1,
            payload: ping_payload,
        };
        write_envelope(&mut stream, &ping).await.unwrap();
        let response: ResponseEnvelope = read_envelope(&mut stream).await.unwrap();
        assert_eq!(response.domain, SYSTEM_DOMAIN_ID);
        assert_eq!(response.action, SYSTEM_ACTION_PONG_ERROR);

        let _ = handle.shutdown.send(());
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn connection_times_out_without_handshake() {
        let registry = build_default_registry().expect("registry");
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-handshake-timeout");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);
        let registry = bus.registry();

        let (_client, server) = UnixStream::pair().expect("pair");
        let handle = tokio::spawn(handle_connection(server, bus, registry, 1));

        tokio::time::sleep(HANDSHAKE_TIMEOUT + Duration::from_millis(50)).await;
        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout waiting for handshake");
        assert!(result.expect("join ok").is_ok());
    }

    #[tokio::test]
    async fn connection_times_out_when_idle_after_handshake() {
        let registry = build_default_registry().expect("registry");
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-idle-timeout");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);
        let registry = bus.registry();

        let (mut client, server) = UnixStream::pair().expect("pair");
        let handle = tokio::spawn(handle_connection(server, bus, registry, 1));

        let version = VersionInfo::from_pkg_version().unwrap();
        let ping_payload = encode_payload(&PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        })
        .unwrap();
        let ping = RequestEnvelope {
            domain: SYSTEM_DOMAIN_ID,
            action: SYSTEM_ACTION_PING,
            workflow_id: 1,
            payload: ping_payload,
        };
        write_envelope(&mut client, &ping).await.unwrap();
        let response: ResponseEnvelope = read_envelope(&mut client).await.unwrap();
        assert_eq!(response.action, SYSTEM_ACTION_PONG);

        tokio::time::sleep(IDLE_TIMEOUT + Duration::from_millis(50)).await;
        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout waiting for idle close");
        assert!(result.expect("join ok").is_ok());
    }

    #[tokio::test]
    async fn connection_times_out_on_partial_frame() {
        let registry = build_default_registry().expect("registry");
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-partial-frame");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);
        let registry = bus.registry();

        let (mut client, server) = UnixStream::pair().expect("pair");
        let handle = tokio::spawn(handle_connection(server, bus, registry, 1));

        let version = VersionInfo::from_pkg_version().unwrap();
        let ping_payload = encode_payload(&PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        })
        .unwrap();
        let ping = RequestEnvelope {
            domain: SYSTEM_DOMAIN_ID,
            action: SYSTEM_ACTION_PING,
            workflow_id: 1,
            payload: ping_payload,
        };
        write_envelope(&mut client, &ping).await.unwrap();
        let response: ResponseEnvelope = read_envelope(&mut client).await.unwrap();
        assert_eq!(response.action, SYSTEM_ACTION_PONG);

        let len = 8u32;
        client.write_all(&len.to_le_bytes()).await.unwrap();
        client.write_all(&[0x01]).await.unwrap();

        tokio::time::sleep(IDLE_TIMEOUT + Duration::from_millis(50)).await;
        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout waiting for partial frame close");
        assert!(result.expect("join ok").is_ok());
    }

    #[tokio::test]
    async fn connection_closes_cleanly_on_client_drop() {
        let registry = build_default_registry().expect("registry");
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-client-drop");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);
        let registry = bus.registry();

        let (mut client, server) = UnixStream::pair().expect("pair");
        let handle = tokio::spawn(handle_connection(server, bus, registry, 1));

        let version = VersionInfo::from_pkg_version().unwrap();
        let ping_payload = encode_payload(&PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        })
        .unwrap();
        let ping = RequestEnvelope {
            domain: SYSTEM_DOMAIN_ID,
            action: SYSTEM_ACTION_PING,
            workflow_id: 1,
            payload: ping_payload,
        };
        write_envelope(&mut client, &ping).await.unwrap();
        let response: ResponseEnvelope = read_envelope(&mut client).await.unwrap();
        assert_eq!(response.action, SYSTEM_ACTION_PONG);

        drop(client);
        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout waiting for client drop");
        assert!(result.expect("join ok").is_ok());
    }

    #[tokio::test]
    async fn listener_handles_concurrent_pings() {
        let registry = build_default_registry().expect("registry");
        let (_temp_dir, runtime_paths) = short_runtime_paths("socket-concurrent");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            std::sync::Arc::new(build_test_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);
        let registry = bus.registry();

        let socket_path = runtime_paths.state_sys_dir.join("management.sock");
        let listener = bind_listener(&socket_path).expect("bind");
        let handle = spawn_listener(listener, socket_path.clone(), bus.clone(), registry);

        let version = VersionInfo::from_pkg_version().unwrap();
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let socket_path = socket_path.clone();
            let version = version;
            tasks.push(tokio::spawn(async move {
                let mut stream = UnixStream::connect(&socket_path).await.unwrap();
                let ping_payload = encode_payload(&PingRequest {
                    version_major: version.major,
                    version_minor: version.minor,
                    version_patch: version.patch,
                })
                .unwrap();
                let ping = RequestEnvelope {
                    domain: SYSTEM_DOMAIN_ID,
                    action: SYSTEM_ACTION_PING,
                    workflow_id: 1,
                    payload: ping_payload,
                };
                write_envelope(&mut stream, &ping).await.unwrap();
                let response: ResponseEnvelope = read_envelope(&mut stream).await.unwrap();
                assert_eq!(response.action, SYSTEM_ACTION_PONG);
            }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        let _ = handle.shutdown.send(());
        let _ = handle.task.await;
    }
}
