// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::protocol::{RequestEnvelope, ResponseEnvelope, read_envelope, write_envelope};
use super::{SocketError, SocketErrorKind, SocketResult};
use crate::management::codec::{CodecError, decode_payload, encode_payload};
use crate::management::core::{ManagementCommand, ManagementRequest, ManagementResponse};
use crate::management::registry::{DomainActionKey, ManagementRegistry};
use crate::management::system::{
    PingRequest, PongErrorResponse, PongResponse, SYSTEM_ACTION_PING, SYSTEM_ACTION_PONG,
    SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID,
};
use crate::management::{VersionInfo, WorkflowCounter, next_connection_id};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_WARN_AFTER: Duration = Duration::from_secs(2);

pub enum SocketConnect {
    Ready(SocketClient),
    Stale,
    Incompatible(String),
}

pub struct SocketClient {
    stream: UnixStream,
    registry: Arc<ManagementRegistry>,
    workflow_counter: WorkflowCounter,
    path: PathBuf,
    connection_id: u32,
}

impl SocketClient {
    pub async fn connect(
        path: &Path,
        registry: Arc<ManagementRegistry>,
    ) -> SocketResult<SocketConnect> {
        let stream = match UnixStream::connect(path).await {
            Ok(stream) => stream,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    return Err(SocketError::new(
                        SocketErrorKind::Unauthorized,
                        "Permission denied for management socket",
                    ));
                }
                return Ok(SocketConnect::Stale);
            }
        };

        let mut client = SocketClient {
            stream,
            registry,
            workflow_counter: WorkflowCounter::new(),
            path: path.to_path_buf(),
            connection_id: next_connection_id(),
        };

        match client.handshake().await? {
            HandshakeResult::Ready => Ok(SocketConnect::Ready(client)),
            HandshakeResult::Stale => Ok(SocketConnect::Stale),
            HandshakeResult::Incompatible(message) => Ok(SocketConnect::Incompatible(message)),
        }
    }

    pub async fn send(&mut self, command: ManagementCommand) -> SocketResult<ManagementResponse> {
        let workflow_id = self
            .workflow_counter
            .next_id()
            .map_err(|err| SocketError::new(SocketErrorKind::Protocol, err.to_string()))?;
        let request = ManagementRequest {
            workflow_id,
            connection_id: self.connection_id,
            command,
        };

        let envelope = self.encode_request(&request)?;
        let send = write_envelope(&mut self.stream, &envelope);
        timeout(CLIENT_TIMEOUT, send)
            .await
            .map_err(|_| SocketError::new(SocketErrorKind::Timeout, "Request timeout"))??;

        let receive = read_envelope::<ResponseEnvelope>(&mut self.stream);
        let response = timeout(CLIENT_TIMEOUT, receive)
            .await
            .map_err(|_| SocketError::new(SocketErrorKind::Timeout, "Response timeout"))??;

        if response.workflow_id != workflow_id {
            return Err(SocketError::new(
                SocketErrorKind::Protocol,
                format!(
                    "Response workflow_id {} does not match {}",
                    response.workflow_id, workflow_id
                ),
            ));
        }

        self.decode_response(response)
    }

    async fn handshake(&mut self) -> SocketResult<HandshakeResult> {
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

        let workflow_id = self
            .workflow_counter
            .next_id()
            .map_err(|err| SocketError::new(SocketErrorKind::Protocol, err.to_string()))?;
        let envelope = RequestEnvelope {
            domain: SYSTEM_DOMAIN_ID,
            action: SYSTEM_ACTION_PING,
            workflow_id,
            payload,
        };

        let send = write_envelope(&mut self.stream, &envelope);
        match timeout(CLIENT_TIMEOUT, send).await {
            Ok(Ok(())) => {}
            _ => return Ok(HandshakeResult::Stale),
        }

        let receive = read_envelope::<ResponseEnvelope>(&mut self.stream);
        tokio::pin!(receive);
        let warn = tokio::time::sleep(HANDSHAKE_WARN_AFTER);
        tokio::pin!(warn);

        let response_result = tokio::select! {
            result = &mut receive => result,
            _ = &mut warn => {
                eprintln!(
                    "Warning: no response from management socket {} after {}s; assuming stale and removing after {}s.",
                    self.path.display(),
                    HANDSHAKE_WARN_AFTER.as_secs(),
                    CLIENT_TIMEOUT.as_secs()
                );
                let remaining = CLIENT_TIMEOUT
                    .checked_sub(HANDSHAKE_WARN_AFTER)
                    .unwrap_or_else(|| Duration::from_secs(0));
                match timeout(remaining, &mut receive).await {
                    Ok(result) => result,
                    Err(_) => return Ok(HandshakeResult::Stale),
                }
            }
        };

        let response = match response_result {
            Ok(response) => response,
            Err(_) => return Ok(HandshakeResult::Stale),
        };

        if response.domain != SYSTEM_DOMAIN_ID {
            return Ok(HandshakeResult::Incompatible(
                "Unexpected handshake domain".to_string(),
            ));
        }
        if response.workflow_id != workflow_id {
            return Ok(HandshakeResult::Incompatible(
                "Handshake workflow_id mismatch".to_string(),
            ));
        }

        match response.action {
            SYSTEM_ACTION_PONG => {
                let _pong: PongResponse = decode_payload(&response.payload).map_err(|err| {
                    SocketError::new(
                        SocketErrorKind::Codec,
                        format!("Failed to decode pong: {}", err),
                    )
                })?;
                Ok(HandshakeResult::Ready)
            }
            SYSTEM_ACTION_PONG_ERROR => {
                let pong: PongErrorResponse = decode_payload(&response.payload).map_err(|err| {
                    SocketError::new(
                        SocketErrorKind::Codec,
                        format!("Failed to decode pong error: {}", err),
                    )
                })?;
                Ok(HandshakeResult::Incompatible(pong.message))
            }
            _ => Ok(HandshakeResult::Incompatible(
                "Unexpected handshake action".to_string(),
            )),
        }
    }

    fn encode_request(&self, request: &ManagementRequest) -> SocketResult<RequestEnvelope> {
        let key = DomainActionKey::new(request.domain_id(), request.action_id());
        let codec = self
            .registry
            .codec_registry()
            .request_codec(&key)
            .ok_or_else(|| {
                SocketError::new(
                    SocketErrorKind::Protocol,
                    format!(
                        "No request codec for domain {} action {}",
                        key.domain_id, key.action_id
                    ),
                )
            })?;
        codec.validate(&request.command).map_err(|err| {
            SocketError::new(
                SocketErrorKind::Protocol,
                format!("Request validation failed: {}", err),
            )
        })?;
        let payload = codec.encode(&request.command).map_err(map_codec_error)?;
        Ok(RequestEnvelope {
            domain: key.domain_id,
            action: key.action_id,
            workflow_id: request.workflow_id,
            payload,
        })
    }

    fn decode_response(&self, response: ResponseEnvelope) -> SocketResult<ManagementResponse> {
        let key = DomainActionKey::new(response.domain, response.action);
        let codec = self
            .registry
            .codec_registry()
            .response_codec(&key)
            .ok_or_else(|| {
                SocketError::new(
                    SocketErrorKind::Protocol,
                    format!(
                        "No response codec for domain {} action {}",
                        key.domain_id, key.action_id
                    ),
                )
            })?;
        let payload = codec.decode(&response.payload).map_err(map_codec_error)?;
        Ok(ManagementResponse {
            domain_id: response.domain,
            action_id: response.action,
            workflow_id: response.workflow_id,
            payload,
        })
    }
}

enum HandshakeResult {
    Ready,
    Stale,
    Incompatible(String),
}

fn map_codec_error(err: CodecError) -> SocketError {
    SocketError::new(SocketErrorKind::Codec, err.to_string())
}
