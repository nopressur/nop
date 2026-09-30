// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::WsTicketStore;
use crate::ws_auth;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::{AggregatedMessage, AggregatedMessageStream, Session};
use futures_util::StreamExt;
use nop_config::ValidatedConfig;
use nop_management_bus::ManagementBus;
use nop_management_bus::ManagementTools;
use nop_management_bus::UploadRegistry;
use nop_management_bus::WorkflowTracker;
use nop_management_bus::ws::{
    AuthResponseFrame, BlobStreamProducer, ErrorFrame, RequestFrame, ResponseFrame, StreamAckFrame,
    StreamChunkFrame, StreamError, StreamErrorKind, WS_MAX_MESSAGE_BYTES, WsFrame,
    WsProtocolErrorKind, decode_frame, encode_frame,
};
use nop_management_bus::{assign_content_stream_id, open_content_blob_stream};
use nop_management_contract::system::{SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID};
use nop_management_contract::{
    DomainActionKey, ManagementRequest, ManagementResponse, MessageResponse,
};
use nop_rt_csrf::CsrfTokenStore;
use nop_rt_iam::AuthRequest;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const STREAM_ACK_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(not(test))]
const STREAM_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const OUTBOUND_STREAM_ID_START: u32 = 0x8000_0000;

pub async fn ws_ticket(
    req: HttpRequest,
    ticket_store: web::Data<WsTicketStore>,
    config: web::Data<ValidatedConfig>,
) -> Result<HttpResponse> {
    log::debug!("Admin WS ticket request received");
    if let Err(response) = ws_auth::require_validated_csrf(&req) {
        return Ok(*response);
    }

    let jwt_id = match ws_auth::resolve_jwt_id(&req, &config) {
        Some(jwt_id) => jwt_id,
        None => {
            log::warn!("Admin WS ticket request missing auth");
            return Ok(HttpResponse::Unauthorized().json(json!({
                "error": "Authentication required"
            })));
        }
    };

    let ticket = ticket_store.issue(&jwt_id);
    log::debug!("Admin WS ticket issued");
    Ok(HttpResponse::Ok().json(json!({
        "ticket": ticket,
        "expires_in_seconds": ticket_store.expiry_seconds()
    })))
}

pub async fn management_ws(
    req: HttpRequest,
    stream: web::Payload,
    management_tools: web::Data<ManagementTools>,
    csrf_store: web::Data<CsrfTokenStore>,
    ticket_store: web::Data<WsTicketStore>,
    config: web::Data<ValidatedConfig>,
) -> Result<HttpResponse> {
    let jwt_id = match ws_auth::resolve_jwt_id(&req, &config) {
        Some(jwt_id) => jwt_id,
        None => {
            log::warn!("Admin WS connection missing auth");
            return Ok(HttpResponse::Unauthorized().json(json!({
                "error": "Authentication required"
            })));
        }
    };
    let actor_email = req.user_info().map(|user| user.email);

    log::debug!("Admin WS connection starting");
    let (response, session, message_stream) = actix_ws::handle(&req, stream)?;
    let message_stream = message_stream
        .max_frame_size(WS_MAX_MESSAGE_BYTES)
        .aggregate_continuations()
        .max_continuation_size(WS_MAX_MESSAGE_BYTES);
    let bus = management_tools.management_bus.clone();
    let registry = bus.registry();
    let upload_registry = management_tools.upload_registry.clone();
    let csrf_store = csrf_store.into_inner();
    let ticket_store = ticket_store.into_inner();

    actix_web::rt::spawn(async move {
        if let Err(err) = handle_ws_session(
            session,
            message_stream,
            bus,
            registry,
            csrf_store,
            ticket_store,
            jwt_id,
            actor_email,
            upload_registry,
        )
        .await
        {
            log::warn!("Management WS session ended: {}", err);
        }
    });

    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn handle_ws_session(
    mut session: Session,
    mut messages: AggregatedMessageStream,
    bus: ManagementBus,
    registry: Arc<nop_management_bus::ManagementRegistry>,
    csrf_store: Arc<CsrfTokenStore>,
    ticket_store: Arc<WsTicketStore>,
    jwt_id: String,
    actor_email: Option<String>,
    upload_registry: Arc<UploadRegistry>,
) -> Result<(), String> {
    log::debug!("Admin WS session started");
    log::debug!("Admin WS waiting for auth frame");
    let auth_bytes = match read_auth_frame(&mut session, &mut messages).await {
        Ok(bytes) => bytes,
        Err(err) => {
            log::warn!("Admin WS auth frame read failed: {}", err);
            return Err(err);
        }
    };
    log::debug!("Admin WS auth frame received");
    let auth_frame = match decode_frame(&auth_bytes) {
        Ok(WsFrame::Auth(frame)) => frame,
        Ok(_) => {
            log::warn!("Admin WS auth frame type mismatch");
            send_auth_error(&mut session, "First frame must be Auth").await?;
            return Err("First frame must be Auth".to_string());
        }
        Err(err) => {
            log::warn!("Admin WS auth frame decode failed: {}", err);
            send_auth_error(&mut session, &format!("{}", err)).await?;
            return Err(format!("Auth decode error: {}", err));
        }
    };

    if let Err(err) = ws_auth::validate_auth_frame(
        &csrf_store,
        &ticket_store,
        &jwt_id,
        &auth_frame.csrf_token,
        &auth_frame.ticket,
    ) {
        log::warn!("{}", err.log_message());
        send_auth_error(&mut session, err.client_message()).await?;
        return Err(err.client_message().to_string());
    }

    log::info!("Admin WS authenticated");
    let ok = WsFrame::AuthOk(AuthResponseFrame {
        message: "Authenticated".to_string(),
    });
    send_frame(&mut session, &ok).await?;

    let connection_id = nop_management_bus::next_connection_id();
    let mut coordinator = WsCoordinator::new(
        session,
        bus,
        registry,
        upload_registry.clone(),
        connection_id,
        actor_email,
    );
    loop {
        let next_message = if coordinator.awaiting_outbound_ack() {
            match tokio::time::timeout(STREAM_ACK_TIMEOUT, messages.next()).await {
                Ok(message) => message,
                Err(_) => {
                    let message = format!(
                        "Outbound stream ack timed out after {}ms",
                        STREAM_ACK_TIMEOUT.as_millis()
                    );
                    log::warn!("{}", message);
                    coordinator.send_error(&message).await?;
                    break;
                }
            }
        } else {
            messages.next().await
        };
        let Some(message) = next_message else {
            break;
        };
        let message = message.map_err(|err| format!("WS error: {}", err))?;
        match message {
            AggregatedMessage::Binary(bytes) => {
                let frame = match decode_frame(&bytes) {
                    Ok(frame) => frame,
                    Err(err) => {
                        log::warn!("Admin WS frame decode error: {}", err);
                        coordinator.send_error(&format!("{}", err)).await?;
                        break;
                    }
                };
                if let Err(err) = coordinator.handle_frame(frame).await {
                    log::warn!("Admin WS frame handling error: {}", err);
                    coordinator.send_error(&err).await?;
                    break;
                }
            }
            AggregatedMessage::Ping(bytes) => {
                coordinator.handle_ping(bytes.as_ref()).await?;
            }
            AggregatedMessage::Close(_) => {
                break;
            }
            _ => {}
        }
    }

    if let Err(err) = upload_registry.cleanup_connection(connection_id).await {
        log::warn!("Upload registry cleanup failed: {}", err);
    }
    log::info!("Admin WS session closed");
    Ok(())
}

async fn read_auth_frame(
    session: &mut Session,
    messages: &mut AggregatedMessageStream,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("WebSocket auth timed out".to_string());
        }
        let remaining = deadline - now;
        let message = tokio::time::timeout(remaining, messages.next())
            .await
            .map_err(|_| "WebSocket auth timed out".to_string())?;
        let message = match message {
            Some(message) => message.map_err(|err| format!("WS error: {}", err))?,
            None => return Err("WebSocket closed before auth".to_string()),
        };
        match message {
            AggregatedMessage::Binary(bytes) => return Ok(bytes.to_vec()),
            AggregatedMessage::Ping(bytes) => {
                session.pong(&bytes).await.map_err(|err| err.to_string())?;
            }
            AggregatedMessage::Close(_) => return Err("WebSocket closed before auth".to_string()),
            _ => {}
        }
    }
}

async fn send_auth_error(session: &mut Session, message: &str) -> Result<(), String> {
    let frame = WsFrame::AuthErr(AuthResponseFrame {
        message: message.to_string(),
    });
    send_frame(session, &frame).await?;
    session
        .clone()
        .close(None)
        .await
        .map_err(|err| err.to_string())
}

async fn send_frame(session: &mut Session, frame: &WsFrame) -> Result<(), String> {
    let bytes = encode_frame(frame).map_err(|err| err.to_string())?;
    session.binary(bytes).await.map_err(|err| err.to_string())
}

struct WsCoordinator {
    session: Session,
    bus: ManagementBus,
    registry: Arc<nop_management_bus::ManagementRegistry>,
    upload_registry: Arc<UploadRegistry>,
    connection_id: u32,
    actor_email: Option<String>,
    outbound_streams: OutboundBlobStreams,
    workflow_tracker: WorkflowTracker,
}

impl WsCoordinator {
    fn new(
        session: Session,
        bus: ManagementBus,
        registry: Arc<nop_management_bus::ManagementRegistry>,
        upload_registry: Arc<UploadRegistry>,
        connection_id: u32,
        actor_email: Option<String>,
    ) -> Self {
        Self {
            session,
            bus,
            registry,
            upload_registry,
            connection_id,
            actor_email,
            outbound_streams: OutboundBlobStreams::new(),
            workflow_tracker: WorkflowTracker::new(),
        }
    }

    async fn handle_frame(&mut self, frame: WsFrame) -> Result<(), String> {
        match frame {
            WsFrame::Request(frame) => {
                log::trace!(
                    "Admin WS frame Request (domain={}, action={}, connection_id={}, workflow_id={})",
                    frame.domain_id,
                    frame.action_id,
                    self.connection_id,
                    frame.workflow_id
                );
                self.handle_request(frame).await
            }
            WsFrame::Ack(frame) => {
                log::trace!(
                    "Admin WS frame Ack (stream_id={}, seq={})",
                    frame.stream_id,
                    frame.seq
                );
                self.handle_ack(frame).await
            }
            WsFrame::StreamChunk(frame) => {
                log::trace!(
                    "Admin WS frame StreamChunk (stream_id={}, seq={}, flags={})",
                    frame.stream_id,
                    frame.seq,
                    frame.flags
                );
                self.handle_stream_chunk(frame).await
            }
            _ => Ok(()),
        }
    }

    async fn handle_ping(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.session
            .pong(bytes)
            .await
            .map_err(|err| err.to_string())
    }

    fn awaiting_outbound_ack(&self) -> bool {
        self.outbound_streams.has_pending_ack()
    }

    async fn handle_request(&mut self, frame: RequestFrame) -> Result<(), String> {
        log::trace!(
            "Admin WS request received (domain={}, action={}, connection_id={}, workflow_id={})",
            frame.domain_id,
            frame.action_id,
            self.connection_id,
            frame.workflow_id
        );
        if let Err(err) = self.workflow_tracker.accept(frame.workflow_id) {
            let error_response =
                error_response(frame.workflow_id, &err.to_string(), &self.registry)?;
            self.send(&WsFrame::Response(error_response)).await?;
            return Ok(());
        }
        let request = match decode_request(
            &frame,
            &self.registry,
            self.connection_id,
            self.actor_email.clone(),
        ) {
            Ok(request) => request,
            Err(err) => {
                log::warn!(
                    "Admin WS request decode failed (domain={}, action={}, connection_id={}, workflow_id={}): {}",
                    frame.domain_id,
                    frame.action_id,
                    self.connection_id,
                    frame.workflow_id,
                    err
                );
                let error_response = error_response(frame.workflow_id, &err, &self.registry)?;
                self.send(&WsFrame::Response(error_response)).await?;
                return Ok(());
            }
        };
        let mut response = match self.bus.send_request(request).await {
            Ok(response) => response,
            Err(err) => {
                log::warn!(
                    "Admin WS request error (domain={}, action={}, connection_id={}, workflow_id={}): {}",
                    frame.domain_id,
                    frame.action_id,
                    self.connection_id,
                    frame.workflow_id,
                    err
                );
                let error_response =
                    error_response(frame.workflow_id, &format!("{}", err), &self.registry)?;
                self.send(&WsFrame::Response(error_response)).await?;
                return Ok(());
            }
        };

        let outbound_stream = self.prepare_outbound_stream(&mut response).await?;
        let response_frame = encode_response(&response, &self.registry)?;
        if !self.send_response(response_frame).await? {
            return Ok(());
        }
        if let Some((stream_id, producer)) = outbound_stream {
            self.outbound_streams.insert(stream_id, producer)?;
            self.send_next_outbound_chunk(stream_id).await?;
        }
        Ok(())
    }

    async fn handle_ack(&mut self, frame: StreamAckFrame) -> Result<(), String> {
        self.outbound_streams
            .ack(frame.stream_id, frame.seq)
            .map_err(|err| format!("Ack error: {}", err))?;
        self.send_next_outbound_chunk(frame.stream_id).await
    }

    async fn prepare_outbound_stream(
        &mut self,
        response: &mut ManagementResponse,
    ) -> Result<Option<(u32, BlobStreamProducer)>, String> {
        let stream_id = self.outbound_streams.allocate_stream_id()?;
        let Some(plan) = assign_content_stream_id(response, stream_id) else {
            return Ok(None);
        };
        let producer = open_content_blob_stream(&self.bus.context(), &plan)
            .await
            .map_err(stream_error_to_string)?;
        Ok(Some((stream_id, producer)))
    }

    async fn send_next_outbound_chunk(&mut self, stream_id: u32) -> Result<(), String> {
        let next = self
            .outbound_streams
            .next_chunk(stream_id)
            .await
            .map_err(stream_error_to_string)?;
        if let Some(chunk) = next {
            self.send(&WsFrame::StreamChunk(chunk)).await?;
        }
        Ok(())
    }

    async fn handle_stream_chunk(&mut self, frame: StreamChunkFrame) -> Result<(), String> {
        let is_final = frame.is_final();
        let is_compressed = frame.is_compressed();
        let stream_id = frame.stream_id;
        let seq = frame.seq;
        let payload = frame.payload;
        if let Err(err) = self
            .upload_registry
            .append_chunk(stream_id, payload, is_final, is_compressed)
            .await
        {
            let message = format!("Inbound stream error: {}", err);
            if let Err(err) = self.upload_registry.abort_stream(stream_id).await {
                log::warn!("Upload stream abort failed: {}", err);
            }
            return Err(message);
        }
        let ack = WsFrame::Ack(StreamAckFrame { stream_id, seq });
        self.send(&ack).await
    }

    async fn send_error(&mut self, message: &str) -> Result<(), String> {
        self.send(&WsFrame::Error(ErrorFrame {
            message: message.to_string(),
        }))
        .await
    }

    async fn send(&mut self, frame: &WsFrame) -> Result<(), String> {
        send_frame(&mut self.session, frame).await
    }

    async fn send_response(&mut self, frame: ResponseFrame) -> Result<bool, String> {
        let workflow_id = frame.workflow_id;
        let response = WsFrame::Response(frame);
        let bytes = match encode_frame(&response) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == WsProtocolErrorKind::FrameTooLarge => {
                let error = error_response(workflow_id, &err.to_string(), &self.registry)?;
                self.send(&WsFrame::Response(error)).await?;
                return Ok(false);
            }
            Err(err) => return Err(err.to_string()),
        };
        self.session
            .binary(bytes)
            .await
            .map_err(|err| err.to_string())?;
        Ok(true)
    }
}

struct OutboundBlobStream {
    producer: BlobStreamProducer,
    pending_seq: Option<u32>,
    final_sent: bool,
}

impl OutboundBlobStream {
    fn new(producer: BlobStreamProducer) -> Self {
        Self {
            producer,
            pending_seq: None,
            final_sent: false,
        }
    }

    fn ack(&mut self, stream_id: u32, seq: u32) -> Result<(), StreamError> {
        match self.pending_seq {
            Some(expected) if expected == seq => {
                self.pending_seq = None;
                Ok(())
            }
            Some(expected) => Err(StreamError::new(
                StreamErrorKind::AckMismatch,
                format!(
                    "Stream {} expected ack {}, got {}",
                    stream_id, expected, seq
                ),
            )),
            None => Err(StreamError::new(
                StreamErrorKind::AckMismatch,
                format!("Stream {} has no pending ack", stream_id),
            )),
        }
    }

    async fn next_chunk(&mut self) -> Result<Option<StreamChunkFrame>, StreamError> {
        if self.pending_seq.is_some() || self.final_sent {
            return Ok(None);
        }
        let chunk = self.producer.next_chunk().await?;
        if let Some(ref chunk) = chunk {
            self.pending_seq = Some(chunk.seq);
            if chunk.is_final() {
                self.final_sent = true;
            }
        }
        Ok(chunk)
    }

    fn is_done(&self) -> bool {
        self.pending_seq.is_none() && self.final_sent
    }
}

struct OutboundBlobStreams {
    next_stream_id: u32,
    streams: HashMap<u32, OutboundBlobStream>,
}

impl OutboundBlobStreams {
    fn new() -> Self {
        Self {
            next_stream_id: OUTBOUND_STREAM_ID_START,
            streams: HashMap::new(),
        }
    }

    fn allocate_stream_id(&mut self) -> Result<u32, String> {
        for _ in OUTBOUND_STREAM_ID_START..=u32::MAX {
            let stream_id = self.next_stream_id;
            self.next_stream_id = if self.next_stream_id == u32::MAX {
                OUTBOUND_STREAM_ID_START
            } else {
                self.next_stream_id + 1
            };
            if !self.streams.contains_key(&stream_id) {
                return Ok(stream_id);
            }
        }
        Err("Outbound stream id space exhausted".to_string())
    }

    fn insert(&mut self, stream_id: u32, producer: BlobStreamProducer) -> Result<(), String> {
        if stream_id < OUTBOUND_STREAM_ID_START {
            return Err("Outbound stream id is outside the outbound range".to_string());
        }
        if self
            .streams
            .insert(stream_id, OutboundBlobStream::new(producer))
            .is_some()
        {
            return Err(format!("Outbound stream {} already exists", stream_id));
        }
        Ok(())
    }

    fn ack(&mut self, stream_id: u32, seq: u32) -> Result<(), StreamError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| StreamError::new(StreamErrorKind::UnknownStream, "Stream not found"))?;
        stream.ack(stream_id, seq)
    }

    fn has_pending_ack(&self) -> bool {
        self.streams
            .values()
            .any(|stream| stream.pending_seq.is_some())
    }

    async fn next_chunk(
        &mut self,
        stream_id: u32,
    ) -> Result<Option<StreamChunkFrame>, StreamError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| StreamError::new(StreamErrorKind::UnknownStream, "Stream not found"))?;
        let chunk = stream.next_chunk().await?;
        if stream.is_done() {
            self.streams.remove(&stream_id);
        }
        Ok(chunk)
    }
}

fn stream_error_to_string(err: StreamError) -> String {
    format!("Outbound stream error: {}", err)
}

fn decode_request(
    frame: &RequestFrame,
    registry: &nop_management_bus::ManagementRegistry,
    connection_id: u32,
    actor_email: Option<String>,
) -> Result<ManagementRequest, String> {
    let key = DomainActionKey::new(frame.domain_id, frame.action_id);
    let codec = registry
        .codec_registry()
        .request_codec(&key)
        .ok_or_else(|| {
            format!(
                "No request codec for domain {} action {}",
                key.domain_id, key.action_id
            )
        })?;
    let command = codec
        .decode(&frame.payload)
        .map_err(|err| format!("Failed to decode request payload: {}", err))?;
    codec
        .validate(&command)
        .map_err(|err| format!("Request validation failed: {}", err))?;
    Ok(ManagementRequest {
        workflow_id: frame.workflow_id,
        connection_id,
        command,
        actor_email,
    })
}

fn encode_response(
    response: &ManagementResponse,
    registry: &nop_management_bus::ManagementRegistry,
) -> Result<ResponseFrame, String> {
    let key = DomainActionKey::new(response.domain_id, response.action_id);
    let codec = registry
        .codec_registry()
        .response_codec(&key)
        .ok_or_else(|| {
            format!(
                "No response codec for domain {} action {}",
                key.domain_id, key.action_id
            )
        })?;
    codec
        .validate(response)
        .map_err(|err| format!("Response validation failed: {}", err))?;
    let payload = codec
        .encode(response)
        .map_err(|err| format!("Failed to encode response payload: {}", err))?;
    Ok(ResponseFrame {
        domain_id: response.domain_id,
        action_id: response.action_id,
        workflow_id: response.workflow_id,
        payload,
    })
}

fn error_response(
    workflow_id: u32,
    message: &str,
    registry: &nop_management_bus::ManagementRegistry,
) -> Result<ResponseFrame, String> {
    let message = truncate_message(message);
    let response = ManagementResponse {
        domain_id: SYSTEM_DOMAIN_ID,
        action_id: SYSTEM_ACTION_PONG_ERROR,
        workflow_id,
        payload: nop_management_contract::ResponsePayload::Message(
            MessageResponse::new(message)
                .map_err(|err: nop_management_contract::ManagementError| err.to_string())?,
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
    use actix_web::web::Bytes;
    use actix_web::{App, HttpServer};
    use actix_ws::Item;
    use awc::Client;
    use awc::ws::{Frame as ClientFrame, Message as ClientMessage};
    use futures_util::SinkExt;
    use nop_config::{DevMode, ValidatedConfig};
    use nop_content_store::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, content_id_hex, sidecar_path,
        write_sidecar_atomic,
    };
    use nop_management_bus::ws::STREAM_FLAG_FINAL;
    use nop_management_bus::ws::{AuthFrame, WS_MAX_STREAM_CHUNK_BYTES};
    use nop_management_bus::{VersionInfo, build_default_registry};
    use nop_management_contract::content::{
        BinaryUploadCommitRequest, BinaryUploadInitRequest, CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
        CONTENT_ACTION_BINARY_UPLOAD_INIT, CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_OK, CONTENT_ACTION_READ, CONTENT_ACTION_READ_ERR,
        CONTENT_ACTION_READ_OK, CONTENT_DOMAIN_ID, ContentReadRequest, ContentReadResponse,
        UploadStreamInitResponse,
    };
    use nop_management_contract::system::{
        GetLoggingConfigRequest, LoggingConfigResponse, PingRequest, SYSTEM_ACTION_LOGGING_GET,
        SYSTEM_ACTION_LOGGING_GET_OK, SYSTEM_ACTION_PING, SYSTEM_ACTION_PONG, SYSTEM_DOMAIN_ID,
    };
    use nop_management_contract::{
        MessageResponse, WireDecode, WireEncode, WireReader, WireWriter,
    };
    use nop_rt_csrf::CsrfTokenStore;
    use nop_testing::test_config::TestConfigBuilder;
    use nop_testing::test_runtime_paths::short_runtime_paths;
    use std::net::TcpListener;
    use tempfile::TempDir;
    use tokio::time::{Duration, timeout};

    fn encode_payload<T: WireEncode>(payload: &T) -> Vec<u8> {
        let mut writer = WireWriter::new();
        payload.encode(&mut writer).expect("encode payload");
        writer.into_bytes()
    }

    fn decode_payload<T: WireDecode>(bytes: &[u8]) -> T {
        let mut reader = WireReader::new(bytes);
        let payload = T::decode(&mut reader).expect("decode payload");
        reader
            .ensure_fully_consumed()
            .expect("payload fully consumed");
        payload
    }

    fn build_test_config(dev_mode: Option<DevMode>) -> ValidatedConfig {
        let mut config = TestConfigBuilder::new()
            .with_streaming(false)
            .with_dev_mode(dev_mode)
            .build();
        config.server.port = 0;
        if let Some(server) = config.servers.first_mut() {
            server.port = 0;
        }
        config.security.max_violations = 10;
        config.security.cooldown_seconds = 60;
        config.upload.allowed_extensions = vec!["md".to_string()];
        config
    }

    fn expected_binary_content() -> Vec<u8> {
        (0..(WS_MAX_STREAM_CHUNK_BYTES + 37))
            .map(|index| (index % 251) as u8)
            .collect()
    }

    fn expected_small_markdown_content() -> &'static str {
        "# Small\r\n\nInline editor source.\r\n"
    }

    fn expected_large_markdown_content() -> Vec<u8> {
        let mut body = b"# Large\r\n".to_vec();
        body.extend(std::iter::repeat_n(
            b'a',
            WS_MAX_STREAM_CHUNK_BYTES - body.len() - 1,
        ));
        body.extend_from_slice("€".as_bytes());
        body.extend_from_slice(b"\r\nTrailing CRLF line.\r\n");
        body
    }

    fn seed_ws_content(runtime_paths: &nop_rt_paths::RuntimePaths) {
        let content_id = ContentId(4);
        let version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, version);
        if let Some(parent) = blob.parent() {
            std::fs::create_dir_all(parent).expect("create content shard");
        }
        std::fs::write(&blob, expected_binary_content()).expect("write binary content");

        let sidecar = ContentSidecar {
            alias: "assets/large.bin".to_string(),
            title: Some("Large Binary".to_string()),
            mime: "application/octet-stream".to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            disable_navbar: false,
            disable_floating_nav: false,
            content_width: Default::default(),
            original_filename: Some("large.bin".to_string()),
            theme: None,
        };
        let sidecar_file = sidecar_path(&runtime_paths.content_dir, content_id, version);
        write_sidecar_atomic(&sidecar_file, &sidecar).expect("write content sidecar");

        let content_id = ContentId(5);
        let version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, version);
        if let Some(parent) = blob.parent() {
            std::fs::create_dir_all(parent).expect("create markdown shard");
        }
        std::fs::write(&blob, expected_small_markdown_content()).expect("write small markdown");

        let sidecar = ContentSidecar {
            alias: "docs/small".to_string(),
            title: Some("Small Markdown".to_string()),
            mime: "text/markdown".to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            disable_navbar: false,
            disable_floating_nav: false,
            content_width: Default::default(),
            original_filename: Some("small.md".to_string()),
            theme: None,
        };
        let sidecar_file = sidecar_path(&runtime_paths.content_dir, content_id, version);
        write_sidecar_atomic(&sidecar_file, &sidecar).expect("write small markdown sidecar");

        let content_id = ContentId(6);
        let version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, version);
        if let Some(parent) = blob.parent() {
            std::fs::create_dir_all(parent).expect("create markdown shard");
        }
        std::fs::write(&blob, expected_large_markdown_content()).expect("write large markdown");

        let sidecar = ContentSidecar {
            alias: "docs/large".to_string(),
            title: Some("Large Markdown".to_string()),
            mime: "text/markdown".to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            disable_navbar: false,
            disable_floating_nav: false,
            content_width: Default::default(),
            original_filename: Some("large.md".to_string()),
            theme: None,
        };
        let sidecar_file = sidecar_path(&runtime_paths.content_dir, content_id, version);
        write_sidecar_atomic(&sidecar_file, &sidecar).expect("write large markdown sidecar");
    }

    async fn start_test_server() -> (String, Arc<WsTicketStore>, Arc<CsrfTokenStore>, TempDir) {
        let config = build_test_config(Some(DevMode::Localhost));
        let csrf_store = Arc::new(CsrfTokenStore::new(&config));
        let ticket_store = Arc::new(WsTicketStore::new_with_expiry(Duration::from_secs(2)));

        let (temp_dir, runtime_paths) = short_runtime_paths("ws-test");
        seed_ws_content(&runtime_paths);
        let registry = build_default_registry().expect("registry");
        let upload_registry = Arc::new(nop_management_bus::UploadRegistry::new());
        let context = nop_management_bus::ManagementContext::from_components(
            runtime_paths.root.clone(),
            Arc::new(config.clone()),
            runtime_paths.clone(),
        )
        .expect("context")
        .with_upload_registry(upload_registry.clone());
        let bus = ManagementBus::start(registry, context);
        let management_tools = ManagementTools::new(bus, upload_registry);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();

        let csrf_store_clone = csrf_store.clone();
        let ticket_store_clone = ticket_store.clone();
        let management_tools = Arc::new(management_tools);

        actix_web::rt::spawn(async move {
            let _ = HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(config.clone()))
                    .app_data(web::Data::from(management_tools.clone()))
                    .app_data(web::Data::from(csrf_store_clone.clone()))
                    .app_data(web::Data::from(ticket_store_clone.clone()))
                    .route("/admin/ws", web::get().to(management_ws))
            })
            .listen(listener)
            .unwrap()
            .run()
            .await;
        });

        (
            format!("http://{}", addr),
            ticket_store,
            csrf_store,
            temp_dir,
        )
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_rejects_non_auth_first_frame() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");
        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let version = VersionInfo::from_pkg_version().unwrap();
        let ping_payload = encode_payload(&PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        });
        let frame = WsFrame::Request(RequestFrame {
            domain_id: SYSTEM_DOMAIN_ID,
            action_id: SYSTEM_ACTION_PING,
            workflow_id: 1,
            payload: ping_payload,
        });
        let bytes = encode_frame(&frame).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                assert!(matches!(frame, WsFrame::AuthErr(_)));
            }
            _ => panic!("expected binary auth error"),
        }

        let _ = ticket;
        let _ = csrf;
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_accepts_auth_and_handles_ping() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        let bytes = encode_frame(&auth).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                assert!(matches!(frame, WsFrame::AuthOk(_)));
            }
            _ => panic!("expected auth ok"),
        }

        let version = VersionInfo::from_pkg_version().unwrap();
        let ping_payload = encode_payload(&PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        });
        let ping = WsFrame::Request(RequestFrame {
            domain_id: SYSTEM_DOMAIN_ID,
            action_id: SYSTEM_ACTION_PING,
            workflow_id: 1,
            payload: ping_payload,
        });
        let bytes = encode_frame(&ping).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                match frame {
                    WsFrame::Response(response) => {
                        assert_eq!(response.domain_id, SYSTEM_DOMAIN_ID);
                        assert_eq!(response.action_id, SYSTEM_ACTION_PONG);
                    }
                    _ => panic!("expected response frame"),
                }
            }
            _ => panic!("expected binary response"),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_aggregates_auth_continuations() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        let bytes = encode_frame(&auth).unwrap();
        let split_at = bytes.len() / 2;
        let first = Bytes::copy_from_slice(&bytes[..split_at]);
        let last = Bytes::copy_from_slice(&bytes[split_at..]);

        framed
            .send(ClientMessage::Continuation(Item::FirstBinary(first)))
            .await
            .unwrap();
        framed
            .send(ClientMessage::Continuation(Item::Last(last)))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                assert!(matches!(frame, WsFrame::AuthOk(_)));
            }
            _ => panic!("expected auth ok"),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_streams_binary_upload_chunks() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        let bytes = encode_frame(&auth).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                assert!(matches!(frame, WsFrame::AuthOk(_)));
            }
            _ => panic!("expected auth ok"),
        }

        let init_request = BinaryUploadInitRequest {
            alias: Some("files/streamed-large.md".to_string()),
            title: Some("Streamed Large".to_string()),
            tags: Vec::new(),
            filename: "streamed-large.md".to_string(),
            mime: "text/markdown".to_string(),
            size_bytes: 512 * 1024,
        };
        let payload = encode_payload(&init_request);
        let init_frame = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_BINARY_UPLOAD_INIT,
            workflow_id: 1,
            payload,
        });
        let bytes = encode_frame(&init_frame).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        let init = match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                match frame {
                    WsFrame::Response(response) => {
                        assert_eq!(response.domain_id, CONTENT_DOMAIN_ID);
                        if response.action_id == CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR {
                            let message =
                                decode_payload::<MessageResponse>(&response.payload).message;
                            panic!("binary upload init failed: {}", message);
                        }
                        assert_eq!(response.action_id, CONTENT_ACTION_BINARY_UPLOAD_INIT_OK);
                        decode_payload::<UploadStreamInitResponse>(&response.payload)
                    }
                    other => panic!("expected response frame, got {:?}", other),
                }
            }
            _ => panic!("expected binary init response"),
        };

        let chunk_size = init.chunk_bytes as usize;
        let mut remaining = init_request.size_bytes as usize;
        let mut seq = 0;

        while remaining > 0 {
            let chunk_len = remaining.min(chunk_size);
            let is_final = chunk_len == remaining;
            let chunk = WsFrame::StreamChunk(StreamChunkFrame {
                stream_id: init.stream_id,
                seq,
                flags: if is_final { STREAM_FLAG_FINAL } else { 0 },
                payload: vec![0x61; chunk_len],
            });

            framed
                .send(ClientMessage::Binary(encode_frame(&chunk).unwrap().into()))
                .await
                .unwrap();
            let response = timeout(Duration::from_secs(2), framed.next())
                .await
                .expect("ack timeout")
                .expect("ack frame")
                .expect("ack payload");
            match response {
                ClientFrame::Binary(bytes) => {
                    let frame = decode_frame(&bytes).unwrap();
                    match frame {
                        WsFrame::Ack(ack) => {
                            assert_eq!(ack.stream_id, init.stream_id);
                            assert_eq!(ack.seq, seq);
                        }
                        other => panic!("expected ack, got {:?}", other),
                    }
                }
                _ => panic!("expected binary ack"),
            }

            remaining -= chunk_len;
            seq += 1;
        }

        let commit_request = BinaryUploadCommitRequest {
            upload_id: init.upload_id,
        };
        let payload = encode_payload(&commit_request);
        let commit_frame = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
            workflow_id: 2,
            payload,
        });
        let bytes = encode_frame(&commit_frame).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                match frame {
                    WsFrame::Response(response) => {
                        assert_eq!(response.domain_id, CONTENT_DOMAIN_ID);
                        if response.action_id == CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR {
                            let message =
                                decode_payload::<MessageResponse>(&response.payload).message;
                            panic!("binary upload commit failed: {}", message);
                        }
                        assert_eq!(response.action_id, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK);
                    }
                    other => panic!("expected response frame, got {:?}", other),
                }
            }
            _ => panic!("expected binary commit response"),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_streams_content_read_chunks_with_ack_gating() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        framed
            .send(ClientMessage::Binary(encode_frame(&auth).unwrap().into()))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        assert!(matches!(
            response,
            ClientFrame::Binary(bytes) if matches!(decode_frame(&bytes).unwrap(), WsFrame::AuthOk(_))
        ));

        let read_request = ContentReadRequest {
            id: content_id_hex(ContentId(4)),
            stream_content: Some(true),
        };
        let request = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ,
            workflow_id: 1,
            payload: encode_payload(&read_request),
        });
        framed
            .send(ClientMessage::Binary(
                encode_frame(&request).unwrap().into(),
            ))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        let read_response = match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Response(response) => {
                    assert_eq!(response.domain_id, CONTENT_DOMAIN_ID);
                    assert_eq!(response.action_id, CONTENT_ACTION_READ_OK);
                    decode_payload::<ContentReadResponse>(&response.payload)
                }
                other => panic!("expected content read response, got {:?}", other),
            },
            _ => panic!("expected binary content read response"),
        };
        assert!(read_response.content.is_none());
        let stream_id = read_response.stream_id.expect("stream id");
        let chunk_bytes = read_response.chunk_bytes.expect("chunk bytes") as usize;
        assert!(stream_id >= OUTBOUND_STREAM_ID_START);
        assert_eq!(
            read_response.size_bytes.expect("size bytes") as usize,
            expected_binary_content().len()
        );

        let first = framed.next().await.unwrap().unwrap();
        let first = match first {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::StreamChunk(chunk) => chunk,
                other => panic!("expected first stream chunk, got {:?}", other),
            },
            _ => panic!("expected binary stream chunk"),
        };
        assert_eq!(first.stream_id, stream_id);
        assert_eq!(first.seq, 0);
        assert_eq!(first.payload.len(), chunk_bytes);
        assert!(!first.is_final());

        framed
            .send(ClientMessage::Ping(Bytes::from_static(b"gate")))
            .await
            .unwrap();
        let pong = framed.next().await.unwrap().unwrap();
        assert!(matches!(pong, ClientFrame::Pong(_)));

        framed
            .send(ClientMessage::Binary(
                encode_frame(&WsFrame::Ack(StreamAckFrame { stream_id, seq: 0 }))
                    .unwrap()
                    .into(),
            ))
            .await
            .unwrap();
        let second = framed.next().await.unwrap().unwrap();
        let second = match second {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::StreamChunk(chunk) => chunk,
                other => panic!("expected second stream chunk, got {:?}", other),
            },
            _ => panic!("expected binary stream chunk"),
        };
        assert_eq!(second.stream_id, stream_id);
        assert_eq!(second.seq, 1);
        assert!(second.is_final());

        let mut received = first.payload;
        received.extend_from_slice(&second.payload);
        assert_eq!(received, expected_binary_content());

        framed
            .send(ClientMessage::Binary(
                encode_frame(&WsFrame::Ack(StreamAckFrame { stream_id, seq: 1 }))
                    .unwrap()
                    .into(),
            ))
            .await
            .unwrap();

        let payload = encode_payload(&GetLoggingConfigRequest {});
        let request = WsFrame::Request(RequestFrame {
            domain_id: SYSTEM_DOMAIN_ID,
            action_id: SYSTEM_ACTION_LOGGING_GET,
            workflow_id: 2,
            payload,
        });
        framed
            .send(ClientMessage::Binary(
                encode_frame(&request).unwrap().into(),
            ))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Response(response) => {
                    assert_eq!(response.domain_id, SYSTEM_DOMAIN_ID);
                    assert_eq!(response.action_id, SYSTEM_ACTION_LOGGING_GET_OK);
                }
                other => panic!("expected logging response, got {:?}", other),
            },
            _ => panic!("expected binary logging response"),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_returns_small_markdown_inline_with_stream_flag() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        framed
            .send(ClientMessage::Binary(encode_frame(&auth).unwrap().into()))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        assert!(matches!(
            response,
            ClientFrame::Binary(bytes) if matches!(decode_frame(&bytes).unwrap(), WsFrame::AuthOk(_))
        ));

        let read_request = ContentReadRequest {
            id: content_id_hex(ContentId(5)),
            stream_content: Some(true),
        };
        let request = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ,
            workflow_id: 1,
            payload: encode_payload(&read_request),
        });
        framed
            .send(ClientMessage::Binary(
                encode_frame(&request).unwrap().into(),
            ))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Response(response) => {
                    assert_eq!(response.domain_id, CONTENT_DOMAIN_ID);
                    assert_eq!(response.action_id, CONTENT_ACTION_READ_OK);
                    let payload = decode_payload::<ContentReadResponse>(&response.payload);
                    assert_eq!(
                        payload.content.as_deref(),
                        Some(expected_small_markdown_content())
                    );
                    assert!(payload.stream_id.is_none());
                    assert!(payload.chunk_bytes.is_none());
                    assert!(payload.size_bytes.is_none());
                }
                other => panic!("expected content read response, got {:?}", other),
            },
            _ => panic!("expected binary content read response"),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_streams_large_markdown_read_as_raw_bytes() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let expected = expected_large_markdown_content();
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        framed
            .send(ClientMessage::Binary(encode_frame(&auth).unwrap().into()))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        assert!(matches!(
            response,
            ClientFrame::Binary(bytes) if matches!(decode_frame(&bytes).unwrap(), WsFrame::AuthOk(_))
        ));

        let read_request = ContentReadRequest {
            id: content_id_hex(ContentId(6)),
            stream_content: Some(true),
        };
        let request = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ,
            workflow_id: 1,
            payload: encode_payload(&read_request),
        });
        framed
            .send(ClientMessage::Binary(
                encode_frame(&request).unwrap().into(),
            ))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        let stream_id = match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Response(response) => {
                    assert_eq!(response.domain_id, CONTENT_DOMAIN_ID);
                    assert_eq!(response.action_id, CONTENT_ACTION_READ_OK);
                    let payload = decode_payload::<ContentReadResponse>(&response.payload);
                    assert!(payload.content.is_none());
                    assert_eq!(payload.size_bytes, Some(expected.len() as u64));
                    assert_eq!(payload.chunk_bytes, Some(WS_MAX_STREAM_CHUNK_BYTES as u32));
                    payload.stream_id.expect("stream id")
                }
                other => panic!("expected content read response, got {:?}", other),
            },
            _ => panic!("expected binary content read response"),
        };

        let mut received = Vec::new();
        let mut seq = 0;
        loop {
            let frame = framed.next().await.unwrap().unwrap();
            let chunk = match frame {
                ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                    WsFrame::StreamChunk(chunk) => chunk,
                    other => panic!("expected stream chunk, got {:?}", other),
                },
                other => panic!("expected binary stream chunk, got {:?}", other),
            };
            assert_eq!(chunk.stream_id, stream_id);
            assert_eq!(chunk.seq, seq);
            assert!(chunk.payload.len() <= WS_MAX_STREAM_CHUNK_BYTES);
            let final_chunk = chunk.is_final();
            received.extend_from_slice(&chunk.payload);
            framed
                .send(ClientMessage::Binary(
                    encode_frame(&WsFrame::Ack(StreamAckFrame { stream_id, seq }))
                        .unwrap()
                        .into(),
                ))
                .await
                .unwrap();
            if final_chunk {
                break;
            }
            seq += 1;
        }

        assert_eq!(received.len(), expected.len());
        assert_eq!(received, expected);
        assert!(
            String::from_utf8(received)
                .unwrap()
                .contains("€\r\nTrailing")
        );
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_rejects_large_markdown_without_stream_flag() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        framed
            .send(ClientMessage::Binary(encode_frame(&auth).unwrap().into()))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        assert!(matches!(
            response,
            ClientFrame::Binary(bytes) if matches!(decode_frame(&bytes).unwrap(), WsFrame::AuthOk(_))
        ));

        let read_request = ContentReadRequest {
            id: content_id_hex(ContentId(6)),
            stream_content: None,
        };
        let request = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ,
            workflow_id: 1,
            payload: encode_payload(&read_request),
        });
        framed
            .send(ClientMessage::Binary(
                encode_frame(&request).unwrap().into(),
            ))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Response(response) => {
                    assert_eq!(response.domain_id, CONTENT_DOMAIN_ID);
                    assert_eq!(response.action_id, CONTENT_ACTION_READ_ERR);
                    let payload = decode_payload::<MessageResponse>(&response.payload);
                    assert!(payload.message.contains("request streaming content"));
                }
                other => panic!("expected content read error response, got {:?}", other),
            },
            _ => panic!("expected binary content read response"),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_rejects_malformed_content_stream_ack() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        framed
            .send(ClientMessage::Binary(encode_frame(&auth).unwrap().into()))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        assert!(matches!(
            response,
            ClientFrame::Binary(bytes) if matches!(decode_frame(&bytes).unwrap(), WsFrame::AuthOk(_))
        ));

        let read_request = ContentReadRequest {
            id: content_id_hex(ContentId(4)),
            stream_content: Some(true),
        };
        let request = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ,
            workflow_id: 1,
            payload: encode_payload(&read_request),
        });
        framed
            .send(ClientMessage::Binary(
                encode_frame(&request).unwrap().into(),
            ))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        let stream_id = match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Response(response) => {
                    let payload = decode_payload::<ContentReadResponse>(&response.payload);
                    payload.stream_id.expect("stream id")
                }
                other => panic!("expected content read response, got {:?}", other),
            },
            _ => panic!("expected binary content read response"),
        };
        let first = framed.next().await.unwrap().unwrap();
        match first {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::StreamChunk(chunk) => {
                    assert_eq!(chunk.stream_id, stream_id);
                    assert_eq!(chunk.seq, 0);
                }
                other => panic!("expected first stream chunk, got {:?}", other),
            },
            _ => panic!("expected binary stream chunk"),
        }

        framed
            .send(ClientMessage::Binary(
                encode_frame(&WsFrame::Ack(StreamAckFrame { stream_id, seq: 1 }))
                    .unwrap()
                    .into(),
            ))
            .await
            .unwrap();
        let response = timeout(Duration::from_secs(2), framed.next())
            .await
            .expect("error timeout")
            .expect("error frame")
            .expect("error payload");
        match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Error(error) => assert!(error.message.contains("Ack error")),
                other => panic!("expected error frame, got {:?}", other),
            },
            other => panic!("expected binary error frame, got {:?}", other),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_times_out_unacked_content_stream() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        framed
            .send(ClientMessage::Binary(encode_frame(&auth).unwrap().into()))
            .await
            .unwrap();
        let response = framed.next().await.unwrap().unwrap();
        assert!(matches!(
            response,
            ClientFrame::Binary(bytes) if matches!(decode_frame(&bytes).unwrap(), WsFrame::AuthOk(_))
        ));

        let read_request = ContentReadRequest {
            id: content_id_hex(ContentId(4)),
            stream_content: Some(true),
        };
        let request = WsFrame::Request(RequestFrame {
            domain_id: CONTENT_DOMAIN_ID,
            action_id: CONTENT_ACTION_READ,
            workflow_id: 1,
            payload: encode_payload(&read_request),
        });
        framed
            .send(ClientMessage::Binary(
                encode_frame(&request).unwrap().into(),
            ))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Response(response) => {
                    let payload = decode_payload::<ContentReadResponse>(&response.payload);
                    assert!(payload.stream_id.is_some());
                }
                other => panic!("expected content read response, got {:?}", other),
            },
            _ => panic!("expected binary content read response"),
        }

        let first = framed.next().await.unwrap().unwrap();
        match first {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::StreamChunk(chunk) => {
                    assert_eq!(chunk.seq, 0);
                    assert!(!chunk.is_final());
                }
                other => panic!("expected first stream chunk, got {:?}", other),
            },
            _ => panic!("expected binary stream chunk"),
        }

        let response = timeout(Duration::from_secs(2), framed.next())
            .await
            .expect("timeout error frame")
            .expect("error frame")
            .expect("error payload");
        match response {
            ClientFrame::Binary(bytes) => match decode_frame(&bytes).unwrap() {
                WsFrame::Error(error) => assert!(error.message.contains("ack timed out")),
                other => panic!("expected error frame, got {:?}", other),
            },
            other => panic!("expected binary error frame, got {:?}", other),
        }
    }

    #[cfg(debug_assertions)]
    #[actix_web::test]
    async fn ws_accepts_auth_and_handles_logging_get() {
        let (base_url, ticket_store, csrf_store, _temp_dir) = start_test_server().await;
        let ticket = ticket_store.issue("localhost");
        let csrf = csrf_store.get_or_refresh_token("localhost");

        let client = Client::new();
        let (_resp, mut framed) = client
            .ws(format!("{}/admin/ws", base_url))
            .connect()
            .await
            .expect("connect");

        let auth = WsFrame::Auth(AuthFrame {
            ticket,
            csrf_token: csrf,
        });
        let bytes = encode_frame(&auth).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                assert!(matches!(frame, WsFrame::AuthOk(_)));
            }
            _ => panic!("expected auth ok"),
        }

        let payload = encode_payload(&GetLoggingConfigRequest {});
        let request = WsFrame::Request(RequestFrame {
            domain_id: SYSTEM_DOMAIN_ID,
            action_id: SYSTEM_ACTION_LOGGING_GET,
            workflow_id: 1,
            payload,
        });
        let bytes = encode_frame(&request).unwrap();
        framed
            .send(ClientMessage::Binary(bytes.into()))
            .await
            .unwrap();

        let response = framed.next().await.unwrap().unwrap();
        match response {
            ClientFrame::Binary(bytes) => {
                let frame = decode_frame(&bytes).unwrap();
                match frame {
                    WsFrame::Response(response) => {
                        assert_eq!(response.domain_id, SYSTEM_DOMAIN_ID);
                        assert_eq!(response.action_id, SYSTEM_ACTION_LOGGING_GET_OK);
                        let config: LoggingConfigResponse = decode_payload(&response.payload);
                        assert_eq!(config.rotation_max_size_mb, 16);
                        assert_eq!(config.rotation_max_files, 10);
                    }
                    _ => panic!("expected response frame"),
                }
            }
            _ => panic!("expected binary response"),
        }
    }
}
