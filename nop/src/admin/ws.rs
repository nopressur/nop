// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::admin::ws_auth;
use crate::app_state::AppState;
use crate::config::ValidatedConfig;
use crate::management::ManagementBus;
use crate::management::UploadRegistry;
use crate::management::ws::{
    AuthResponseFrame, ErrorFrame, RequestFrame, ResponseFrame, StreamAckFrame, StreamChunkFrame,
    StreamTracker, WS_MAX_MESSAGE_BYTES, WsFrame, decode_frame, encode_frame,
};
use crate::management::{
    DomainActionKey, ManagementRequest, ManagementResponse, MessageResponse,
    SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID, WorkflowTracker,
};
use crate::util::{CsrfTokenStore, WsTicketStore};
use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::{AggregatedMessage, AggregatedMessageStream, Session};
use futures_util::StreamExt;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(not(test))]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn ws_ticket(
    req: HttpRequest,
    ticket_store: web::Data<WsTicketStore>,
    config: web::Data<ValidatedConfig>,
) -> Result<HttpResponse> {
    log::debug!("Admin WS ticket request received");
    if let Err(response) = ws_auth::require_validated_csrf(&req) {
        return Ok(response);
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
    app_state: web::Data<AppState>,
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

    log::debug!("Admin WS connection starting");
    let (response, session, message_stream) = actix_ws::handle(&req, stream)?;
    let message_stream = message_stream
        .max_frame_size(WS_MAX_MESSAGE_BYTES)
        .aggregate_continuations()
        .max_continuation_size(WS_MAX_MESSAGE_BYTES);
    let bus = app_state.management_bus.clone();
    let registry = bus.registry();
    let upload_registry = app_state.upload_registry.clone();
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
    registry: Arc<crate::management::ManagementRegistry>,
    csrf_store: Arc<CsrfTokenStore>,
    ticket_store: Arc<WsTicketStore>,
    jwt_id: String,
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

    let connection_id = crate::management::next_connection_id();
    let mut coordinator = WsCoordinator::new(
        session,
        bus,
        registry,
        upload_registry.clone(),
        connection_id,
    );
    while let Some(message) = messages.next().await {
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
    registry: Arc<crate::management::ManagementRegistry>,
    upload_registry: Arc<UploadRegistry>,
    connection_id: u32,
    outbound_streams: StreamTracker,
    workflow_tracker: WorkflowTracker,
}

impl WsCoordinator {
    fn new(
        session: Session,
        bus: ManagementBus,
        registry: Arc<crate::management::ManagementRegistry>,
        upload_registry: Arc<UploadRegistry>,
        connection_id: u32,
    ) -> Self {
        Self {
            session,
            bus,
            registry,
            upload_registry,
            connection_id,
            outbound_streams: StreamTracker::new(),
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
        let request = match decode_request(&frame, &self.registry, self.connection_id) {
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
        let response = match self.bus.send_request(request).await {
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

        let response_frame = encode_response(&response, &self.registry)?;
        self.send(&WsFrame::Response(response_frame)).await
    }

    async fn handle_ack(&mut self, frame: StreamAckFrame) -> Result<(), String> {
        if let Err(err) = self.outbound_streams.ack(frame.stream_id, frame.seq) {
            return Err(format!("Ack error: {}", err));
        }
        if let Some(next) = self.outbound_streams.next_chunk(frame.stream_id) {
            self.send(&WsFrame::StreamChunk(next)).await?;
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
}

fn decode_request(
    frame: &RequestFrame,
    registry: &crate::management::ManagementRegistry,
    connection_id: u32,
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
    })
}

fn encode_response(
    response: &ManagementResponse,
    registry: &crate::management::ManagementRegistry,
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
    registry: &crate::management::ManagementRegistry,
) -> Result<ResponseFrame, String> {
    let message = truncate_message(message);
    let response = ManagementResponse {
        domain_id: SYSTEM_DOMAIN_ID,
        action_id: SYSTEM_ACTION_PONG_ERROR,
        workflow_id,
        payload: crate::management::ResponsePayload::Message(
            MessageResponse::new(message).map_err(|err| err.to_string())?,
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
    use crate::config::{DevMode, ValidatedConfig};
    use crate::management::ws::AuthFrame;
    use crate::management::ws::STREAM_FLAG_FINAL;
    use crate::management::{
        BinaryUploadCommitRequest, BinaryUploadInitRequest, CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
        CONTENT_ACTION_BINARY_UPLOAD_INIT, CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_OK, CONTENT_DOMAIN_ID, MessageResponse,
        UploadStreamInitResponse, VersionInfo, WireDecode, WireEncode, WireReader, WireWriter,
        build_default_registry,
    };
    use crate::util::CsrfTokenStore;
    use crate::util::short_runtime_paths;
    use crate::util::test_config::TestConfigBuilder;
    use actix_web::web::Bytes;
    use actix_web::{App, HttpServer};
    use actix_ws::Item;
    use awc::Client;
    use awc::ws::{Frame as ClientFrame, Message as ClientMessage};
    use futures_util::SinkExt;
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

    async fn start_test_server() -> (String, Arc<WsTicketStore>, Arc<CsrfTokenStore>, TempDir) {
        let config = build_test_config(Some(DevMode::Localhost));
        let csrf_store = Arc::new(CsrfTokenStore::new(&config));
        let ticket_store = Arc::new(WsTicketStore::new_with_expiry(Duration::from_secs(2)));

        let (temp_dir, runtime_paths) = short_runtime_paths("ws-test");
        let registry = build_default_registry().expect("registry");
        let upload_registry = Arc::new(crate::management::UploadRegistry::new());
        let context = crate::management::ManagementContext::from_components(
            runtime_paths.root.clone(),
            Arc::new(config.clone()),
            runtime_paths.clone(),
        )
        .expect("context")
        .with_upload_registry(upload_registry.clone());
        let bus = ManagementBus::start(registry, context);
        let app_state = AppState::new("Test", runtime_paths, bus, upload_registry);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();

        let csrf_store_clone = csrf_store.clone();
        let ticket_store_clone = ticket_store.clone();
        let app_state = Arc::new(app_state);

        actix_web::rt::spawn(async move {
            let _ = HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(config.clone()))
                    .app_data(web::Data::from(app_state.clone()))
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
        let ping_payload = encode_payload(&crate::management::PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        });
        let frame = WsFrame::Request(RequestFrame {
            domain_id: SYSTEM_DOMAIN_ID,
            action_id: crate::management::SYSTEM_ACTION_PING,
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
        let ping_payload = encode_payload(&crate::management::PingRequest {
            version_major: version.major,
            version_minor: version.minor,
            version_patch: version.patch,
        });
        let ping = WsFrame::Request(RequestFrame {
            domain_id: SYSTEM_DOMAIN_ID,
            action_id: crate::management::SYSTEM_ACTION_PING,
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
                        assert_eq!(response.action_id, crate::management::SYSTEM_ACTION_PONG);
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

        let payload = encode_payload(&crate::management::GetLoggingConfigRequest {});
        let request = WsFrame::Request(RequestFrame {
            domain_id: SYSTEM_DOMAIN_ID,
            action_id: crate::management::SYSTEM_ACTION_LOGGING_GET,
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
                        assert_eq!(
                            response.action_id,
                            crate::management::SYSTEM_ACTION_LOGGING_GET_OK
                        );
                        let config: crate::management::LoggingConfigResponse =
                            decode_payload(&response.payload);
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
