// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::Config;
use crate::management::codec::{
    FieldLimit, FieldLimits, FieldValues, RequestCodec, ResponseCodec, validate_field_limits,
};
use crate::management::core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse, MessageResponse,
    ResponsePayload,
};
use crate::management::errors::{DomainError, DomainResult, ManagementErrorKind};
use crate::management::registry::{DomainActionKey, ManagementHandler, ManagementRegistry};
use crate::management::{
    CodecError, RegistryError, WireDecode, WireEncode, WireReader, WireResult, WireWriter,
};
use crate::util::log_rotation::{LogRotationSettings, LogRunMode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub const SYSTEM_DOMAIN_ID: u32 = 0;
pub const SYSTEM_ACTION_PING: u32 = 1;
pub const SYSTEM_ACTION_PONG: u32 = 2;
pub const SYSTEM_ACTION_PONG_ERROR: u32 = 3;
pub const SYSTEM_ACTION_LOGGING_GET: u32 = 4;
pub const SYSTEM_ACTION_LOGGING_GET_OK: u32 = 5;
pub const SYSTEM_ACTION_LOGGING_GET_ERR: u32 = 6;
pub const SYSTEM_ACTION_LOGGING_SET: u32 = 7;
pub const SYSTEM_ACTION_LOGGING_SET_OK: u32 = 8;
pub const SYSTEM_ACTION_LOGGING_SET_ERR: u32 = 9;
pub const SYSTEM_ACTION_LOGGING_CLEAR: u32 = 10;
pub const SYSTEM_ACTION_LOGGING_CLEAR_OK: u32 = 11;
pub const SYSTEM_ACTION_LOGGING_CLEAR_ERR: u32 = 12;

#[derive(Debug, Clone)]
pub enum SystemCommand {
    Ping(PingRequest),
    GetLoggingConfig(GetLoggingConfigRequest),
    SetLoggingConfig(SetLoggingConfigRequest),
    ClearLogs(ClearLogsRequest),
}

impl SystemCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            SystemCommand::Ping(_) => SYSTEM_ACTION_PING,
            SystemCommand::GetLoggingConfig(_) => SYSTEM_ACTION_LOGGING_GET,
            SystemCommand::SetLoggingConfig(_) => SYSTEM_ACTION_LOGGING_SET,
            SystemCommand::ClearLogs(_) => SYSTEM_ACTION_LOGGING_CLEAR,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest {
    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongErrorResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLoggingConfigRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLoggingConfigRequest {
    pub rotation_max_size_mb: u64,
    pub rotation_max_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearLogsRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfigResponse {
    pub level: String,
    pub rotation_max_size_mb: u64,
    pub rotation_max_files: u32,
    pub run_mode: String,
    pub file_logging_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearLogsResponse {
    pub message: String,
    pub deleted_files: u64,
    pub deleted_bytes: u64,
}

impl WireEncode for PingRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_u16(self.version_major);
        writer.write_u16(self.version_minor);
        writer.write_u16(self.version_patch);
        Ok(())
    }
}

impl WireDecode for PingRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            version_major: reader.read_u16()?,
            version_minor: reader.read_u16()?,
            version_patch: reader.read_u16()?,
        })
    }
}

impl WireEncode for GetLoggingConfigRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for GetLoggingConfigRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for SetLoggingConfigRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_u64(self.rotation_max_size_mb);
        writer.write_u32(self.rotation_max_files);
        Ok(())
    }
}

impl WireDecode for SetLoggingConfigRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            rotation_max_size_mb: reader.read_u64()?,
            rotation_max_files: reader.read_u32()?,
        })
    }
}

impl WireEncode for ClearLogsRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for ClearLogsRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for LoggingConfigResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.level)?;
        writer.write_u64(self.rotation_max_size_mb);
        writer.write_u32(self.rotation_max_files);
        writer.write_string(&self.run_mode)?;
        writer.write_bool(self.file_logging_active);
        Ok(())
    }
}

impl WireDecode for LoggingConfigResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            level: reader.read_string()?,
            rotation_max_size_mb: reader.read_u64()?,
            rotation_max_files: reader.read_u32()?,
            run_mode: reader.read_string()?,
            file_logging_active: reader.read_bool()?,
        })
    }
}

impl WireEncode for ClearLogsResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.message)?;
        writer.write_u64(self.deleted_files);
        writer.write_u64(self.deleted_bytes);
        Ok(())
    }
}

impl WireDecode for ClearLogsResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            message: reader.read_string()?,
            deleted_files: reader.read_u64()?,
            deleted_bytes: reader.read_u64()?,
        })
    }
}

impl WireEncode for PongResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.message)
    }
}

impl WireDecode for PongResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            message: reader.read_string()?,
        })
    }
}

impl WireEncode for PongErrorResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.message)
    }
}

impl WireDecode for PongErrorResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            message: reader.read_string()?,
        })
    }
}

#[derive(Debug)]
pub enum SystemError {
    InvalidCommand,
    InvalidMessage(String),
    Io(String),
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemError::InvalidCommand => write!(f, "Invalid system command"),
            SystemError::InvalidMessage(message) => write!(f, "{}", message),
            SystemError::Io(message) => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for SystemError {}

impl DomainError for SystemError {
    fn kind(&self) -> ManagementErrorKind {
        match self {
            SystemError::InvalidCommand => ManagementErrorKind::Validation,
            SystemError::InvalidMessage(_) => ManagementErrorKind::Validation,
            SystemError::Io(_) => ManagementErrorKind::Internal,
        }
    }
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), RegistryError> {
    registry.register_domain(crate::management::registry::DomainDescriptor {
        name: "system",
        id: SYSTEM_DOMAIN_ID,
        actions: vec![
            crate::management::registry::ActionDescriptor {
                name: "ping",
                id: SYSTEM_ACTION_PING,
            },
            crate::management::registry::ActionDescriptor {
                name: "pong",
                id: SYSTEM_ACTION_PONG,
            },
            crate::management::registry::ActionDescriptor {
                name: "pong_error",
                id: SYSTEM_ACTION_PONG_ERROR,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_get",
                id: SYSTEM_ACTION_LOGGING_GET,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_get_ok",
                id: SYSTEM_ACTION_LOGGING_GET_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_get_err",
                id: SYSTEM_ACTION_LOGGING_GET_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_set",
                id: SYSTEM_ACTION_LOGGING_SET,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_set_ok",
                id: SYSTEM_ACTION_LOGGING_SET_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_set_err",
                id: SYSTEM_ACTION_LOGGING_SET_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_clear",
                id: SYSTEM_ACTION_LOGGING_CLEAR,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_clear_ok",
                id: SYSTEM_ACTION_LOGGING_CLEAR_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "logging_clear_err",
                id: SYSTEM_ACTION_LOGGING_CLEAR_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_system_request(request, context).await })
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

async fn handle_system_request(
    request: ManagementRequest,
    context: Arc<ManagementContext>,
) -> DomainResult<ManagementResponse> {
    match request.command {
        ManagementCommand::System(SystemCommand::Ping(payload)) => {
            handle_ping(payload, request.workflow_id, context.as_ref()).await
        }
        ManagementCommand::System(SystemCommand::GetLoggingConfig(_)) => {
            handle_get_logging_config(request.workflow_id, context.as_ref()).await
        }
        ManagementCommand::System(SystemCommand::SetLoggingConfig(payload)) => {
            handle_set_logging_config(payload, request.workflow_id, context.as_ref()).await
        }
        ManagementCommand::System(SystemCommand::ClearLogs(_)) => {
            handle_clear_logs(request.workflow_id, context.as_ref()).await
        }
        ManagementCommand::Users(_)
        | ManagementCommand::Tags(_)
        | ManagementCommand::Content(_)
        | ManagementCommand::Roles(_) => Err(Box::new(SystemError::InvalidCommand)),
    }
}

async fn handle_ping(
    payload: PingRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> DomainResult<ManagementResponse> {
    let expected = context.version;
    let message = if payload.version_major == expected.major
        && payload.version_minor == expected.minor
        && payload.version_patch == expected.patch
    {
        format!(
            "Version match {}.{}.{}",
            expected.major, expected.minor, expected.patch
        )
    } else {
        format!(
            "Version mismatch: expected {}.{}.{} but got {}.{}.{}",
            expected.major,
            expected.minor,
            expected.patch,
            payload.version_major,
            payload.version_minor,
            payload.version_patch
        )
    };

    let response = if payload.version_major == expected.major
        && payload.version_minor == expected.minor
        && payload.version_patch == expected.patch
    {
        ManagementResponse::message(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG, workflow_id, message)
    } else {
        ManagementResponse::message(
            SYSTEM_DOMAIN_ID,
            SYSTEM_ACTION_PONG_ERROR,
            workflow_id,
            message,
        )
    };

    response.map_err(|err| Box::new(SystemError::InvalidMessage(err.to_string())) as _)
}

async fn handle_get_logging_config(
    workflow_id: u32,
    context: &ManagementContext,
) -> DomainResult<ManagementResponse> {
    let response = match build_logging_config_response(context) {
        Ok(response) => response,
        Err(err) => {
            return message_response(SYSTEM_ACTION_LOGGING_GET_ERR, workflow_id, &err.to_string());
        }
    };

    Ok(ManagementResponse {
        domain_id: SYSTEM_DOMAIN_ID,
        action_id: SYSTEM_ACTION_LOGGING_GET_OK,
        workflow_id,
        payload: ResponsePayload::SystemLoggingConfig(response),
    })
}

async fn handle_set_logging_config(
    payload: SetLoggingConfigRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> DomainResult<ManagementResponse> {
    let rotation = LogRotationSettings {
        max_size_mb: payload.rotation_max_size_mb,
        max_files: payload.rotation_max_files,
    };

    if let Err(message) = validate_rotation_settings(rotation) {
        return message_response(SYSTEM_ACTION_LOGGING_SET_ERR, workflow_id, &message);
    }

    if let Err(err) = persist_logging_rotation(context.runtime_root.as_path(), rotation) {
        return message_response(SYSTEM_ACTION_LOGGING_SET_ERR, workflow_id, &err.to_string());
    }

    if let Err(err) = context.log_controller.update_rotation(rotation) {
        return message_response(
            SYSTEM_ACTION_LOGGING_SET_ERR,
            workflow_id,
            &format!("Failed to apply logging rotation: {}", err),
        );
    }

    let response = match build_logging_config_response(context) {
        Ok(response) => response,
        Err(err) => {
            return message_response(SYSTEM_ACTION_LOGGING_SET_ERR, workflow_id, &err.to_string());
        }
    };

    Ok(ManagementResponse {
        domain_id: SYSTEM_DOMAIN_ID,
        action_id: SYSTEM_ACTION_LOGGING_SET_OK,
        workflow_id,
        payload: ResponsePayload::SystemLoggingConfig(response),
    })
}

async fn handle_clear_logs(
    workflow_id: u32,
    context: &ManagementContext,
) -> DomainResult<ManagementResponse> {
    let stats = match context.log_controller.clear_logs() {
        Ok(stats) => stats,
        Err(err) => {
            return message_response(
                SYSTEM_ACTION_LOGGING_CLEAR_ERR,
                workflow_id,
                &format!("Failed to clear logs: {}", err),
            );
        }
    };

    let message = format!(
        "Cleared {} log files ({} bytes).",
        stats.deleted_files, stats.deleted_bytes
    );
    let payload = ClearLogsResponse {
        message,
        deleted_files: stats.deleted_files as u64,
        deleted_bytes: stats.deleted_bytes,
    };
    Ok(ManagementResponse {
        domain_id: SYSTEM_DOMAIN_ID,
        action_id: SYSTEM_ACTION_LOGGING_CLEAR_OK,
        workflow_id,
        payload: ResponsePayload::SystemLogCleanup(payload),
    })
}

fn build_logging_config_response(
    context: &ManagementContext,
) -> Result<LoggingConfigResponse, SystemError> {
    let rotation = context
        .log_controller
        .rotation()
        .map_err(|err| SystemError::Io(format!("Logging state error: {}", err)))?;
    let file_logging_active = context
        .log_controller
        .file_logging_active()
        .map_err(|err| SystemError::Io(format!("Logging state error: {}", err)))?;
    let run_mode = match context.log_controller.run_mode() {
        LogRunMode::Daemon => "daemon",
        LogRunMode::Foreground => "foreground",
    }
    .to_string();

    Ok(LoggingConfigResponse {
        level: context.config.logging.level.clone(),
        rotation_max_size_mb: rotation.max_size_mb,
        rotation_max_files: rotation.max_files,
        run_mode,
        file_logging_active,
    })
}

fn message_response(
    action_id: u32,
    workflow_id: u32,
    message: &str,
) -> DomainResult<ManagementResponse> {
    ManagementResponse::message(SYSTEM_DOMAIN_ID, action_id, workflow_id, message)
        .map_err(|err| Box::new(SystemError::InvalidMessage(err.to_string())) as _)
}

fn validate_rotation_settings(settings: LogRotationSettings) -> Result<(), String> {
    if !(1..=1024).contains(&settings.max_size_mb) {
        return Err(format!(
            "Rotation max_size_mb must be between 1 and 1024, got {}",
            settings.max_size_mb
        ));
    }
    if !(1..=100).contains(&settings.max_files) {
        return Err(format!(
            "Rotation max_files must be between 1 and 100, got {}",
            settings.max_files
        ));
    }
    Ok(())
}

fn persist_logging_rotation(root: &Path, rotation: LogRotationSettings) -> Result<(), SystemError> {
    let mut config = Config::load(root).map_err(|err| SystemError::Io(err.to_string()))?;
    config.logging.rotation.max_size_mb = rotation.max_size_mb;
    config.logging.rotation.max_files = rotation.max_files;

    let yaml = serde_yaml::to_string(&config)
        .map_err(|err| SystemError::Io(format!("Failed to serialize config: {}", err)))?;
    let config_path = root.join("config.yaml");
    fs::write(&config_path, yaml).map_err(|err| {
        SystemError::Io(format!(
            "Failed to write config file '{}': {}",
            config_path.display(),
            err
        ))
    })?;
    Ok(())
}

struct PingRequestCodec;

impl RequestCodec for PingRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PING)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: PingRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::Ping(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::Ping(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for ping codec",
            )),
        }
    }
}

struct LoggingGetRequestCodec;

impl RequestCodec for LoggingGetRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let _request: GetLoggingConfigRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::GetLoggingConfig(
            GetLoggingConfigRequest {},
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::GetLoggingConfig(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for logging get codec",
            )),
        }
    }
}

struct LoggingSetRequestCodec;

impl RequestCodec for LoggingSetRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: SetLoggingConfigRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::SetLoggingConfig(
            request,
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::SetLoggingConfig(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for logging set codec",
            )),
        }
    }
}

struct LoggingClearRequestCodec;

impl RequestCodec for LoggingClearRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let _request: ClearLogsRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::ClearLogs(
            ClearLogsRequest {},
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::ClearLogs(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for logging clear codec",
            )),
        }
    }
}

struct PongResponseCodec;

impl ResponseCodec for PongResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let message = match &response.payload {
            crate::management::core::ResponsePayload::Message(payload) => payload.message.clone(),
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for pong codec",
                ));
            }
        };
        crate::management::codec::encode_payload(&PongResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: PongResponse = crate::management::codec::decode_payload(payload)?;
        let message = MessageResponse::new(response.message)
            .map_err(|err| CodecError::new(ManagementErrorKind::Codec, err.to_string()))?;
        Ok(ResponsePayload::Message(message))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for pong codec",
            )),
        }
    }
}

struct PongErrorResponseCodec;

impl ResponseCodec for PongErrorResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG_ERROR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let message = match &response.payload {
            crate::management::core::ResponsePayload::Message(payload) => payload.message.clone(),
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for pong error codec",
                ));
            }
        };
        crate::management::codec::encode_payload(&PongErrorResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: PongErrorResponse = crate::management::codec::decode_payload(payload)?;
        let message = MessageResponse::new(response.message)
            .map_err(|err| CodecError::new(ManagementErrorKind::Codec, err.to_string()))?;
        Ok(ResponsePayload::Message(message))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for pong error codec",
            )),
        }
    }
}

struct LoggingGetOkResponseCodec;

impl ResponseCodec for LoggingGetOkResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("level", FieldLimit::MaxChars(16)),
            ("run_mode", FieldLimit::MaxChars(16)),
            (
                "rotation_max_size_mb",
                FieldLimit::Range { min: 1, max: 1024 },
            ),
            ("rotation_max_files", FieldLimit::Range { min: 1, max: 100 }),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let payload = match &response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => payload,
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for logging get ok codec",
                ));
            }
        };
        crate::management::codec::encode_payload(payload)
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: LoggingConfigResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::SystemLoggingConfig(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("level", payload.level.chars().count());
                values.insert_len("run_mode", payload.run_mode.chars().count());
                values.insert_len(
                    "rotation_max_size_mb",
                    payload.rotation_max_size_mb as usize,
                );
                values.insert_len("rotation_max_files", payload.rotation_max_files as usize);
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging get ok codec",
            )),
        }
    }
}

struct LoggingGetErrResponseCodec;

impl ResponseCodec for LoggingGetErrResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET_ERR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let message = match &response.payload {
            ResponsePayload::Message(payload) => payload.message.clone(),
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for logging get error codec",
                ));
            }
        };
        crate::management::codec::encode_payload(&MessageResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::Message(message))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging get error codec",
            )),
        }
    }
}

struct LoggingSetOkResponseCodec;

impl ResponseCodec for LoggingSetOkResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("level", FieldLimit::MaxChars(16)),
            ("run_mode", FieldLimit::MaxChars(16)),
            (
                "rotation_max_size_mb",
                FieldLimit::Range { min: 1, max: 1024 },
            ),
            ("rotation_max_files", FieldLimit::Range { min: 1, max: 100 }),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let payload = match &response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => payload,
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for logging set ok codec",
                ));
            }
        };
        crate::management::codec::encode_payload(payload)
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: LoggingConfigResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::SystemLoggingConfig(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("level", payload.level.chars().count());
                values.insert_len("run_mode", payload.run_mode.chars().count());
                values.insert_len(
                    "rotation_max_size_mb",
                    payload.rotation_max_size_mb as usize,
                );
                values.insert_len("rotation_max_files", payload.rotation_max_files as usize);
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging set ok codec",
            )),
        }
    }
}

struct LoggingSetErrResponseCodec;

impl ResponseCodec for LoggingSetErrResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET_ERR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let message = match &response.payload {
            ResponsePayload::Message(payload) => payload.message.clone(),
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for logging set error codec",
                ));
            }
        };
        crate::management::codec::encode_payload(&MessageResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::Message(message))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging set error codec",
            )),
        }
    }
}

struct LoggingClearOkResponseCodec;

impl ResponseCodec for LoggingClearOkResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let payload = match &response.payload {
            ResponsePayload::SystemLogCleanup(payload) => payload,
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for logging clear ok codec",
                ));
            }
        };
        crate::management::codec::encode_payload(payload)
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ClearLogsResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::SystemLogCleanup(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::SystemLogCleanup(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging clear ok codec",
            )),
        }
    }
}

struct LoggingClearErrResponseCodec;

impl ResponseCodec for LoggingClearErrResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR_ERR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        let message = match &response.payload {
            ResponsePayload::Message(payload) => payload.message.clone(),
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Codec,
                    "Unsupported response payload for logging clear error codec",
                ));
            }
        };
        crate::management::codec::encode_payload(&MessageResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::Message(message))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging clear error codec",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, AuthMethod, Config, JwtConfig, LocalAuthConfig, LoggingConfig,
        LoggingRotationConfig, NavigationConfig, PasswordHashingConfig, RenderingConfig,
        SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig, UploadConfig, UsersConfig,
        ValidatedConfig, test_local_users_config, test_server_list,
    };
    use crate::management::{
        ManagementBus, ManagementCommand, ManagementContext, build_default_registry,
    };
    use crate::util::log_rotation::DEFAULT_LOG_FILE_NAME;
    use crate::util::test_fixtures::TestFixtureRoot;
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
                        disable_refresh: false,
                        refresh_threshold_percentage: 10,
                        refresh_threshold_hours: 24,
                    },
                    password: PasswordHashingConfig::default(),
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
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            Arc::new(build_validated_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);

        let response = bus
            .send(
                crate::management::next_connection_id(),
                1,
                ManagementCommand::System(SystemCommand::GetLoggingConfig(
                    GetLoggingConfigRequest {},
                )),
            )
            .await
            .expect("get logging");
        match response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => {
                assert_eq!(payload.rotation_max_size_mb, 16);
                assert_eq!(payload.rotation_max_files, 10);
                assert_eq!(payload.run_mode, "foreground");
                assert!(!payload.file_logging_active);
            }
            _ => panic!("expected logging config payload"),
        }

        let response = bus
            .send(
                crate::management::next_connection_id(),
                2,
                ManagementCommand::System(SystemCommand::SetLoggingConfig(
                    SetLoggingConfigRequest {
                        rotation_max_size_mb: 20,
                        rotation_max_files: 5,
                    },
                )),
            )
            .await
            .expect("set logging");
        match response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => {
                assert_eq!(payload.rotation_max_size_mb, 20);
                assert_eq!(payload.rotation_max_files, 5);
            }
            _ => panic!("expected logging config payload"),
        }

        let updated = Config::load(fixture.path()).expect("load config");
        assert_eq!(updated.logging.rotation.max_size_mb, 20);
        assert_eq!(updated.logging.rotation.max_files, 5);

        let response = bus
            .send(
                crate::management::next_connection_id(),
                3,
                ManagementCommand::System(SystemCommand::ClearLogs(ClearLogsRequest {})),
            )
            .await
            .expect("clear logs");
        match response.payload {
            ResponsePayload::SystemLogCleanup(payload) => {
                assert_eq!(payload.deleted_files, 2);
                assert!(payload.deleted_bytes > 0);
            }
            _ => panic!("expected log cleanup payload"),
        }

        assert!(runtime_paths.logs_dir.exists());
        assert!(!runtime_paths.logs_dir.join(DEFAULT_LOG_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn system_logging_set_rejects_invalid_values() {
        let fixture = TestFixtureRoot::new_unique("system-logging-invalid").unwrap();
        fixture.init_runtime_layout().unwrap();
        write_config(fixture.path());
        let runtime_paths = fixture.runtime_paths().unwrap();

        let registry = build_default_registry().expect("registry");
        let context = ManagementContext::from_components(
            runtime_paths.root.clone(),
            Arc::new(build_validated_config()),
            runtime_paths.clone(),
        )
        .expect("context");
        let bus = ManagementBus::start(registry, context);

        let response = bus
            .send(
                crate::management::next_connection_id(),
                1,
                ManagementCommand::System(SystemCommand::SetLoggingConfig(
                    SetLoggingConfigRequest {
                        rotation_max_size_mb: 0,
                        rotation_max_files: 10,
                    },
                )),
            )
            .await
            .expect("set logging");

        assert_eq!(response.action_id, SYSTEM_ACTION_LOGGING_SET_ERR);
        match response.payload {
            ResponsePayload::Message(payload) => {
                assert!(payload.message.contains("max_size_mb"));
            }
            _ => panic!("expected message payload"),
        }
    }
}
