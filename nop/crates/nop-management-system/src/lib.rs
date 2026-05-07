// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop_config::{Config, ValidatedConfig};
use nop_management_contract::codec::{
    CodecError, FieldLimit, FieldLimits, FieldValues, RequestCodec, ResponseCodec, decode_payload,
    encode_payload, validate_field_limits,
};
use nop_management_contract::core::{
    ManagementCommand, ManagementRequest, ManagementResponse, MessageResponse, ResponsePayload,
};
use nop_management_contract::registry::DomainActionKey;
pub use nop_management_contract::system::{
    ClearLogsRequest, ClearLogsResponse, GetLoggingConfigRequest, LoggingConfigResponse,
    PingRequest, PongErrorResponse, PongResponse, SYSTEM_ACTION_LOGGING_CLEAR,
    SYSTEM_ACTION_LOGGING_CLEAR_ERR, SYSTEM_ACTION_LOGGING_CLEAR_OK, SYSTEM_ACTION_LOGGING_GET,
    SYSTEM_ACTION_LOGGING_GET_ERR, SYSTEM_ACTION_LOGGING_GET_OK, SYSTEM_ACTION_LOGGING_SET,
    SYSTEM_ACTION_LOGGING_SET_ERR, SYSTEM_ACTION_LOGGING_SET_OK, SYSTEM_ACTION_PING,
    SYSTEM_ACTION_PONG, SYSTEM_ACTION_PONG_ERROR, SYSTEM_DOMAIN_ID, SetLoggingConfigRequest,
    SystemCommand,
};
use nop_management_errors::{DomainError, DomainResult, ManagementErrorKind};
use nop_rt_logging::{LogController, LogRotationSettings, LogRunMode};
use std::fmt;
use std::fs;
use std::path::Path;

pub trait SystemContext {
    fn version(&self) -> (u16, u16, u16);
    fn runtime_root(&self) -> &Path;
    fn log_controller(&self) -> &LogController;
    fn config(&self) -> &ValidatedConfig;
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

pub async fn handle_system_request<C>(
    request: ManagementRequest,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: SystemContext + ?Sized,
{
    match request.command {
        ManagementCommand::System(SystemCommand::Ping(payload)) => {
            handle_ping(payload, request.workflow_id, context).await
        }
        ManagementCommand::System(SystemCommand::GetLoggingConfig(_)) => {
            handle_get_logging_config(request.workflow_id, context).await
        }
        ManagementCommand::System(SystemCommand::SetLoggingConfig(payload)) => {
            handle_set_logging_config(payload, request.workflow_id, context).await
        }
        ManagementCommand::System(SystemCommand::ClearLogs(_)) => {
            handle_clear_logs(request.workflow_id, context).await
        }
        ManagementCommand::Users(_)
        | ManagementCommand::Tags(_)
        | ManagementCommand::Content(_)
        | ManagementCommand::Roles(_)
        | ManagementCommand::Search(_) => Err(Box::new(SystemError::InvalidCommand)),
    }
}

async fn handle_ping<C>(
    payload: PingRequest,
    workflow_id: u32,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: SystemContext + ?Sized,
{
    let (major, minor, patch) = context.version();
    let message = if payload.version_major == major
        && payload.version_minor == minor
        && payload.version_patch == patch
    {
        format!("Version match {}.{}.{}", major, minor, patch)
    } else {
        format!(
            "Version mismatch: expected {}.{}.{} but got {}.{}.{}",
            major,
            minor,
            patch,
            payload.version_major,
            payload.version_minor,
            payload.version_patch
        )
    };

    let response = if payload.version_major == major
        && payload.version_minor == minor
        && payload.version_patch == patch
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

async fn handle_get_logging_config<C>(
    workflow_id: u32,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: SystemContext + ?Sized,
{
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

async fn handle_set_logging_config<C>(
    payload: SetLoggingConfigRequest,
    workflow_id: u32,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: SystemContext + ?Sized,
{
    let rotation = LogRotationSettings {
        max_size_mb: payload.rotation_max_size_mb,
        max_files: payload.rotation_max_files,
    };

    if let Err(message) = validate_rotation_settings(rotation) {
        return message_response(SYSTEM_ACTION_LOGGING_SET_ERR, workflow_id, &message);
    }

    if let Err(err) = persist_logging_rotation(context.runtime_root(), rotation) {
        return message_response(SYSTEM_ACTION_LOGGING_SET_ERR, workflow_id, &err.to_string());
    }

    if let Err(err) = context.log_controller().update_rotation(rotation) {
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

async fn handle_clear_logs<C>(workflow_id: u32, context: &C) -> DomainResult<ManagementResponse>
where
    C: SystemContext + ?Sized,
{
    let stats = match context.log_controller().clear_logs() {
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

fn build_logging_config_response<C>(context: &C) -> Result<LoggingConfigResponse, SystemError>
where
    C: SystemContext + ?Sized,
{
    let rotation = context
        .log_controller()
        .rotation()
        .map_err(|err| SystemError::Io(format!("Logging state error: {}", err)))?;
    let file_logging_active = context
        .log_controller()
        .file_logging_active()
        .map_err(|err| SystemError::Io(format!("Logging state error: {}", err)))?;
    let run_mode = match context.log_controller().run_mode() {
        LogRunMode::Daemon => "daemon",
        LogRunMode::Foreground => "foreground",
    }
    .to_string();

    Ok(LoggingConfigResponse {
        level: context.config().logging.level.clone(),
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

pub struct PingRequestCodec;

impl RequestCodec for PingRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PING)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: PingRequest = decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::Ping(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::Ping(request)) => encode_payload(request),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for ping codec",
            )),
        }
    }
}

pub struct LoggingGetRequestCodec;

impl RequestCodec for LoggingGetRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let _request: GetLoggingConfigRequest = decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::GetLoggingConfig(
            GetLoggingConfigRequest {},
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::GetLoggingConfig(request)) => {
                encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for logging get codec",
            )),
        }
    }
}

pub struct LoggingSetRequestCodec;

impl RequestCodec for LoggingSetRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: SetLoggingConfigRequest = decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::SetLoggingConfig(
            request,
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::SetLoggingConfig(request)) => {
                encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for logging set codec",
            )),
        }
    }
}

pub struct LoggingClearRequestCodec;

impl RequestCodec for LoggingClearRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let _request: ClearLogsRequest = decode_payload(payload)?;
        Ok(ManagementCommand::System(SystemCommand::ClearLogs(
            ClearLogsRequest {},
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::System(SystemCommand::ClearLogs(request)) => encode_payload(request),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported request type for logging clear codec",
            )),
        }
    }
}

pub struct PongResponseCodec;

impl ResponseCodec for PongResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG)
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
                    "Unsupported response payload for pong codec",
                ));
            }
        };
        encode_payload(&PongResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: PongResponse = decode_payload(payload)?;
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

pub struct PongErrorResponseCodec;

impl ResponseCodec for PongErrorResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PONG_ERROR)
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
                    "Unsupported response payload for pong error codec",
                ));
            }
        };
        encode_payload(&PongErrorResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: PongErrorResponse = decode_payload(payload)?;
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

pub struct LoggingGetOkResponseCodec;

impl ResponseCodec for LoggingGetOkResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("level", FieldLimit::MaxChars(32)),
            ("run_mode", FieldLimit::MaxChars(16)),
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
        encode_payload(payload)
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: LoggingConfigResponse = decode_payload(payload)?;
        Ok(ResponsePayload::SystemLoggingConfig(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("level", payload.level.chars().count());
                values.insert_len("run_mode", payload.run_mode.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging get ok codec",
            )),
        }
    }
}

pub struct LoggingGetErrResponseCodec;

impl ResponseCodec for LoggingGetErrResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_GET_ERR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(512))])
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
        encode_payload(&MessageResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = decode_payload(payload)?;
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

pub struct LoggingSetOkResponseCodec;

impl ResponseCodec for LoggingSetOkResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("level", FieldLimit::MaxChars(32)),
            ("run_mode", FieldLimit::MaxChars(16)),
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
        encode_payload(payload)
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: LoggingConfigResponse = decode_payload(payload)?;
        Ok(ResponsePayload::SystemLoggingConfig(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::SystemLoggingConfig(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("level", payload.level.chars().count());
                values.insert_len("run_mode", payload.run_mode.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for logging set ok codec",
            )),
        }
    }
}

pub struct LoggingSetErrResponseCodec;

impl ResponseCodec for LoggingSetErrResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_SET_ERR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(512))])
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
        encode_payload(&MessageResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = decode_payload(payload)?;
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

pub struct LoggingClearOkResponseCodec;

impl ResponseCodec for LoggingClearOkResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(512))])
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
        encode_payload(payload)
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ClearLogsResponse = decode_payload(payload)?;
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

pub struct LoggingClearErrResponseCodec;

impl ResponseCodec for LoggingClearErrResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_LOGGING_CLEAR_ERR)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(512))])
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
        encode_payload(&MessageResponse { message })
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = decode_payload(payload)?;
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
