// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::wire::{WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use serde::{Deserialize, Serialize};

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
