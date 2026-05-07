// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::wire::{WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use serde::{Deserialize, Serialize};

pub const ROLES_DOMAIN_ID: u32 = 13;

pub const ROLE_ACTION_ADD: u32 = 1;
pub const ROLE_ACTION_CHANGE: u32 = 2;
pub const ROLE_ACTION_DELETE: u32 = 3;
pub const ROLE_ACTION_LIST: u32 = 4;
pub const ROLE_ACTION_SHOW: u32 = 5;

pub const ROLE_ACTION_ADD_OK: u32 = 101;
pub const ROLE_ACTION_ADD_ERR: u32 = 102;
pub const ROLE_ACTION_CHANGE_OK: u32 = 201;
pub const ROLE_ACTION_CHANGE_ERR: u32 = 202;
pub const ROLE_ACTION_DELETE_OK: u32 = 301;
pub const ROLE_ACTION_DELETE_ERR: u32 = 302;
pub const ROLE_ACTION_LIST_OK: u32 = 401;
pub const ROLE_ACTION_LIST_ERR: u32 = 402;
pub const ROLE_ACTION_SHOW_OK: u32 = 501;
pub const ROLE_ACTION_SHOW_ERR: u32 = 502;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessRule {
    Union,
    Intersect,
}

#[derive(Debug, Clone)]
pub enum RoleCommand {
    Add(RoleAddRequest),
    Change(RoleChangeRequest),
    Delete(RoleDeleteRequest),
    List(RoleListRequest),
    Show(RoleShowRequest),
}

impl RoleCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            RoleCommand::Add(_) => ROLE_ACTION_ADD,
            RoleCommand::Change(_) => ROLE_ACTION_CHANGE,
            RoleCommand::Delete(_) => ROLE_ACTION_DELETE,
            RoleCommand::List(_) => ROLE_ACTION_LIST,
            RoleCommand::Show(_) => ROLE_ACTION_SHOW,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAddRequest {
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleChangeRequest {
    pub role: String,
    pub new_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDeleteRequest {
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleShowRequest {
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleListResponse {
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleShowResponse {
    pub role: String,
}

impl WireEncode for RoleAddRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.role)
    }
}

impl WireDecode for RoleAddRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            role: reader.read_string()?,
        })
    }
}

impl WireEncode for RoleChangeRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.role)?;
        writer.write_string(&self.new_role)?;
        Ok(())
    }
}

impl WireDecode for RoleChangeRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            role: reader.read_string()?,
            new_role: reader.read_string()?,
        })
    }
}

impl WireEncode for RoleDeleteRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.role)
    }
}

impl WireDecode for RoleDeleteRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            role: reader.read_string()?,
        })
    }
}

impl WireEncode for RoleListRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for RoleListRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for RoleShowRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.role)
    }
}

impl WireDecode for RoleShowRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            role: reader.read_string()?,
        })
    }
}

impl WireEncode for RoleListResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_vec(&self.roles, |writer, role| writer.write_string(role))
    }
}

impl WireDecode for RoleListResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            roles: reader.read_vec(|reader| reader.read_string())?,
        })
    }
}

impl WireEncode for RoleShowResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.role)
    }
}

impl WireDecode for RoleShowResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            role: reader.read_string()?,
        })
    }
}
