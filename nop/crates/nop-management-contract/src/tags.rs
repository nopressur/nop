// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::roles::AccessRule;
use crate::wire::{
    OptionMap, WireDecode, WireEncode, WireError, WireReader, WireResult, WireWriter,
};
use serde::{Deserialize, Serialize};

pub const TAGS_DOMAIN_ID: u32 = 11;

pub const TAG_ACTION_ADD: u32 = 1;
pub const TAG_ACTION_CHANGE: u32 = 2;
pub const TAG_ACTION_DELETE: u32 = 3;
pub const TAG_ACTION_LIST: u32 = 4;
pub const TAG_ACTION_SHOW: u32 = 5;

pub const TAG_ACTION_ADD_OK: u32 = 101;
pub const TAG_ACTION_ADD_ERR: u32 = 102;
pub const TAG_ACTION_CHANGE_OK: u32 = 201;
pub const TAG_ACTION_CHANGE_ERR: u32 = 202;
pub const TAG_ACTION_DELETE_OK: u32 = 301;
pub const TAG_ACTION_DELETE_ERR: u32 = 302;
pub const TAG_ACTION_LIST_OK: u32 = 401;
pub const TAG_ACTION_LIST_ERR: u32 = 402;
pub const TAG_ACTION_SHOW_OK: u32 = 501;
pub const TAG_ACTION_SHOW_ERR: u32 = 502;

#[derive(Debug, Clone)]
pub enum TagCommand {
    Add(TagAddRequest),
    Change(TagChangeRequest),
    Delete(TagDeleteRequest),
    List(TagListRequest),
    Show(TagShowRequest),
}

impl TagCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            TagCommand::Add(_) => TAG_ACTION_ADD,
            TagCommand::Change(_) => TAG_ACTION_CHANGE,
            TagCommand::Delete(_) => TAG_ACTION_DELETE,
            TagCommand::List(_) => TAG_ACTION_LIST,
            TagCommand::Show(_) => TAG_ACTION_SHOW,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagAddRequest {
    pub id: String,
    pub name: String,
    pub roles: Vec<String>,
    pub access_rule: Option<AccessRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagChangeRequest {
    pub id: String,
    #[serde(default)]
    pub new_id: Option<String>,
    pub name: Option<String>,
    pub roles: Option<Vec<String>>,
    pub access_rule: Option<AccessRule>,
    #[serde(default)]
    pub clear_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagDeleteRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagShowRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagListResponse {
    pub tags: Vec<TagSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagShowResponse {
    pub id: String,
    pub name: String,
    pub roles: Vec<String>,
    pub access_rule: Option<AccessRule>,
}

#[derive(Debug, Clone)]
struct AccessRuleWire(AccessRule);

impl AccessRuleWire {
    fn from_rule(rule: &AccessRule) -> Self {
        Self(rule.clone())
    }
}

impl WireEncode for AccessRuleWire {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let value = match self.0 {
            AccessRule::Union => 0,
            AccessRule::Intersect => 1,
        };
        writer.write_u32(value);
        Ok(())
    }
}

impl WireDecode for AccessRuleWire {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        match reader.read_u32()? {
            0 => Ok(Self(AccessRule::Union)),
            1 => Ok(Self(AccessRule::Intersect)),
            value => Err(WireError::new(format!("Unknown access rule {}", value))),
        }
    }
}

impl WireEncode for TagAddRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.access_rule.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        writer.write_string(&self.name)?;
        writer.write_vec(&self.roles, |writer, role| writer.write_string(role))?;
        if let Some(access_rule) = &self.access_rule {
            AccessRuleWire::from_rule(access_rule).encode(writer)?;
        }
        Ok(())
    }
}

impl WireDecode for TagAddRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        let id = reader.read_string()?;
        let name = reader.read_string()?;
        let roles = reader.read_vec(|reader| reader.read_string())?;
        let access_rule = if flags[0] {
            Some(AccessRuleWire::decode(reader)?.0)
        } else {
            None
        };
        Ok(Self {
            id,
            name,
            roles,
            access_rule,
        })
    }
}

impl WireEncode for TagChangeRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.new_id.is_some(),
            self.name.is_some(),
            self.roles.is_some(),
            self.access_rule.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        if let Some(value) = &self.new_id {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.name {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.roles {
            writer.write_vec(value, |writer, role| writer.write_string(role))?;
        }
        if let Some(value) = &self.access_rule {
            AccessRuleWire::from_rule(value).encode(writer)?;
        }
        writer.write_bool(self.clear_access);
        Ok(())
    }
}

impl WireDecode for TagChangeRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 4)?;
        let id = reader.read_string()?;
        let new_id = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let name = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let roles = if flags[2] {
            Some(reader.read_vec(|reader| reader.read_string())?)
        } else {
            None
        };
        let access_rule = if flags[3] {
            Some(AccessRuleWire::decode(reader)?.0)
        } else {
            None
        };
        let clear_access = reader.read_bool()?;
        Ok(Self {
            id,
            new_id,
            name,
            roles,
            access_rule,
            clear_access,
        })
    }
}

impl WireEncode for TagDeleteRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.id)
    }
}

impl WireDecode for TagDeleteRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            id: reader.read_string()?,
        })
    }
}

impl WireEncode for TagListRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for TagListRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for TagShowRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.id)
    }
}

impl WireDecode for TagShowRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            id: reader.read_string()?,
        })
    }
}

impl WireEncode for TagSummary {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.id)?;
        writer.write_string(&self.name)?;
        Ok(())
    }
}

impl WireDecode for TagSummary {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            id: reader.read_string()?,
            name: reader.read_string()?,
        })
    }
}

impl WireEncode for TagListResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_vec(&self.tags, |writer, item| item.encode(writer))
    }
}

impl WireDecode for TagListResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            tags: reader.read_vec(TagSummary::decode)?,
        })
    }
}

impl WireEncode for TagShowResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.access_rule.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        writer.write_string(&self.name)?;
        writer.write_vec(&self.roles, |writer, role| writer.write_string(role))?;
        if let Some(access_rule) = &self.access_rule {
            AccessRuleWire::from_rule(access_rule).encode(writer)?;
        }
        Ok(())
    }
}

impl WireDecode for TagShowResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        let id = reader.read_string()?;
        let name = reader.read_string()?;
        let roles = reader.read_vec(|reader| reader.read_string())?;
        let access_rule = if flags[0] {
            Some(AccessRuleWire::decode(reader)?.0)
        } else {
            None
        };
        Ok(Self {
            id,
            name,
            roles,
            access_rule,
        })
    }
}
