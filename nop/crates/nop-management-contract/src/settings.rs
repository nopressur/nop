// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::wire::{OptionMap, WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use serde::{Deserialize, Serialize};

pub const SETTINGS_DOMAIN_ID: u32 = 22;

pub const SETTINGS_ACTION_GET: u32 = 1;
pub const SETTINGS_ACTION_SET_NAME: u32 = 2;
pub const SETTINGS_ACTION_SET_TITLE: u32 = 3;
pub const SETTINGS_ACTION_SET_DESCRIPTION: u32 = 4;

pub const SETTINGS_ACTION_GET_OK: u32 = 101;
pub const SETTINGS_ACTION_GET_ERR: u32 = 102;
pub const SETTINGS_ACTION_SET_NAME_OK: u32 = 201;
pub const SETTINGS_ACTION_SET_NAME_ERR: u32 = 202;
pub const SETTINGS_ACTION_SET_TITLE_OK: u32 = 301;
pub const SETTINGS_ACTION_SET_TITLE_ERR: u32 = 302;
pub const SETTINGS_ACTION_SET_DESCRIPTION_OK: u32 = 401;
pub const SETTINGS_ACTION_SET_DESCRIPTION_ERR: u32 = 402;

#[derive(Debug, Clone)]
pub enum SettingsCommand {
    Get(SettingsGetRequest),
    SetName(SettingsSetNameRequest),
    SetTitle(SettingsSetTitleRequest),
    SetDescription(SettingsSetDescriptionRequest),
}

impl SettingsCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            SettingsCommand::Get(_) => SETTINGS_ACTION_GET,
            SettingsCommand::SetName(_) => SETTINGS_ACTION_SET_NAME,
            SettingsCommand::SetTitle(_) => SETTINGS_ACTION_SET_TITLE,
            SettingsCommand::SetDescription(_) => SETTINGS_ACTION_SET_DESCRIPTION,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsGetRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsSetNameRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsSetTitleRequest {
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsSetDescriptionRequest {
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettingsResponse {
    pub name: String,
    pub title: Option<String>,
    pub description: Option<String>,
}

impl WireEncode for SettingsGetRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for SettingsGetRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for SettingsSetNameRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.name)
    }
}

impl WireDecode for SettingsSetNameRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            name: reader.read_string()?,
        })
    }
}

impl WireEncode for SettingsSetTitleRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.title.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        if let Some(title) = &self.title {
            writer.write_string(title)?;
        }
        Ok(())
    }
}

impl WireDecode for SettingsSetTitleRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        let title = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        Ok(Self { title })
    }
}

impl WireEncode for SettingsSetDescriptionRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.description.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        if let Some(description) = &self.description {
            writer.write_string(description)?;
        }
        Ok(())
    }
}

impl WireDecode for SettingsSetDescriptionRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        let description = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        Ok(Self { description })
    }
}

impl WireEncode for SettingsResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.name)?;
        let option_flags = [self.title.is_some(), self.description.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        if let Some(title) = &self.title {
            writer.write_string(title)?;
        }
        if let Some(description) = &self.description {
            writer.write_string(description)?;
        }
        Ok(())
    }
}

impl WireDecode for SettingsResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let name = reader.read_string()?;
        let flags = OptionMap::read(reader, 2)?;
        let title = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let description = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        Ok(Self {
            name,
            title,
            description,
        })
    }
}
