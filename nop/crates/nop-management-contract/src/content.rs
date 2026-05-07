// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::wire::{OptionMap, WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use serde::{Deserialize, Serialize};

pub const CONTENT_DOMAIN_ID: u32 = 12;

pub const CONTENT_ACTION_LIST: u32 = 1;
pub const CONTENT_ACTION_READ: u32 = 2;
pub const CONTENT_ACTION_UPDATE: u32 = 3;
pub const CONTENT_ACTION_DELETE: u32 = 4;
pub const CONTENT_ACTION_UPLOAD: u32 = 5;
pub const CONTENT_ACTION_NAV_INDEX: u32 = 6;
pub const CONTENT_ACTION_BINARY_PREVALIDATE: u32 = 7;
pub const CONTENT_ACTION_BINARY_UPLOAD_INIT: u32 = 8;
pub const CONTENT_ACTION_BINARY_UPLOAD_COMMIT: u32 = 9;
pub const CONTENT_ACTION_UPLOAD_STREAM_INIT: u32 = 10;
pub const CONTENT_ACTION_UPLOAD_STREAM_COMMIT: u32 = 11;
pub const CONTENT_ACTION_UPDATE_STREAM_INIT: u32 = 12;
pub const CONTENT_ACTION_UPDATE_STREAM_COMMIT: u32 = 13;

pub const CONTENT_ACTION_LIST_OK: u32 = 101;
pub const CONTENT_ACTION_LIST_ERR: u32 = 102;
pub const CONTENT_ACTION_READ_OK: u32 = 201;
pub const CONTENT_ACTION_READ_ERR: u32 = 202;
pub const CONTENT_ACTION_UPDATE_OK: u32 = 301;
pub const CONTENT_ACTION_UPDATE_ERR: u32 = 302;
pub const CONTENT_ACTION_DELETE_OK: u32 = 401;
pub const CONTENT_ACTION_DELETE_ERR: u32 = 402;
pub const CONTENT_ACTION_UPLOAD_OK: u32 = 501;
pub const CONTENT_ACTION_UPLOAD_ERR: u32 = 502;
pub const CONTENT_ACTION_NAV_INDEX_OK: u32 = 601;
pub const CONTENT_ACTION_NAV_INDEX_ERR: u32 = 602;
pub const CONTENT_ACTION_BINARY_PREVALIDATE_OK: u32 = 701;
pub const CONTENT_ACTION_BINARY_PREVALIDATE_ERR: u32 = 702;
pub const CONTENT_ACTION_BINARY_UPLOAD_INIT_OK: u32 = 801;
pub const CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR: u32 = 802;
pub const CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK: u32 = 901;
pub const CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR: u32 = 902;
pub const CONTENT_ACTION_UPLOAD_STREAM_INIT_OK: u32 = 1001;
pub const CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR: u32 = 1002;
pub const CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK: u32 = 1101;
pub const CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR: u32 = 1102;
pub const CONTENT_ACTION_UPDATE_STREAM_INIT_OK: u32 = 1201;
pub const CONTENT_ACTION_UPDATE_STREAM_INIT_ERR: u32 = 1202;
pub const CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK: u32 = 1301;
pub const CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR: u32 = 1302;

#[derive(Debug, Clone)]
pub enum ContentCommand {
    List(ContentListRequest),
    Read(ContentReadRequest),
    Update(ContentUpdateRequest),
    Delete(ContentDeleteRequest),
    Upload(ContentUploadRequest),
    NavIndex(ContentNavIndexRequest),
    BinaryPrevalidate(BinaryPrevalidateRequest),
    BinaryUploadInit(BinaryUploadInitRequest),
    BinaryUploadCommit(BinaryUploadCommitRequest),
    UploadStreamInit(ContentUploadStreamInitRequest),
    UploadStreamCommit(ContentUploadStreamCommitRequest),
    UpdateStreamInit(ContentUpdateStreamInitRequest),
    UpdateStreamCommit(ContentUpdateStreamCommitRequest),
}

impl ContentCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            ContentCommand::List(_) => CONTENT_ACTION_LIST,
            ContentCommand::Read(_) => CONTENT_ACTION_READ,
            ContentCommand::Update(_) => CONTENT_ACTION_UPDATE,
            ContentCommand::Delete(_) => CONTENT_ACTION_DELETE,
            ContentCommand::Upload(_) => CONTENT_ACTION_UPLOAD,
            ContentCommand::NavIndex(_) => CONTENT_ACTION_NAV_INDEX,
            ContentCommand::BinaryPrevalidate(_) => CONTENT_ACTION_BINARY_PREVALIDATE,
            ContentCommand::BinaryUploadInit(_) => CONTENT_ACTION_BINARY_UPLOAD_INIT,
            ContentCommand::BinaryUploadCommit(_) => CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
            ContentCommand::UploadStreamInit(_) => CONTENT_ACTION_UPLOAD_STREAM_INIT,
            ContentCommand::UploadStreamCommit(_) => CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
            ContentCommand::UpdateStreamInit(_) => CONTENT_ACTION_UPDATE_STREAM_INIT,
            ContentCommand::UpdateStreamCommit(_) => CONTENT_ACTION_UPDATE_STREAM_COMMIT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentSortField {
    Title,
    Alias,
    Tags,
    Mime,
    NavTitle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentSortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentListRequest {
    pub page: u32,
    pub page_size: u32,
    pub sort_field: ContentSortField,
    pub sort_direction: ContentSortDirection,
    pub query: Option<String>,
    pub tags: Option<Vec<String>>,
    pub markdown_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentReadRequest {
    pub id: String,
    pub stream_content: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentUpdateRequest {
    pub id: String,
    pub new_alias: Option<String>,
    pub title: Option<String>,
    pub tags: Option<Vec<String>>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
    pub theme: Option<String>,
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentDeleteRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentUploadRequest {
    pub alias: Option<String>,
    pub title: Option<String>,
    pub mime: String,
    pub tags: Vec<String>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
    pub original_filename: Option<String>,
    pub theme: Option<String>,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPrevalidateRequest {
    pub filename: String,
    pub mime: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryUploadInitRequest {
    pub alias: Option<String>,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub filename: String,
    pub mime: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryUploadCommitRequest {
    pub upload_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentUploadStreamInitRequest {
    pub alias: Option<String>,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
    pub theme: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentUploadStreamCommitRequest {
    pub upload_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentUpdateStreamInitRequest {
    pub id: String,
    pub new_alias: Option<String>,
    pub title: Option<String>,
    pub tags: Option<Vec<String>>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
    pub theme: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentUpdateStreamCommitRequest {
    pub upload_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentNavIndexRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSummary {
    pub id: String,
    pub alias: String,
    pub title: Option<String>,
    pub mime: String,
    pub tags: Vec<String>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
    pub original_filename: Option<String>,
    pub is_markdown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentListResponse {
    pub total: u32,
    pub page: u32,
    pub page_size: u32,
    pub items: Vec<ContentSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentNavIndexEntry {
    pub id: String,
    pub alias: String,
    pub title: Option<String>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentNavIndexResponse {
    pub items: Vec<ContentNavIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentReadResponse {
    pub id: String,
    pub alias: String,
    pub title: Option<String>,
    pub mime: String,
    pub tags: Vec<String>,
    pub nav_title: Option<String>,
    pub nav_parent_id: Option<String>,
    pub nav_order: Option<i32>,
    pub original_filename: Option<String>,
    pub theme: Option<String>,
    pub content: Option<String>,
    pub stream_id: Option<u32>,
    pub chunk_bytes: Option<u32>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentUploadResponse {
    pub id: String,
    pub alias: String,
    pub mime: String,
    pub is_markdown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPrevalidateResponse {
    pub accepted: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStreamInitResponse {
    pub upload_id: u32,
    pub stream_id: u32,
    pub max_bytes: u64,
    pub chunk_bytes: u32,
}

impl WireEncode for ContentSortField {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let value = match self {
            ContentSortField::Title => 0,
            ContentSortField::Alias => 1,
            ContentSortField::Tags => 2,
            ContentSortField::Mime => 3,
            ContentSortField::NavTitle => 4,
        };
        writer.write_u32(value);
        Ok(())
    }
}

impl WireDecode for ContentSortField {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        match reader.read_u32()? {
            0 => Ok(ContentSortField::Title),
            1 => Ok(ContentSortField::Alias),
            2 => Ok(ContentSortField::Tags),
            3 => Ok(ContentSortField::Mime),
            4 => Ok(ContentSortField::NavTitle),
            value => Err(crate::wire::WireError::new(format!(
                "Unknown sort field {}",
                value
            ))),
        }
    }
}

impl WireEncode for ContentSortDirection {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let value = match self {
            ContentSortDirection::Asc => 0,
            ContentSortDirection::Desc => 1,
        };
        writer.write_u32(value);
        Ok(())
    }
}

impl WireDecode for ContentSortDirection {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        match reader.read_u32()? {
            0 => Ok(ContentSortDirection::Asc),
            1 => Ok(ContentSortDirection::Desc),
            value => Err(crate::wire::WireError::new(format!(
                "Unknown sort direction {}",
                value
            ))),
        }
    }
}

impl WireEncode for ContentListRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.query.is_some(), self.tags.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_u32(self.page);
        writer.write_u32(self.page_size);
        self.sort_field.encode(writer)?;
        self.sort_direction.encode(writer)?;
        if let Some(value) = &self.query {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.tags {
            writer.write_vec(value, |writer, tag| writer.write_string(tag))?;
        }
        writer.write_bool(self.markdown_only);
        Ok(())
    }
}

impl WireDecode for ContentListRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 2)?;
        let page = reader.read_u32()?;
        let page_size = reader.read_u32()?;
        let sort_field = ContentSortField::decode(reader)?;
        let sort_direction = ContentSortDirection::decode(reader)?;
        let query = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let tags = if flags[1] {
            Some(reader.read_vec(|reader| reader.read_string())?)
        } else {
            None
        };
        let markdown_only = reader.read_bool()?;
        Ok(Self {
            page,
            page_size,
            sort_field,
            sort_direction,
            query,
            tags,
            markdown_only,
        })
    }
}

impl WireEncode for ContentReadRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.stream_content.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        if let Some(value) = self.stream_content {
            writer.write_bool(value);
        }
        Ok(())
    }
}

impl WireDecode for ContentReadRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        let id = reader.read_string()?;
        let stream_content = if flags[0] {
            Some(reader.read_bool()?)
        } else {
            None
        };
        Ok(Self { id, stream_content })
    }
}

impl WireEncode for ContentUpdateRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.new_alias.is_some(),
            self.title.is_some(),
            self.tags.is_some(),
            self.nav_title.is_some(),
            self.nav_parent_id.is_some(),
            self.nav_order.is_some(),
            self.theme.is_some(),
            self.content.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        if let Some(value) = &self.new_alias {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.tags {
            writer.write_vec(value, |writer, tag| writer.write_string(tag))?;
        }
        if let Some(value) = &self.nav_title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_parent_id {
            writer.write_string(value)?;
        }
        if let Some(value) = self.nav_order {
            writer.write_i32(value);
        }
        if let Some(value) = &self.theme {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.content {
            writer.write_string(value)?;
        }
        Ok(())
    }
}

impl WireDecode for ContentUpdateRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 8)?;
        let id = reader.read_string()?;
        let new_alias = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let tags = if flags[2] {
            Some(reader.read_vec(|reader| reader.read_string())?)
        } else {
            None
        };
        let nav_title = if flags[3] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_parent_id = if flags[4] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_order = if flags[5] {
            Some(reader.read_i32()?)
        } else {
            None
        };
        let theme = if flags[6] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let content = if flags[7] {
            Some(reader.read_string()?)
        } else {
            None
        };
        Ok(Self {
            id,
            new_alias,
            title,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            theme,
            content,
        })
    }
}

impl WireEncode for ContentDeleteRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.id)
    }
}

impl WireDecode for ContentDeleteRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            id: reader.read_string()?,
        })
    }
}

impl WireEncode for ContentUploadRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.alias.is_some(),
            self.title.is_some(),
            self.nav_title.is_some(),
            self.nav_parent_id.is_some(),
            self.nav_order.is_some(),
            self.original_filename.is_some(),
            self.theme.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        if let Some(value) = &self.alias {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        writer.write_string(&self.mime)?;
        writer.write_vec(&self.tags, |writer, tag| writer.write_string(tag))?;
        if let Some(value) = &self.nav_title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_parent_id {
            writer.write_string(value)?;
        }
        if let Some(value) = self.nav_order {
            writer.write_i32(value);
        }
        if let Some(value) = &self.original_filename {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.theme {
            writer.write_string(value)?;
        }
        writer.write_bytes(&self.content)?;
        Ok(())
    }
}

impl WireDecode for ContentUploadRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 7)?;
        let alias = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let mime = reader.read_string()?;
        let tags = reader.read_vec(|reader| reader.read_string())?;
        let nav_title = if flags[2] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_parent_id = if flags[3] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_order = if flags[4] {
            Some(reader.read_i32()?)
        } else {
            None
        };
        let original_filename = if flags[5] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let theme = if flags[6] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let content = reader.read_bytes()?;
        Ok(Self {
            alias,
            title,
            mime,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            original_filename,
            theme,
            content,
        })
    }
}

impl WireEncode for BinaryPrevalidateRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.filename)?;
        writer.write_string(&self.mime)?;
        writer.write_u64(self.size_bytes);
        Ok(())
    }
}

impl WireDecode for BinaryPrevalidateRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            filename: reader.read_string()?,
            mime: reader.read_string()?,
            size_bytes: reader.read_u64()?,
        })
    }
}

impl WireEncode for BinaryUploadInitRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.alias.is_some(), self.title.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        if let Some(value) = &self.alias {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        writer.write_vec(&self.tags, |writer, tag| writer.write_string(tag))?;
        writer.write_string(&self.filename)?;
        writer.write_string(&self.mime)?;
        writer.write_u64(self.size_bytes);
        Ok(())
    }
}

impl WireDecode for BinaryUploadInitRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 2)?;
        let alias = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let tags = reader.read_vec(|reader| reader.read_string())?;
        let filename = reader.read_string()?;
        let mime = reader.read_string()?;
        let size_bytes = reader.read_u64()?;
        Ok(Self {
            alias,
            title,
            tags,
            filename,
            mime,
            size_bytes,
        })
    }
}

impl WireEncode for BinaryUploadCommitRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_u32(self.upload_id);
        Ok(())
    }
}

impl WireDecode for BinaryUploadCommitRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            upload_id: reader.read_u32()?,
        })
    }
}

impl WireEncode for ContentUploadStreamInitRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.alias.is_some(),
            self.title.is_some(),
            self.nav_title.is_some(),
            self.nav_parent_id.is_some(),
            self.nav_order.is_some(),
            self.theme.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        if let Some(value) = &self.alias {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        writer.write_vec(&self.tags, |writer, tag| writer.write_string(tag))?;
        if let Some(value) = &self.nav_title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_parent_id {
            writer.write_string(value)?;
        }
        if let Some(value) = self.nav_order {
            writer.write_i32(value);
        }
        if let Some(value) = &self.theme {
            writer.write_string(value)?;
        }
        writer.write_u64(self.size_bytes);
        Ok(())
    }
}

impl WireDecode for ContentUploadStreamInitRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 6)?;
        let alias = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let tags = reader.read_vec(|reader| reader.read_string())?;
        let nav_title = if flags[2] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_parent_id = if flags[3] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_order = if flags[4] {
            Some(reader.read_i32()?)
        } else {
            None
        };
        let theme = if flags[5] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let size_bytes = reader.read_u64()?;
        Ok(Self {
            alias,
            title,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            theme,
            size_bytes,
        })
    }
}

impl WireEncode for ContentUploadStreamCommitRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_u32(self.upload_id);
        Ok(())
    }
}

impl WireDecode for ContentUploadStreamCommitRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            upload_id: reader.read_u32()?,
        })
    }
}

impl WireEncode for ContentUpdateStreamInitRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.new_alias.is_some(),
            self.title.is_some(),
            self.tags.is_some(),
            self.nav_title.is_some(),
            self.nav_parent_id.is_some(),
            self.nav_order.is_some(),
            self.theme.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        if let Some(value) = &self.new_alias {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.tags {
            writer.write_vec(value, |writer, tag| writer.write_string(tag))?;
        }
        if let Some(value) = &self.nav_title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_parent_id {
            writer.write_string(value)?;
        }
        if let Some(value) = self.nav_order {
            writer.write_i32(value);
        }
        if let Some(value) = &self.theme {
            writer.write_string(value)?;
        }
        writer.write_u64(self.size_bytes);
        Ok(())
    }
}

impl WireDecode for ContentUpdateStreamInitRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 7)?;
        let id = reader.read_string()?;
        let new_alias = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let tags = if flags[2] {
            Some(reader.read_vec(|reader| reader.read_string())?)
        } else {
            None
        };
        let nav_title = if flags[3] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_parent_id = if flags[4] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_order = if flags[5] {
            Some(reader.read_i32()?)
        } else {
            None
        };
        let theme = if flags[6] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let size_bytes = reader.read_u64()?;
        Ok(Self {
            id,
            new_alias,
            title,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            theme,
            size_bytes,
        })
    }
}

impl WireEncode for ContentUpdateStreamCommitRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_u32(self.upload_id);
        Ok(())
    }
}

impl WireDecode for ContentUpdateStreamCommitRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            upload_id: reader.read_u32()?,
        })
    }
}

impl WireEncode for ContentNavIndexRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for ContentNavIndexRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for ContentSummary {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.title.is_some(),
            self.nav_title.is_some(),
            self.nav_parent_id.is_some(),
            self.nav_order.is_some(),
            self.original_filename.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        writer.write_string(&self.alias)?;
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        writer.write_string(&self.mime)?;
        writer.write_vec(&self.tags, |writer, tag| writer.write_string(tag))?;
        if let Some(value) = &self.nav_title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_parent_id {
            writer.write_string(value)?;
        }
        if let Some(value) = self.nav_order {
            writer.write_i32(value);
        }
        if let Some(value) = &self.original_filename {
            writer.write_string(value)?;
        }
        writer.write_bool(self.is_markdown);
        Ok(())
    }
}

impl WireDecode for ContentSummary {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 5)?;
        let id = reader.read_string()?;
        let alias = reader.read_string()?;
        let title = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let mime = reader.read_string()?;
        let tags = reader.read_vec(|reader| reader.read_string())?;
        let nav_title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_parent_id = if flags[2] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_order = if flags[3] {
            Some(reader.read_i32()?)
        } else {
            None
        };
        let original_filename = if flags[4] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let is_markdown = reader.read_bool()?;
        Ok(Self {
            id,
            alias,
            title,
            mime,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            original_filename,
            is_markdown,
        })
    }
}

impl WireEncode for ContentListResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_u32(self.total);
        writer.write_u32(self.page);
        writer.write_u32(self.page_size);
        writer.write_vec(&self.items, |writer, item| item.encode(writer))
    }
}

impl WireDecode for ContentListResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            total: reader.read_u32()?,
            page: reader.read_u32()?,
            page_size: reader.read_u32()?,
            items: reader.read_vec(ContentSummary::decode)?,
        })
    }
}

impl WireEncode for ContentNavIndexEntry {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.title.is_some(),
            self.nav_title.is_some(),
            self.nav_parent_id.is_some(),
            self.nav_order.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        writer.write_string(&self.alias)?;
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_parent_id {
            writer.write_string(value)?;
        }
        if let Some(value) = self.nav_order {
            writer.write_i32(value);
        }
        Ok(())
    }
}

impl WireDecode for ContentNavIndexEntry {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 4)?;
        let id = reader.read_string()?;
        let alias = reader.read_string()?;
        let title = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_parent_id = if flags[2] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_order = if flags[3] {
            Some(reader.read_i32()?)
        } else {
            None
        };
        Ok(Self {
            id,
            alias,
            title,
            nav_title,
            nav_parent_id,
            nav_order,
        })
    }
}

impl WireEncode for ContentNavIndexResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_vec(&self.items, |writer, item| item.encode(writer))
    }
}

impl WireDecode for ContentNavIndexResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            items: reader.read_vec(ContentNavIndexEntry::decode)?,
        })
    }
}

impl WireEncode for ContentReadResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [
            self.title.is_some(),
            self.nav_title.is_some(),
            self.nav_parent_id.is_some(),
            self.nav_order.is_some(),
            self.original_filename.is_some(),
            self.theme.is_some(),
            self.content.is_some(),
            self.stream_id.is_some(),
            self.chunk_bytes.is_some(),
            self.size_bytes.is_some(),
        ];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.id)?;
        writer.write_string(&self.alias)?;
        if let Some(value) = &self.title {
            writer.write_string(value)?;
        }
        writer.write_string(&self.mime)?;
        writer.write_vec(&self.tags, |writer, tag| writer.write_string(tag))?;
        if let Some(value) = &self.nav_title {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.nav_parent_id {
            writer.write_string(value)?;
        }
        if let Some(value) = self.nav_order {
            writer.write_i32(value);
        }
        if let Some(value) = &self.original_filename {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.theme {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.content {
            writer.write_string(value)?;
        }
        if let Some(value) = self.stream_id {
            writer.write_u32(value);
        }
        if let Some(value) = self.chunk_bytes {
            writer.write_u32(value);
        }
        if let Some(value) = self.size_bytes {
            writer.write_u64(value);
        }
        Ok(())
    }
}

impl WireDecode for ContentReadResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 10)?;
        let id = reader.read_string()?;
        let alias = reader.read_string()?;
        let title = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let mime = reader.read_string()?;
        let tags = reader.read_vec(|reader| reader.read_string())?;
        let nav_title = if flags[1] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_parent_id = if flags[2] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let nav_order = if flags[3] {
            Some(reader.read_i32()?)
        } else {
            None
        };
        let original_filename = if flags[4] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let theme = if flags[5] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let content = if flags[6] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let stream_id = if flags[7] {
            Some(reader.read_u32()?)
        } else {
            None
        };
        let chunk_bytes = if flags[8] {
            Some(reader.read_u32()?)
        } else {
            None
        };
        let size_bytes = if flags[9] {
            Some(reader.read_u64()?)
        } else {
            None
        };
        Ok(Self {
            id,
            alias,
            title,
            mime,
            tags,
            nav_title,
            nav_parent_id,
            nav_order,
            original_filename,
            theme,
            content,
            stream_id,
            chunk_bytes,
            size_bytes,
        })
    }
}

impl WireEncode for ContentUploadResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.id)?;
        writer.write_string(&self.alias)?;
        writer.write_string(&self.mime)?;
        writer.write_bool(self.is_markdown);
        Ok(())
    }
}

impl WireDecode for ContentUploadResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            id: reader.read_string()?,
            alias: reader.read_string()?,
            mime: reader.read_string()?,
            is_markdown: reader.read_bool()?,
        })
    }
}

impl WireEncode for BinaryPrevalidateResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_bool(self.accepted);
        writer.write_string(&self.message)?;
        Ok(())
    }
}

impl WireDecode for BinaryPrevalidateResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            accepted: reader.read_bool()?,
            message: reader.read_string()?,
        })
    }
}

impl WireEncode for UploadStreamInitResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_u32(self.upload_id);
        writer.write_u32(self.stream_id);
        writer.write_u64(self.max_bytes);
        writer.write_u32(self.chunk_bytes);
        Ok(())
    }
}

impl WireDecode for UploadStreamInitResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            upload_id: reader.read_u32()?,
            stream_id: reader.read_u32()?,
            max_bytes: reader.read_u64()?,
            chunk_bytes: reader.read_u32()?,
        })
    }
}
