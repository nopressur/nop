// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, content_id_hex, generate_content_id,
    normalize_optional_alias, parse_content_id_hex, read_sidecar, sidecar_path, validate_sidecar,
    write_sidecar_atomic,
};
use crate::content::reserved_paths::ReservedPaths;
use crate::management::codec::{
    CodecError, FieldLimit, FieldLimits, FieldValues, RequestCodec, ResponseCodec,
    validate_field_limits,
};
use crate::management::core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse, MessageResponse,
    ResponsePayload,
};
use crate::management::errors::ManagementErrorKind;
use crate::management::registry::{DomainActionKey, ManagementHandler, ManagementRegistry};
use crate::management::ws::WS_MAX_STREAM_CHUNK_BYTES;
use crate::management::{OptionMap, WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use crate::public::page_meta_cache::{CachedObject, PageMetaCache};
use crate::util::detect_mime_type;
use serde::{Deserialize, Serialize};
use std::cmp::{Ordering, min};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

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

const MAX_ALIAS_CHARS: usize = 512;
const MAX_TITLE_CHARS: usize = 256;
const MAX_TAG_COUNT: usize = 256;
const MAX_TAG_CHARS: usize = 128;
const MAX_THEME_CHARS: usize = 128;
const MAX_MIME_CHARS: usize = 128;
const MAX_ORIGINAL_FILENAME_CHARS: usize = 512;
const MAX_QUERY_CHARS: usize = 256;
const MAX_PAGE_SIZE: u32 = 200;
const MAX_ID_CHARS: usize = 16;
const MAX_NAV_PARENT_CHARS: usize = 16;
const MAX_NAV_INDEX_ITEMS: usize = 2048;
const HOME_ALIAS: &str = "index";
const DEFAULT_STREAM_CHUNK_BYTES: u32 = WS_MAX_STREAM_CHUNK_BYTES as u32;

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
            value => Err(crate::management::WireError::new(format!(
                "Unknown content sort field {}",
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
            value => Err(crate::management::WireError::new(format!(
                "Unknown content sort direction {}",
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
        writer.write_string(&self.id)
    }
}

impl WireDecode for ContentReadRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            id: reader.read_string()?,
        })
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
        writer.write_vec(&self.items, |writer, item| item.encode(writer))?;
        Ok(())
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
        Ok(())
    }
}

impl WireDecode for ContentReadResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 7)?;
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

pub fn register(registry: &mut ManagementRegistry) -> Result<(), crate::management::RegistryError> {
    registry.register_domain(crate::management::registry::DomainDescriptor {
        name: "content",
        id: CONTENT_DOMAIN_ID,
        actions: vec![
            crate::management::registry::ActionDescriptor {
                name: "list",
                id: CONTENT_ACTION_LIST,
            },
            crate::management::registry::ActionDescriptor {
                name: "read",
                id: CONTENT_ACTION_READ,
            },
            crate::management::registry::ActionDescriptor {
                name: "update",
                id: CONTENT_ACTION_UPDATE,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete",
                id: CONTENT_ACTION_DELETE,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload",
                id: CONTENT_ACTION_UPLOAD,
            },
            crate::management::registry::ActionDescriptor {
                name: "nav_index",
                id: CONTENT_ACTION_NAV_INDEX,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_prevalidate",
                id: CONTENT_ACTION_BINARY_PREVALIDATE,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_upload_init",
                id: CONTENT_ACTION_BINARY_UPLOAD_INIT,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_upload_commit",
                id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_stream_init",
                id: CONTENT_ACTION_UPLOAD_STREAM_INIT,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_stream_commit",
                id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_stream_init",
                id: CONTENT_ACTION_UPDATE_STREAM_INIT,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_stream_commit",
                id: CONTENT_ACTION_UPDATE_STREAM_COMMIT,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_ok",
                id: CONTENT_ACTION_LIST_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_err",
                id: CONTENT_ACTION_LIST_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "read_ok",
                id: CONTENT_ACTION_READ_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "read_err",
                id: CONTENT_ACTION_READ_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_ok",
                id: CONTENT_ACTION_UPDATE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_err",
                id: CONTENT_ACTION_UPDATE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_ok",
                id: CONTENT_ACTION_DELETE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_err",
                id: CONTENT_ACTION_DELETE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_ok",
                id: CONTENT_ACTION_UPLOAD_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_err",
                id: CONTENT_ACTION_UPLOAD_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "nav_index_ok",
                id: CONTENT_ACTION_NAV_INDEX_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "nav_index_err",
                id: CONTENT_ACTION_NAV_INDEX_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_prevalidate_ok",
                id: CONTENT_ACTION_BINARY_PREVALIDATE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_prevalidate_err",
                id: CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_upload_init_ok",
                id: CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_upload_init_err",
                id: CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_upload_commit_ok",
                id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "binary_upload_commit_err",
                id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_stream_init_ok",
                id: CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_stream_init_err",
                id: CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_stream_commit_ok",
                id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "upload_stream_commit_err",
                id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_stream_init_ok",
                id: CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_stream_init_err",
                id: CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_stream_commit_ok",
                id: CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "update_stream_commit_err",
                id: CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_content_request(request, context).await })
    });
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_READ),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_INIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_COMMIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_INIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_COMMIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_INIT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_COMMIT),
        handler.clone(),
    )?;

    registry.register_request_codec(Arc::new(ContentListRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentReadRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentUpdateRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentDeleteRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentUploadRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentNavIndexRequestCodec))?;
    registry.register_request_codec(Arc::new(BinaryPrevalidateRequestCodec))?;
    registry.register_request_codec(Arc::new(BinaryUploadInitRequestCodec))?;
    registry.register_request_codec(Arc::new(BinaryUploadCommitRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentUploadStreamInitRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentUploadStreamCommitRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentUpdateStreamInitRequestCodec))?;
    registry.register_request_codec(Arc::new(ContentUpdateStreamCommitRequestCodec))?;

    registry
        .register_response_codec(Arc::new(MessageResponseCodec::new(CONTENT_ACTION_LIST_ERR)))?;
    registry
        .register_response_codec(Arc::new(MessageResponseCodec::new(CONTENT_ACTION_READ_ERR)))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPDATE_OK,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPDATE_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_DELETE_OK,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_DELETE_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPLOAD_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_NAV_INDEX_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
    )))?;
    registry.register_response_codec(Arc::new(MessageResponseCodec::new(
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
    )))?;
    registry.register_response_codec(Arc::new(ContentListResponseCodec))?;
    registry.register_response_codec(Arc::new(ContentNavIndexResponseCodec))?;
    registry.register_response_codec(Arc::new(ContentReadResponseCodec))?;
    registry.register_response_codec(Arc::new(ContentUploadResponseCodec::new(
        CONTENT_ACTION_UPLOAD_OK,
    )))?;
    registry.register_response_codec(Arc::new(ContentUploadResponseCodec::new(
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
    )))?;
    registry.register_response_codec(Arc::new(ContentUploadResponseCodec::new(
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
    )))?;
    registry.register_response_codec(Arc::new(BinaryPrevalidateResponseCodec))?;
    registry.register_response_codec(Arc::new(UploadStreamInitResponseCodec::new(
        CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
    )))?;
    registry.register_response_codec(Arc::new(UploadStreamInitResponseCodec::new(
        CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
    )))?;
    registry.register_response_codec(Arc::new(UploadStreamInitResponseCodec::new(
        CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
    )))?;

    Ok(())
}

async fn handle_content_request(
    request: ManagementRequest,
    context: Arc<ManagementContext>,
) -> crate::management::errors::DomainResult<ManagementResponse> {
    let response = match request.command {
        ManagementCommand::Content(ContentCommand::List(payload)) => {
            handle_list(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Content(ContentCommand::Read(payload)) => {
            handle_read(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Content(ContentCommand::Update(payload)) => {
            handle_update(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Content(ContentCommand::Delete(payload)) => {
            handle_delete(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Content(ContentCommand::Upload(payload)) => {
            handle_upload(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Content(ContentCommand::NavIndex(payload)) => {
            handle_nav_index(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Content(ContentCommand::BinaryPrevalidate(payload)) => {
            handle_binary_prevalidate(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Content(ContentCommand::BinaryUploadInit(payload)) => {
            handle_binary_upload_init(
                payload,
                request.workflow_id,
                request.connection_id,
                &context,
            )
            .await
        }
        ManagementCommand::Content(ContentCommand::BinaryUploadCommit(payload)) => {
            handle_binary_upload_commit(
                payload,
                request.workflow_id,
                request.connection_id,
                &context,
            )
            .await
        }
        ManagementCommand::Content(ContentCommand::UploadStreamInit(payload)) => {
            handle_upload_stream_init(
                payload,
                request.workflow_id,
                request.connection_id,
                &context,
            )
            .await
        }
        ManagementCommand::Content(ContentCommand::UploadStreamCommit(payload)) => {
            handle_upload_stream_commit(
                payload,
                request.workflow_id,
                request.connection_id,
                &context,
            )
            .await
        }
        ManagementCommand::Content(ContentCommand::UpdateStreamInit(payload)) => {
            handle_update_stream_init(
                payload,
                request.workflow_id,
                request.connection_id,
                &context,
            )
            .await
        }
        ManagementCommand::Content(ContentCommand::UpdateStreamCommit(payload)) => {
            handle_update_stream_commit(
                payload,
                request.workflow_id,
                request.connection_id,
                &context,
            )
            .await
        }
        _ => response_err(
            CONTENT_ACTION_LIST_ERR,
            request.workflow_id,
            "Invalid content command",
        ),
    };

    Ok(response)
}

async fn handle_list(
    payload: ContentListRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(CONTENT_ACTION_LIST_ERR, workflow_id, &err);
    }

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_LIST_ERR, workflow_id, &err),
    };

    let mut items: Vec<_> = cache.list_objects();
    if payload.markdown_only {
        items.retain(|object| object.is_markdown);
    }

    if let Some(tags) = payload.tags.as_ref() {
        let tags: Vec<String> = tags.iter().map(|tag| tag.to_ascii_lowercase()).collect();
        items.retain(|object| {
            tags.iter()
                .all(|tag| object.tags.iter().any(|item| item == tag))
        });
    }

    if let Some(query) = payload.query.as_ref() {
        let needle = query.to_ascii_lowercase();
        items.retain(|object| {
            object
                .title
                .as_ref()
                .map(|title| title.to_ascii_lowercase().contains(&needle))
                .unwrap_or(false)
        });
    }

    sort_content_items(&mut items, payload.sort_field, payload.sort_direction);

    let total = items.len() as u32;
    let page_size = payload.page_size;
    let page = payload.page.max(1);
    let start = ((page - 1) * page_size) as usize;
    let end = min(start + page_size as usize, items.len());
    let page_items = if start < items.len() {
        items[start..end].to_vec()
    } else {
        Vec::new()
    };

    let response_items = page_items
        .into_iter()
        .map(|object| ContentSummary {
            id: content_id_hex(object.key.id),
            alias: object.alias,
            title: object.title,
            mime: object.mime,
            tags: object.tags,
            nav_title: object.nav_title,
            nav_parent_id: object.nav_parent_id,
            nav_order: object.nav_order,
            original_filename: object.original_filename,
            is_markdown: object.is_markdown,
        })
        .collect();

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_LIST_OK,
        workflow_id,
        payload: ResponsePayload::ContentList(ContentListResponse {
            total,
            page,
            page_size,
            items: response_items,
        }),
    }
}

fn sort_content_items(
    items: &mut [CachedObject],
    field: ContentSortField,
    direction: ContentSortDirection,
) {
    items.sort_by(|left, right| {
        let ordering = match field {
            ContentSortField::Title => {
                compare_optional_str(left.title.as_deref(), right.title.as_deref(), direction)
            }
            ContentSortField::Alias => compare_optional_str(
                Some(left.alias.as_str()),
                Some(right.alias.as_str()),
                direction,
            ),
            ContentSortField::Tags => {
                let left_tags = tags_sort_value(&left.tags);
                let right_tags = tags_sort_value(&right.tags);
                compare_optional_str(left_tags.as_deref(), right_tags.as_deref(), direction)
            }
            ContentSortField::Mime => compare_optional_str(
                Some(left.mime.as_str()),
                Some(right.mime.as_str()),
                direction,
            ),
            ContentSortField::NavTitle => compare_optional_str(
                left.nav_title.as_deref(),
                right.nav_title.as_deref(),
                direction,
            ),
        };

        ordering.then_with(|| left.key.id.0.cmp(&right.key.id.0))
    });
}

fn tags_sort_value(tags: &[String]) -> Option<String> {
    if tags.is_empty() {
        return None;
    }
    Some(tags.join(", "))
}

fn compare_optional_str(
    left: Option<&str>,
    right: Option<&str>,
    direction: ContentSortDirection,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => match direction {
            ContentSortDirection::Asc => left.cmp(right),
            ContentSortDirection::Desc => right.cmp(left),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::flat_storage::{ContentId, ContentVersion};
    use crate::public::page_meta_cache::ResolvedRoles;
    use crate::public::page_meta_cache::cache::ContentKey;

    fn make_object(
        id: u64,
        title: Option<&str>,
        alias: &str,
        tags: &[&str],
        mime: &str,
        nav_title: Option<&str>,
    ) -> CachedObject {
        CachedObject {
            key: ContentKey {
                id: ContentId(id),
                version: ContentVersion(1),
            },
            alias: alias.to_string(),
            title: title.map(str::to_string),
            theme: None,
            mime: mime.to_string(),
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
            nav_title: nav_title.map(str::to_string),
            nav_parent_id: None,
            nav_order: None,
            original_filename: None,
            last_modified: std::time::SystemTime::UNIX_EPOCH,
            is_markdown: mime == "text/markdown",
            resolved_roles: ResolvedRoles::Public,
        }
    }

    #[test]
    fn sorts_by_title_with_nulls_last_and_id_tiebreaker() {
        let mut items = vec![
            make_object(2, Some("Beta"), "beta", &[], "text/markdown", None),
            make_object(5, Some("Same"), "same-b", &[], "text/markdown", None),
            make_object(4, Some("Same"), "same-a", &[], "text/markdown", None),
            make_object(1, Some("Alpha"), "alpha", &[], "text/markdown", None),
            make_object(3, None, "untitled", &[], "text/markdown", None),
        ];

        sort_content_items(
            &mut items,
            ContentSortField::Title,
            ContentSortDirection::Asc,
        );

        let ids: Vec<u64> = items.iter().map(|item| item.key.id.0).collect();
        assert_eq!(ids, vec![1, 2, 4, 5, 3]);
    }

    #[test]
    fn sorts_by_title_desc_with_nulls_last_and_id_tiebreaker() {
        let mut items = vec![
            make_object(2, Some("Beta"), "beta", &[], "text/markdown", None),
            make_object(5, Some("Same"), "same-b", &[], "text/markdown", None),
            make_object(4, Some("Same"), "same-a", &[], "text/markdown", None),
            make_object(1, Some("Alpha"), "alpha", &[], "text/markdown", None),
            make_object(3, None, "untitled", &[], "text/markdown", None),
        ];

        sort_content_items(
            &mut items,
            ContentSortField::Title,
            ContentSortDirection::Desc,
        );

        let ids: Vec<u64> = items.iter().map(|item| item.key.id.0).collect();
        assert_eq!(ids, vec![4, 5, 2, 1, 3]);
    }

    #[test]
    fn sorts_by_tags_with_empty_last() {
        let mut items = vec![
            make_object(1, Some("Beta"), "beta", &["beta"], "text/markdown", None),
            make_object(2, Some("Alpha"), "alpha", &["alpha"], "text/markdown", None),
            make_object(3, Some("Empty"), "empty", &[], "text/markdown", None),
        ];

        sort_content_items(
            &mut items,
            ContentSortField::Tags,
            ContentSortDirection::Asc,
        );

        let ids: Vec<u64> = items.iter().map(|item| item.key.id.0).collect();
        assert_eq!(ids, vec![2, 1, 3]);
    }

    #[test]
    fn rejects_unknown_sort_field() {
        let mut writer = WireWriter::new();
        writer.write_u32(99);
        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        let err = ContentSortField::decode(&mut reader).unwrap_err();
        assert!(err.to_string().contains("Unknown content sort field"));
    }

    #[test]
    fn rejects_unknown_sort_direction() {
        let mut writer = WireWriter::new();
        writer.write_u32(42);
        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        let err = ContentSortDirection::decode(&mut reader).unwrap_err();
        assert!(err.to_string().contains("Unknown content sort direction"));
    }
}

async fn handle_read(
    payload: ContentReadRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_READ_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_READ_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => return response_err(CONTENT_ACTION_READ_ERR, workflow_id, "Content not found"),
    };

    let sidecar_path = sidecar_path(
        &context.runtime_paths.content_dir,
        object.key.id,
        object.key.version,
    );
    let sidecar = match read_sidecar(&sidecar_path) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_READ_ERR,
                workflow_id,
                &format!("Failed to read sidecar: {}", err),
            );
        }
    };

    let nav_title = normalize_nav_title_value(&sidecar.nav_title);
    let nav_parent_id = normalize_nav_parent_value(&sidecar.nav_parent_id, nav_title.is_some());
    let nav_order = normalize_nav_order_value(&sidecar.nav_order, nav_title.is_some());

    let content = if object.is_markdown {
        let blob_path = blob_path(
            &context.runtime_paths.content_dir,
            object.key.id,
            object.key.version,
        );
        match fs::read_to_string(&blob_path) {
            Ok(content) => Some(content),
            Err(err) => {
                return response_err(
                    CONTENT_ACTION_READ_ERR,
                    workflow_id,
                    &format!("Failed to read content: {}", err),
                );
            }
        }
    } else {
        None
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_READ_OK,
        workflow_id,
        payload: ResponsePayload::ContentRead(ContentReadResponse {
            id: content_id_hex(object.key.id),
            alias: sidecar.alias,
            title: sidecar.title,
            mime: sidecar.mime,
            tags: sidecar.tags,
            nav_title,
            nav_parent_id,
            nav_order,
            original_filename: sidecar.original_filename,
            theme: sidecar.theme,
            content,
        }),
    }
}

async fn handle_update(
    payload: ContentUpdateRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let reserved_paths = ReservedPaths::from_config(&context.config);
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, "Content not found"),
    };

    let current_sidecar_path = sidecar_path(
        &context.runtime_paths.content_dir,
        object.key.id,
        object.key.version,
    );
    let mut sidecar = match read_sidecar(&current_sidecar_path) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to read sidecar: {}", err),
            );
        }
    };

    if let Some(new_alias) = payload.new_alias {
        let canonical = match canonicalize_optional_with_reserved_paths(&new_alias, &reserved_paths)
        {
            Ok(alias) => alias,
            Err(err) => return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err),
        };
        if object.alias == HOME_ALIAS && canonical.as_deref() != Some(HOME_ALIAS) {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Index alias cannot be changed",
            );
        }
        if let Some(canonical) = canonical.as_ref()
            && canonical != &object.alias
            && let Some(existing) = cache.get_by_alias(canonical)
            && existing.key.id != object.key.id
        {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Alias already in use",
            );
        }
        sidecar.alias = canonical.unwrap_or_default();
    }

    if let Some(title) = payload.title {
        let trimmed = title.trim();
        if trimmed.is_empty() {
            sidecar.title = None;
        } else {
            sidecar.title = Some(trimmed.to_string());
        }
    }

    if let Some(tags) = payload.tags {
        if let Err(err) = validate_tags(&tags) {
            return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err);
        }
        sidecar.tags = tags;
    }

    let current_nav_title = normalize_nav_title_value(&sidecar.nav_title);
    let current_nav_parent_id =
        normalize_nav_parent_value(&sidecar.nav_parent_id, current_nav_title.is_some());
    let current_nav_order =
        normalize_nav_order_value(&sidecar.nav_order, current_nav_title.is_some());
    let mut nav_title = current_nav_title.clone();
    let mut nav_parent_id = current_nav_parent_id.clone();
    let mut nav_order = current_nav_order;

    let mut nav_title_updated = false;
    let mut nav_parent_updated = false;
    let mut nav_order_updated = false;

    if let Some(value) = payload.nav_title {
        nav_title_updated = true;
        nav_title = normalize_nav_title_input(&value);
        if nav_title.is_none() {
            nav_parent_id = None;
            nav_order = None;
        }
    }

    if let Some(value) = payload.nav_parent_id {
        nav_parent_updated = true;
        nav_parent_id = normalize_nav_parent_input(&value);
    }

    if let Some(value) = payload.nav_order {
        nav_order_updated = true;
        nav_order = Some(value);
    }

    let nav_modified = nav_title_updated || nav_parent_updated || nav_order_updated;
    let clear_children = nav_modified && current_nav_title.is_some() && nav_title.is_none();
    if nav_modified && nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPDATE_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_modified
        && nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, Some(object.key.id))
    {
        return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err);
    }

    if nav_modified {
        sidecar.nav_title = nav_title.clone();
        sidecar.nav_parent_id = nav_parent_id.clone();
        sidecar.nav_order = nav_order;
    }
    let nav_changed = nav_modified
        && (nav_title != current_nav_title
            || nav_parent_id != current_nav_parent_id
            || nav_order != current_nav_order);

    if let Some(theme) = payload.theme {
        let trimmed = theme.trim();
        if trimmed.is_empty() {
            sidecar.theme = None;
        } else {
            sidecar.theme = Some(trimmed.to_string());
        }
    }

    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }

    let content_bytes = payload.content.map(|content| content.into_bytes());
    if let Some(content) = content_bytes {
        if !object.is_markdown {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Only markdown content can be edited",
            );
        }
        if content.is_empty() {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                "Content cannot be empty",
            );
        }
        if let Err(err) = resolve_upload_limit(content.len() as u64, &context.config) {
            return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err);
        }

        let next_version = match object.key.version.0.checked_add(1) {
            Some(version) => ContentVersion(version),
            None => {
                return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, "Version overflow");
            }
        };
        let blob = blob_path(
            &context.runtime_paths.content_dir,
            object.key.id,
            next_version,
        );
        if let Some(parent) = blob.parent()
            && let Err(err) = fs::create_dir_all(parent)
        {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to create shard dir: {}", err),
            );
        }
        if let Err(err) = fs::write(&blob, content) {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to write content: {}", err),
            );
        }
        let new_sidecar_path = sidecar_path(
            &context.runtime_paths.content_dir,
            object.key.id,
            next_version,
        );
        if let Err(err) = write_sidecar_atomic(&new_sidecar_path, &sidecar) {
            return response_err(
                CONTENT_ACTION_UPDATE_ERR,
                workflow_id,
                &format!("Failed to write sidecar: {}", err),
            );
        }
    } else if let Err(err) = write_sidecar_atomic(&current_sidecar_path, &sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_ERR,
            workflow_id,
            &format!("Failed to update sidecar: {}", err),
        );
    }

    if clear_children
        && let Err(err) =
            clear_child_nav_titles(&cache, &context.runtime_paths.content_dir, object.key.id)
    {
        return response_err(CONTENT_ACTION_UPDATE_ERR, workflow_id, &err);
    }

    invalidate_cache(context).await;
    if nav_changed {
        bump_release_tracker_for_nav_change(context, content_id);
    }
    response_ok(
        CONTENT_ACTION_UPDATE_OK,
        workflow_id,
        "Content updated successfully",
    )
}

async fn handle_delete(
    payload: ContentDeleteRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_DELETE_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_DELETE_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => return response_err(CONTENT_ACTION_DELETE_ERR, workflow_id, "Content not found"),
    };
    let nav_has_entry =
        object.nav_title.is_some() || object.nav_parent_id.is_some() || object.nav_order.is_some();

    if let Err(err) = delete_all_versions(&context.runtime_paths.content_dir, object.key.id) {
        return response_err(
            CONTENT_ACTION_DELETE_ERR,
            workflow_id,
            &format!("Failed to delete content: {}", err),
        );
    }

    invalidate_cache(context).await;
    if nav_has_entry {
        bump_release_tracker_for_nav_change(context, content_id);
    }
    response_ok(
        CONTENT_ACTION_DELETE_OK,
        workflow_id,
        "Content deleted successfully",
    )
}

async fn handle_upload(
    payload: ContentUploadRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err);
    }
    if let Err(err) = resolve_upload_limit(payload.content.len() as u64, &context.config) {
        return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err);
    }

    let reserved_paths = ReservedPaths::from_config(&context.config);
    let alias = match payload.alias.as_deref() {
        Some(value) => match canonicalize_optional_with_reserved_paths(value, &reserved_paths) {
            Ok(alias) => alias,
            Err(err) => return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err),
        },
        None => None,
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err),
    };

    if let Some(alias) = alias.as_ref()
        && cache.get_by_alias(alias).is_some()
    {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            "Alias already exists",
        );
    }

    let content_id = match generate_content_id() {
        Ok(id) => id,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_ERR,
                workflow_id,
                &format!("Failed to generate ID: {}", err),
            );
        }
    };
    let version = ContentVersion(1);
    let mime = if payload.mime.trim().eq_ignore_ascii_case("text/markdown") {
        "text/markdown".to_string()
    } else {
        let filename = payload
            .original_filename
            .as_deref()
            .or(alias.as_deref())
            .unwrap_or("upload");
        detect_mime_type(Path::new(filename), &payload.content)
    };

    let nav_title = normalize_nav_title_value(&payload.nav_title);
    let mut nav_parent_id = normalize_nav_parent_value(&payload.nav_parent_id, nav_title.is_some());
    let mut nav_order = normalize_nav_order_value(&payload.nav_order, nav_title.is_some());
    if nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, None)
    {
        return response_err(CONTENT_ACTION_UPLOAD_ERR, workflow_id, &err);
    }

    if nav_title.is_none() {
        nav_parent_id = None;
        nav_order = None;
    }
    let nav_has_entry = nav_title.is_some();

    let sidecar = ContentSidecar {
        alias: alias.clone().unwrap_or_default(),
        title: payload.title.clone(),
        mime: mime.clone(),
        tags: payload.tags.clone(),
        nav_title,
        nav_parent_id,
        nav_order,
        original_filename: payload.original_filename.clone(),
        theme: payload.theme.clone(),
    };
    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }
    let blob = blob_path(&context.runtime_paths.content_dir, content_id, version);
    if let Some(parent) = blob.parent()
        && let Err(err) = fs::create_dir_all(parent)
    {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Failed to create shard dir: {}", err),
        );
    }
    if let Err(err) = fs::write(&blob, &payload.content) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Failed to write content: {}", err),
        );
    }

    let sidecar_path = sidecar_path(&context.runtime_paths.content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    invalidate_cache(context).await;
    if nav_has_entry {
        bump_release_tracker_for_nav_change(context, content_id);
    }
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPLOAD_OK,
        workflow_id,
        payload: ResponsePayload::ContentUpload(ContentUploadResponse {
            id: content_id_hex(content_id),
            alias: alias.unwrap_or_default(),
            mime: mime.clone(),
            is_markdown: mime == "text/markdown",
        }),
    }
}

async fn handle_nav_index(
    _payload: ContentNavIndexRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_NAV_INDEX_ERR, workflow_id, &err),
    };

    let items = cache
        .list_nav_objects()
        .into_iter()
        .map(|object| ContentNavIndexEntry {
            id: content_id_hex(object.key.id),
            alias: object.alias,
            title: object.title,
            nav_title: object.nav_title,
            nav_parent_id: object.nav_parent_id,
            nav_order: object.nav_order,
        })
        .collect();

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_NAV_INDEX_OK,
        workflow_id,
        payload: ResponsePayload::ContentNavIndex(ContentNavIndexResponse { items }),
    }
}

async fn handle_binary_prevalidate(
    payload: BinaryPrevalidateRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(CONTENT_ACTION_BINARY_PREVALIDATE_ERR, workflow_id, &err);
    }

    let decision = validate_binary_file_inputs(
        &payload.filename,
        &payload.mime,
        payload.size_bytes,
        context,
    );
    let (accepted, message) = match decision {
        Ok(_) => (true, "Accepted".to_string()),
        Err(err) => (false, err),
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_BINARY_PREVALIDATE_OK,
        workflow_id,
        payload: ResponsePayload::ContentBinaryPrevalidate(BinaryPrevalidateResponse {
            accepted,
            message,
        }),
    }
}

async fn handle_binary_upload_init(
    payload: BinaryUploadInitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err);
    }
    if let Err(err) = validate_binary_file_inputs(
        &payload.filename,
        &payload.mime,
        payload.size_bytes,
        context,
    ) {
        return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err);
    }

    let reserved_paths = ReservedPaths::from_config(&context.config);
    let alias = match payload.alias.as_deref() {
        Some(value) => match canonicalize_optional_with_reserved_paths(value, &reserved_paths) {
            Ok(alias) => alias,
            Err(err) => {
                return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err);
            }
        },
        None => None,
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err),
    };

    if let Some(alias) = alias.as_ref()
        && cache.get_by_alias(alias).is_some()
    {
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
            workflow_id,
            "Alias already exists",
        );
    }

    let content_id = match generate_content_id() {
        Ok(id) => id,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
                workflow_id,
                &format!("Failed to generate ID: {}", err),
            );
        }
    };
    let version = ContentVersion(1);
    let blob = blob_path(&context.runtime_paths.content_dir, content_id, version);
    let temp_path = temp_upload_path(&blob);

    let max_bytes = match resolve_upload_limit(payload.size_bytes, &context.config) {
        Ok(max_bytes) => max_bytes,
        Err(err) => return response_err(CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR, workflow_id, &err),
    };

    let init_config = crate::management::upload_registry::UploadBeginConfig::builder(
        connection_id,
        crate::management::upload_registry::UploadKind::Binary(
            crate::management::upload_registry::BinaryUploadMeta {
                content_id: content_id.0,
                version: version.0,
                alias: alias.clone().unwrap_or_default(),
                title: payload.title.clone(),
                tags: payload.tags.clone(),
                filename: payload.filename.clone(),
                mime: payload.mime.clone(),
            },
        ),
        temp_path,
        payload.size_bytes,
        max_bytes,
        DEFAULT_STREAM_CHUNK_BYTES,
    )
    .validate_utf8(false)
    .build();

    let init = match context.upload_registry.begin_upload(init_config).await {
        Ok(init) => init,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUploadStreamInit(UploadStreamInitResponse {
            upload_id: init.upload_id,
            stream_id: init.stream_id,
            max_bytes: init.max_bytes,
            chunk_bytes: init.chunk_bytes,
        }),
    }
}

async fn handle_binary_upload_commit(
    payload: BinaryUploadCommitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let record = match context.upload_registry.take_upload(payload.upload_id).await {
        Ok(record) => record,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let crate::management::upload_registry::UploadRecord {
        kind,
        temp_path,
        connection_id: record_connection_id,
        complete,
        file,
        ..
    } = record;

    if record_connection_id != connection_id {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            "Upload session mismatch",
        );
    }

    if !complete {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            "Upload stream not complete",
        );
    }

    let meta = match kind {
        crate::management::upload_registry::UploadKind::Binary(meta) => meta,
        _ => {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
                workflow_id,
                "Upload type mismatch",
            );
        }
    };

    drop(file);

    let content_id = ContentId(meta.content_id);
    let version = ContentVersion(meta.version);
    let blob = blob_path(&context.runtime_paths.content_dir, content_id, version);
    if let Err(err) = fs::rename(&temp_path, &blob) {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            &format!("Failed to finalize upload: {}", err),
        );
    }

    let detected_mime = detect_mime_for_upload(&blob, &meta.filename);
    let sidecar = ContentSidecar {
        alias: meta.alias.clone(),
        title: meta.title.clone(),
        mime: detected_mime.clone(),
        tags: meta.tags.clone(),
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: Some(meta.filename.clone()),
        theme: None,
    };
    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }
    let sidecar_path = sidecar_path(&context.runtime_paths.content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &sidecar) {
        return response_err(
            CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    invalidate_cache(context).await;
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUpload(ContentUploadResponse {
            id: content_id_hex(content_id),
            alias: meta.alias,
            mime: detected_mime.clone(),
            is_markdown: detected_mime == "text/markdown",
        }),
    }
}

async fn handle_upload_stream_init(
    payload: ContentUploadStreamInitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err);
    }
    let max_bytes = match resolve_upload_limit(payload.size_bytes, &context.config) {
        Ok(max_bytes) => max_bytes,
        Err(err) => return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err),
    };

    let reserved_paths = ReservedPaths::from_config(&context.config);
    let alias = match payload.alias.as_deref() {
        Some(value) => match canonicalize_optional_with_reserved_paths(value, &reserved_paths) {
            Ok(alias) => alias,
            Err(err) => {
                return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err);
            }
        },
        None => None,
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err),
    };

    if let Some(alias) = alias.as_ref()
        && cache.get_by_alias(alias).is_some()
    {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            workflow_id,
            "Alias already exists",
        );
    }

    let content_id = match generate_content_id() {
        Ok(id) => id,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
                workflow_id,
                &format!("Failed to generate ID: {}", err),
            );
        }
    };
    let version = ContentVersion(1);

    let nav_title = normalize_nav_title_value(&payload.nav_title);
    let mut nav_parent_id = normalize_nav_parent_value(&payload.nav_parent_id, nav_title.is_some());
    let mut nav_order = normalize_nav_order_value(&payload.nav_order, nav_title.is_some());
    if nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, None)
    {
        return response_err(CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR, workflow_id, &err);
    }

    if nav_title.is_none() {
        nav_parent_id = None;
        nav_order = None;
    }

    let sidecar = ContentSidecar {
        alias: alias.clone().unwrap_or_default(),
        title: payload.title.clone(),
        mime: "text/markdown".to_string(),
        tags: payload.tags.clone(),
        nav_title,
        nav_parent_id,
        nav_order,
        original_filename: None,
        theme: payload.theme.clone(),
    };
    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }

    let blob = blob_path(&context.runtime_paths.content_dir, content_id, version);
    let temp_path = temp_upload_path(&blob);
    let init_config = crate::management::upload_registry::UploadBeginConfig::builder(
        connection_id,
        crate::management::upload_registry::UploadKind::MarkdownCreate(
            crate::management::upload_registry::MarkdownUploadMeta {
                content_id: content_id.0,
                version: version.0,
                sidecar,
            },
        ),
        temp_path,
        payload.size_bytes,
        max_bytes,
        DEFAULT_STREAM_CHUNK_BYTES,
    )
    .validate_utf8(true)
    .build();

    let init = match context.upload_registry.begin_upload(init_config).await {
        Ok(init) => init,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUploadStreamInit(UploadStreamInitResponse {
            upload_id: init.upload_id,
            stream_id: init.stream_id,
            max_bytes: init.max_bytes,
            chunk_bytes: init.chunk_bytes,
        }),
    }
}

async fn handle_upload_stream_commit(
    payload: ContentUploadStreamCommitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let record = match context.upload_registry.take_upload(payload.upload_id).await {
        Ok(record) => record,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let crate::management::upload_registry::UploadRecord {
        kind,
        temp_path,
        connection_id: record_connection_id,
        complete,
        file,
        ..
    } = record;

    if record_connection_id != connection_id {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload session mismatch",
        );
    }

    if !complete {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload stream not complete",
        );
    }

    let meta = match kind {
        crate::management::upload_registry::UploadKind::MarkdownCreate(meta) => meta,
        _ => {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
                workflow_id,
                "Upload type mismatch",
            );
        }
    };

    drop(file);

    let content_id = ContentId(meta.content_id);
    let version = ContentVersion(meta.version);
    let blob = blob_path(&context.runtime_paths.content_dir, content_id, version);
    if let Err(err) = fs::rename(&temp_path, &blob) {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to finalize upload: {}", err),
        );
    }

    let sidecar_path = sidecar_path(&context.runtime_paths.content_dir, content_id, version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &meta.sidecar) {
        return response_err(
            CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    invalidate_cache(context).await;
    if meta.sidecar.nav_title.is_some() {
        bump_release_tracker_for_nav_change(context, content_id);
    }
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUpload(ContentUploadResponse {
            id: content_id_hex(content_id),
            alias: meta.sidecar.alias,
            mime: "text/markdown".to_string(),
            is_markdown: true,
        }),
    }
}

async fn handle_update_stream_init(
    payload: ContentUpdateStreamInitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
    }
    let max_bytes = match resolve_upload_limit(payload.size_bytes, &context.config) {
        Ok(max_bytes) => max_bytes,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err),
    };

    let reserved_paths = ReservedPaths::from_config(&context.config);
    let content_id = match parse_id_or_err(&payload.id) {
        Ok(id) => id,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err),
    };

    let cache = match get_cache(context).await {
        Ok(cache) => cache,
        Err(err) => return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err),
    };

    let object = match cache.get_by_id(content_id) {
        Some(object) => object,
        None => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Content not found",
            );
        }
    };

    if !object.is_markdown {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            workflow_id,
            "Only markdown content can be edited",
        );
    }

    let current_sidecar_path = sidecar_path(
        &context.runtime_paths.content_dir,
        object.key.id,
        object.key.version,
    );
    let mut sidecar = match read_sidecar(&current_sidecar_path) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                &format!("Failed to read sidecar: {}", err),
            );
        }
    };

    if let Some(new_alias) = payload.new_alias.clone() {
        let canonical = match canonicalize_optional_with_reserved_paths(&new_alias, &reserved_paths)
        {
            Ok(alias) => alias,
            Err(err) => {
                return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
            }
        };
        if object.alias == HOME_ALIAS && canonical.as_deref() != Some(HOME_ALIAS) {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Index alias cannot be changed",
            );
        }
        if let Some(canonical) = canonical.as_ref()
            && canonical != &object.alias
            && let Some(existing) = cache.get_by_alias(canonical)
            && existing.key.id != object.key.id
        {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Alias already in use",
            );
        }
        sidecar.alias = canonical.unwrap_or_default();
    }

    if let Some(title) = payload.title.clone() {
        let trimmed = title.trim();
        if trimmed.is_empty() {
            sidecar.title = None;
        } else {
            sidecar.title = Some(trimmed.to_string());
        }
    }

    if let Some(tags) = payload.tags.clone() {
        if let Err(err) = validate_tags(&tags) {
            return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
        }
        sidecar.tags = tags;
    }

    let current_nav_title = normalize_nav_title_value(&sidecar.nav_title);
    let current_nav_parent_id =
        normalize_nav_parent_value(&sidecar.nav_parent_id, current_nav_title.is_some());
    let current_nav_order =
        normalize_nav_order_value(&sidecar.nav_order, current_nav_title.is_some());
    let mut nav_title = current_nav_title.clone();
    let mut nav_parent_id = current_nav_parent_id.clone();
    let mut nav_order = current_nav_order;

    let mut nav_title_updated = false;
    let mut nav_parent_updated = false;
    let mut nav_order_updated = false;

    if let Some(value) = payload.nav_title.clone() {
        nav_title_updated = true;
        nav_title = normalize_nav_title_input(&value);
        if nav_title.is_none() {
            nav_parent_id = None;
            nav_order = None;
        }
    }

    if let Some(value) = payload.nav_parent_id.clone() {
        nav_parent_updated = true;
        nav_parent_id = normalize_nav_parent_input(&value);
    }

    if let Some(value) = payload.nav_order {
        nav_order_updated = true;
        nav_order = Some(value);
    }

    let nav_modified = nav_title_updated || nav_parent_updated || nav_order_updated;
    let clear_children = nav_modified && current_nav_title.is_some() && nav_title.is_none();
    if nav_modified && nav_title.is_none() && (nav_parent_id.is_some() || nav_order.is_some()) {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            workflow_id,
            "Navbar title is required when setting navbar parent or order",
        );
    }

    if nav_modified
        && nav_title.is_some()
        && let Some(parent_id) = nav_parent_id.as_ref()
        && let Err(err) = validate_nav_parent_id(parent_id, &cache, Some(object.key.id))
    {
        return response_err(CONTENT_ACTION_UPDATE_STREAM_INIT_ERR, workflow_id, &err);
    }

    if nav_modified {
        sidecar.nav_title = nav_title.clone();
        sidecar.nav_parent_id = nav_parent_id.clone();
        sidecar.nav_order = nav_order;
    }
    let nav_changed = nav_modified
        && (nav_title != current_nav_title
            || nav_parent_id != current_nav_parent_id
            || nav_order != current_nav_order);

    if let Some(theme) = payload.theme.clone() {
        let trimmed = theme.trim();
        if trimmed.is_empty() {
            sidecar.theme = None;
        } else {
            sidecar.theme = Some(trimmed.to_string());
        }
    }

    if let Err(err) = validate_sidecar(&sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
            workflow_id,
            &format!("Invalid sidecar: {}", err),
        );
    }

    let next_version = match object.key.version.0.checked_add(1) {
        Some(version) => ContentVersion(version),
        None => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                "Version overflow",
            );
        }
    };
    let blob = blob_path(
        &context.runtime_paths.content_dir,
        object.key.id,
        next_version,
    );
    let temp_path = temp_upload_path(&blob);

    let init_config = crate::management::upload_registry::UploadBeginConfig::builder(
        connection_id,
        crate::management::upload_registry::UploadKind::MarkdownUpdate(
            crate::management::upload_registry::MarkdownUpdateMeta {
                content_id: object.key.id.0,
                base_version: object.key.version.0,
                sidecar,
                clear_children,
                nav_changed,
            },
        ),
        temp_path,
        payload.size_bytes,
        max_bytes,
        DEFAULT_STREAM_CHUNK_BYTES,
    )
    .validate_utf8(true)
    .build();

    let init = match context.upload_registry.begin_upload(init_config).await {
        Ok(init) => init,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id: CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
        workflow_id,
        payload: ResponsePayload::ContentUploadStreamInit(UploadStreamInitResponse {
            upload_id: init.upload_id,
            stream_id: init.stream_id,
            max_bytes: init.max_bytes,
            chunk_bytes: init.chunk_bytes,
        }),
    }
}

async fn handle_update_stream_commit(
    payload: ContentUpdateStreamCommitRequest,
    workflow_id: u32,
    connection_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let record = match context.upload_registry.take_upload(payload.upload_id).await {
        Ok(record) => record,
        Err(err) => {
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let crate::management::upload_registry::UploadRecord {
        kind,
        temp_path,
        connection_id: record_connection_id,
        complete,
        file,
        ..
    } = record;

    if record_connection_id != connection_id {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload session mismatch",
        );
    }

    if !complete {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            "Upload stream not complete",
        );
    }

    let meta = match kind {
        crate::management::upload_registry::UploadKind::MarkdownUpdate(meta) => meta,
        _ => {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
                workflow_id,
                "Upload type mismatch",
            );
        }
    };

    drop(file);

    let content_id = ContentId(meta.content_id);
    let next_version = match meta.base_version.checked_add(1) {
        Some(version) => ContentVersion(version),
        None => {
            let _ = fs::remove_file(&temp_path);
            return response_err(
                CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
                workflow_id,
                "Version overflow",
            );
        }
    };

    let blob = blob_path(&context.runtime_paths.content_dir, content_id, next_version);
    if let Err(err) = fs::rename(&temp_path, &blob) {
        let _ = fs::remove_file(&temp_path);
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to finalize upload: {}", err),
        );
    }

    let sidecar_path = sidecar_path(&context.runtime_paths.content_dir, content_id, next_version);
    if let Err(err) = write_sidecar_atomic(&sidecar_path, &meta.sidecar) {
        return response_err(
            CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
            workflow_id,
            &format!("Failed to write sidecar: {}", err),
        );
    }

    if meta.clear_children
        && let Ok(cache) = get_cache(context).await
        && let Err(err) =
            clear_child_nav_titles(&cache, &context.runtime_paths.content_dir, content_id)
    {
        return response_err(CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR, workflow_id, &err);
    }

    invalidate_cache(context).await;
    if meta.nav_changed {
        bump_release_tracker_for_nav_change(context, content_id);
    }
    response_ok(
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
        workflow_id,
        "Content updated successfully",
    )
}

async fn get_cache(context: &ManagementContext) -> Result<PageMetaCache, String> {
    if let Some(cache) = context.page_cache.as_ref() {
        return Ok(cache.as_ref().clone());
    }

    let cache = PageMetaCache::new(
        context.runtime_paths.content_dir.clone(),
        context.runtime_paths.state_sys_dir.clone(),
        crate::content::reserved_paths::ReservedPaths::from_config(&context.config),
    );
    cache
        .rebuild_cache(true)
        .await
        .map_err(|err| format!("Failed to rebuild cache: {}", err))?;
    Ok(cache)
}

async fn invalidate_cache(context: &ManagementContext) {
    if let Some(cache) = context.page_cache.as_ref()
        && let Err(err) = cache.invalidate().await
    {
        log::error!("Failed to invalidate page cache: {}", err);
    }
}

fn bump_release_tracker_for_nav_change(context: &ManagementContext, content_id: ContentId) {
    if let Some(tracker) = context.release_tracker.as_ref() {
        tracker.bump(&format!("nav updated ({})", content_id_hex(content_id)));
    }
}

fn upload_max_bytes(config: &crate::config::ValidatedConfig) -> Result<Option<u64>, String> {
    let max_mb = config.upload.max_file_size_mb;
    if max_mb == 0 {
        return Ok(None);
    }
    max_mb
        .checked_mul(1024)
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| "Upload size limit overflow".to_string())
        .map(Some)
}

fn resolve_upload_limit(
    size_bytes: u64,
    config: &crate::config::ValidatedConfig,
) -> Result<u64, String> {
    if size_bytes == 0 {
        return Err("Upload size must be greater than 0".to_string());
    }
    let limit = upload_max_bytes(config)?;
    if let Some(max_bytes) = limit {
        if size_bytes > max_bytes {
            return Err("Content exceeds maximum size".to_string());
        }
        return Ok(max_bytes);
    }
    Ok(size_bytes)
}

fn ensure_allowed_extension(
    filename: &str,
    config: &crate::config::ValidatedConfig,
) -> Result<(), String> {
    let ext = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .ok_or_else(|| "Filename must include an extension".to_string())?;

    if config.upload.allowed_extensions.is_empty() {
        return Ok(());
    }

    if config
        .upload
        .allowed_extensions
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&ext))
    {
        Ok(())
    } else {
        Err("File type is not allowed".to_string())
    }
}

fn temp_upload_path(blob_path: &Path) -> std::path::PathBuf {
    let mut temp = blob_path.to_path_buf();
    let file_name = blob_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("upload");
    temp.set_file_name(format!("{}.upload", file_name));
    temp
}

fn validate_binary_file_inputs(
    filename: &str,
    _mime: &str,
    size_bytes: u64,
    context: &ManagementContext,
) -> Result<(), String> {
    resolve_upload_limit(size_bytes, &context.config)?;
    ensure_allowed_extension(filename, &context.config)?;
    crate::security::validate_new_file_path(filename, &context.runtime_paths.content_dir)?;
    Ok(())
}

fn detect_mime_for_upload(blob_path: &Path, filename: &str) -> String {
    let mut buffer = vec![0u8; 8192];
    let mut read_len = 0usize;
    if let Ok(mut file) = fs::File::open(blob_path)
        && let Ok(bytes) = file.read(&mut buffer)
    {
        read_len = bytes;
    }
    buffer.truncate(read_len);
    detect_mime_type(Path::new(filename), &buffer)
}

fn delete_all_versions(content_dir: &Path, id: ContentId) -> Result<(), std::io::Error> {
    let shard = format!("{:02x}", (id.0 & 0xff) as u8);
    let dir = content_dir.join(shard);
    if !dir.exists() {
        return Ok(());
    }

    let prefix = format!("{:016x}.", id.0);
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with(&prefix) {
            continue;
        }
        fs::remove_file(entry.path())?;
    }
    Ok(())
}

fn canonicalize_optional_or_err(value: &str) -> Result<Option<String>, String> {
    let alias = normalize_optional_alias(value).map_err(|err| err.to_string())?;
    if let Some(alias) = alias.as_ref()
        && alias.chars().count() > MAX_ALIAS_CHARS
    {
        return Err("Alias too long".to_string());
    }
    Ok(alias)
}

fn canonicalize_optional_with_reserved_paths(
    value: &str,
    reserved_paths: &ReservedPaths,
) -> Result<Option<String>, String> {
    let alias = canonicalize_optional_or_err(value)?;
    if let Some(alias) = alias.as_ref()
        && reserved_paths.alias_is_reserved(alias)
    {
        return Err("Alias uses reserved path".to_string());
    }
    Ok(alias)
}

fn parse_id_or_err(value: &str) -> Result<ContentId, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Content ID is required".to_string());
    }
    parse_content_id_hex(trimmed)
}

fn validate_tags(tags: &[String]) -> Result<(), String> {
    if tags.len() > MAX_TAG_COUNT {
        return Err("Too many tags".to_string());
    }
    for tag in tags {
        if tag.chars().count() > MAX_TAG_CHARS {
            return Err("Tag is too long".to_string());
        }
        if !tag.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '/'
        }) {
            return Err(format!("Invalid tag id '{}'", tag));
        }
    }
    Ok(())
}

fn normalize_nav_title_input(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_nav_title_value(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .and_then(|value| normalize_nav_title_input(value))
}

fn normalize_nav_parent_input(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn normalize_nav_parent_value(value: &Option<String>, has_nav_title: bool) -> Option<String> {
    if !has_nav_title {
        return None;
    }
    let normalized = value
        .as_ref()
        .and_then(|value| normalize_nav_parent_input(value))?;
    if parse_content_id_hex(&normalized).is_err() {
        return None;
    }
    Some(normalized)
}

fn normalize_nav_order_value(value: &Option<i32>, has_nav_title: bool) -> Option<i32> {
    if has_nav_title { *value } else { None }
}

fn validate_nav_parent_id(
    parent_id: &str,
    cache: &PageMetaCache,
    self_id: Option<ContentId>,
) -> Result<(), String> {
    let parent_id = parse_content_id_hex(parent_id)
        .map_err(|err| format!("Invalid navbar parent id: {}", err))?;
    if let Some(self_id) = self_id
        && self_id == parent_id
    {
        return Err("Navbar parent cannot reference itself".to_string());
    }

    let parent = cache
        .list_objects()
        .into_iter()
        .find(|object| object.key.id == parent_id)
        .ok_or_else(|| "Navbar parent not found".to_string())?;
    if parent.nav_title.is_none() {
        return Err("Navbar parent must have a navbar title".to_string());
    }
    if parent.nav_parent_id.is_some() {
        return Err("Navbar parent must be a root item".to_string());
    }
    Ok(())
}

fn clear_child_nav_titles(
    cache: &PageMetaCache,
    content_dir: &Path,
    parent_id: ContentId,
) -> Result<(), String> {
    let parent_id_hex = content_id_hex(parent_id);
    let children: Vec<_> = cache
        .list_objects()
        .into_iter()
        .filter(|object| object.nav_parent_id.as_deref() == Some(parent_id_hex.as_str()))
        .collect();

    for child in children {
        let sidecar_path = sidecar_path(content_dir, child.key.id, child.key.version);
        let mut sidecar = read_sidecar(&sidecar_path)
            .map_err(|err| format!("Failed to read child sidecar: {}", err))?;
        sidecar.nav_title = None;
        sidecar.nav_parent_id = None;
        sidecar.nav_order = None;
        write_sidecar_atomic(&sidecar_path, &sidecar)
            .map_err(|err| format!("Failed to update child sidecar: {}", err))?;
    }
    Ok(())
}

impl ContentListRequest {
    fn validate(&self) -> Result<(), String> {
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err("Invalid page size".to_string());
        }
        if let Some(query) = &self.query
            && query.chars().count() > MAX_QUERY_CHARS
        {
            return Err("Query too long".to_string());
        }
        if let Some(tags) = &self.tags {
            if tags.iter().any(|tag| tag.trim().is_empty()) {
                return Err("Tag cannot be empty".to_string());
            }
            validate_tags(tags)?;
        }
        Ok(())
    }
}

impl ContentUploadRequest {
    fn validate(&self) -> Result<(), String> {
        if let Some(alias) = &self.alias {
            canonicalize_optional_or_err(alias)?;
        }
        if self.mime.trim().is_empty() {
            return Err("Missing mime".to_string());
        }
        if self.mime.chars().count() > MAX_MIME_CHARS {
            return Err("Mime too long".to_string());
        }
        if let Some(title) = &self.title
            && title.chars().count() > MAX_TITLE_CHARS
        {
            return Err("Title too long".to_string());
        }
        if let Some(filename) = &self.original_filename
            && filename.chars().count() > MAX_ORIGINAL_FILENAME_CHARS
        {
            return Err("Original filename too long".to_string());
        }
        if let Some(theme) = &self.theme
            && theme.chars().count() > MAX_THEME_CHARS
        {
            return Err("Theme too long".to_string());
        }
        if self.content.is_empty() {
            return Err("Content cannot be empty".to_string());
        }
        validate_tags(&self.tags)?;
        Ok(())
    }
}

impl ContentUpdateRequest {
    fn validate(&self) -> Result<(), String> {
        parse_id_or_err(&self.id)?;
        if let Some(new_alias) = &self.new_alias {
            canonicalize_optional_or_err(new_alias)?;
        }
        if let Some(title) = &self.title
            && title.chars().count() > MAX_TITLE_CHARS
        {
            return Err("Title too long".to_string());
        }
        if let Some(tags) = &self.tags {
            validate_tags(tags)?;
        }
        if let Some(theme) = &self.theme
            && theme.chars().count() > MAX_THEME_CHARS
        {
            return Err("Theme too long".to_string());
        }
        if let Some(content) = &self.content
            && content.is_empty()
        {
            return Err("Content cannot be empty".to_string());
        }
        Ok(())
    }
}

impl BinaryPrevalidateRequest {
    fn validate(&self) -> Result<(), String> {
        if self.filename.trim().is_empty() {
            return Err("Filename is required".to_string());
        }
        if self.filename.chars().count() > MAX_ORIGINAL_FILENAME_CHARS {
            return Err("Filename too long".to_string());
        }
        if self.mime.trim().is_empty() {
            return Err("Missing mime".to_string());
        }
        if self.mime.chars().count() > MAX_MIME_CHARS {
            return Err("Mime too long".to_string());
        }
        if self.size_bytes == 0 {
            return Err("Upload size must be greater than 0".to_string());
        }
        Ok(())
    }
}

impl BinaryUploadInitRequest {
    fn validate(&self) -> Result<(), String> {
        if let Some(alias) = &self.alias {
            canonicalize_optional_or_err(alias)?;
        }
        if let Some(title) = &self.title
            && title.chars().count() > MAX_TITLE_CHARS
        {
            return Err("Title too long".to_string());
        }
        if self.filename.trim().is_empty() {
            return Err("Filename is required".to_string());
        }
        if self.filename.chars().count() > MAX_ORIGINAL_FILENAME_CHARS {
            return Err("Filename too long".to_string());
        }
        if self.mime.trim().is_empty() {
            return Err("Missing mime".to_string());
        }
        if self.mime.chars().count() > MAX_MIME_CHARS {
            return Err("Mime too long".to_string());
        }
        if self.size_bytes == 0 {
            return Err("Upload size must be greater than 0".to_string());
        }
        validate_tags(&self.tags)?;
        Ok(())
    }
}

impl ContentUploadStreamInitRequest {
    fn validate(&self) -> Result<(), String> {
        if let Some(alias) = &self.alias {
            canonicalize_optional_or_err(alias)?;
        }
        if let Some(title) = &self.title
            && title.chars().count() > MAX_TITLE_CHARS
        {
            return Err("Title too long".to_string());
        }
        if let Some(theme) = &self.theme
            && theme.chars().count() > MAX_THEME_CHARS
        {
            return Err("Theme too long".to_string());
        }
        if self.size_bytes == 0 {
            return Err("Upload size must be greater than 0".to_string());
        }
        validate_tags(&self.tags)?;
        Ok(())
    }
}

impl ContentUpdateStreamInitRequest {
    fn validate(&self) -> Result<(), String> {
        parse_id_or_err(&self.id)?;
        if let Some(new_alias) = &self.new_alias {
            canonicalize_optional_or_err(new_alias)?;
        }
        if let Some(title) = &self.title
            && title.chars().count() > MAX_TITLE_CHARS
        {
            return Err("Title too long".to_string());
        }
        if let Some(tags) = &self.tags {
            validate_tags(tags)?;
        }
        if let Some(theme) = &self.theme
            && theme.chars().count() > MAX_THEME_CHARS
        {
            return Err("Theme too long".to_string());
        }
        if self.size_bytes == 0 {
            return Err("Upload size must be greater than 0".to_string());
        }
        Ok(())
    }
}

fn response_ok(action_id: u32, workflow_id: u32, message: &str) -> ManagementResponse {
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id,
        workflow_id,
        payload: ResponsePayload::Message(MessageResponse {
            message: message.to_string(),
        }),
    }
}

fn response_err(action_id: u32, workflow_id: u32, message: &str) -> ManagementResponse {
    ManagementResponse {
        domain_id: CONTENT_DOMAIN_ID,
        action_id,
        workflow_id,
        payload: ResponsePayload::Message(MessageResponse {
            message: message.to_string(),
        }),
    }
}

struct ContentListRequestCodec;

impl RequestCodec for ContentListRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("query", FieldLimit::MaxChars(MAX_QUERY_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentListRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::List(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::List(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content list codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::List(request)) => {
                request
                    .validate()
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(query) = &request.query {
                    values.insert_len("query", query.chars().count());
                }
                if let Some(tags) = &request.tags {
                    values.insert_count("tags", tags.len());
                    values.insert_lens("tag", tags.iter().map(|tag| tag.chars().count()).collect());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content list codec",
            )),
        }
    }
}

struct ContentReadRequestCodec;

impl RequestCodec for ContentReadRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_READ)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("id", FieldLimit::MaxChars(MAX_ID_CHARS))])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentReadRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Read(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Read(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content read codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Read(request)) => {
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                parse_id_or_err(&request.id)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content read codec",
            )),
        }
    }
}

struct ContentUpdateRequestCodec;

impl RequestCodec for ContentUpdateRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("new_alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUpdateRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Update(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Update(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Update(request)) => {
                request
                    .validate()
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                if let Some(new_alias) = &request.new_alias {
                    values.insert_len("new_alias", new_alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                if let Some(tags) = &request.tags {
                    values.insert_count("tags", tags.len());
                    values.insert_lens("tag", tags.iter().map(|tag| tag.chars().count()).collect());
                }
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update codec",
            )),
        }
    }
}

struct ContentDeleteRequestCodec;

impl RequestCodec for ContentDeleteRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_DELETE)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("id", FieldLimit::MaxChars(MAX_ID_CHARS))])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentDeleteRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Delete(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Delete(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content delete codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Delete(request)) => {
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                parse_id_or_err(&request.id)
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content delete codec",
            )),
        }
    }
}

struct ContentUploadRequestCodec;

impl RequestCodec for ContentUploadRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            (
                "original_filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUploadRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::Upload(request)))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Upload(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::Upload(request)) => {
                request
                    .validate()
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(alias) = &request.alias {
                    values.insert_len("alias", alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_len("mime", request.mime.chars().count());
                values.insert_count("tags", request.tags.len());
                values.insert_lens(
                    "tag",
                    request.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(filename) = &request.original_filename {
                    values.insert_len("original_filename", filename.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload codec",
            )),
        }
    }
}

struct ContentNavIndexRequestCodec;

impl RequestCodec for ContentNavIndexRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentNavIndexRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(ContentCommand::NavIndex(
            request,
        )))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::NavIndex(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content nav index codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::NavIndex(_)) => Ok(()),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content nav index codec",
            )),
        }
    }
}

struct BinaryPrevalidateRequestCodec;

impl RequestCodec for BinaryPrevalidateRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            (
                "filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: BinaryPrevalidateRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::BinaryPrevalidate(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryPrevalidate(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary prevalidate codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryPrevalidate(request)) => {
                request
                    .validate()
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                values.insert_len("filename", request.filename.chars().count());
                values.insert_len("mime", request.mime.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary prevalidate codec",
            )),
        }
    }
}

struct BinaryUploadInitRequestCodec;

impl RequestCodec for BinaryUploadInitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_INIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            (
                "filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: BinaryUploadInitRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::BinaryUploadInit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryUploadInit(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary upload init codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryUploadInit(request)) => {
                request
                    .validate()
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(alias) = &request.alias {
                    values.insert_len("alias", alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_count("tags", request.tags.len());
                values.insert_lens(
                    "tag",
                    request.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                values.insert_len("filename", request.filename.chars().count());
                values.insert_len("mime", request.mime.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary upload init codec",
            )),
        }
    }
}

struct BinaryUploadCommitRequestCodec;

impl RequestCodec for BinaryUploadCommitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_UPLOAD_COMMIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: BinaryUploadCommitRequest = crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::BinaryUploadCommit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::BinaryUploadCommit(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for binary upload commit codec",
            )),
        }
    }
}

struct ContentUploadStreamInitRequestCodec;

impl RequestCodec for ContentUploadStreamInitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_INIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUploadStreamInitRequest =
            crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UploadStreamInit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UploadStreamInit(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload stream init codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UploadStreamInit(request)) => {
                request
                    .validate()
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                if let Some(alias) = &request.alias {
                    values.insert_len("alias", alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_count("tags", request.tags.len());
                values.insert_lens(
                    "tag",
                    request.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload stream init codec",
            )),
        }
    }
}

struct ContentUploadStreamCommitRequestCodec;

impl RequestCodec for ContentUploadStreamCommitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPLOAD_STREAM_COMMIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUploadStreamCommitRequest =
            crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UploadStreamCommit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UploadStreamCommit(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content upload stream commit codec",
            )),
        }
    }
}

struct ContentUpdateStreamInitRequestCodec;

impl RequestCodec for ContentUpdateStreamInitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_INIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("new_alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
        ])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUpdateStreamInitRequest =
            crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UpdateStreamInit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UpdateStreamInit(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update stream init codec",
            )),
        }
    }

    fn validate(&self, command: &ManagementCommand) -> Result<(), CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UpdateStreamInit(request)) => {
                request
                    .validate()
                    .map_err(|err| CodecError::new(ManagementErrorKind::Validation, err))?;
                let mut values = FieldValues::new();
                values.insert_len("id", request.id.chars().count());
                if let Some(new_alias) = &request.new_alias {
                    values.insert_len("new_alias", new_alias.chars().count());
                }
                if let Some(title) = &request.title {
                    values.insert_len("title", title.chars().count());
                }
                if let Some(tags) = &request.tags {
                    values.insert_count("tags", tags.len());
                    values.insert_lens("tag", tags.iter().map(|tag| tag.chars().count()).collect());
                }
                if let Some(nav_title) = &request.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &request.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(theme) = &request.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update stream init codec",
            )),
        }
    }
}

struct ContentUpdateStreamCommitRequestCodec;

impl RequestCodec for ContentUpdateStreamCommitRequestCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_UPDATE_STREAM_COMMIT)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn decode(&self, payload: &[u8]) -> Result<ManagementCommand, CodecError> {
        let request: ContentUpdateStreamCommitRequest =
            crate::management::codec::decode_payload(payload)?;
        Ok(ManagementCommand::Content(
            ContentCommand::UpdateStreamCommit(request),
        ))
    }

    fn encode(&self, command: &ManagementCommand) -> Result<Vec<u8>, CodecError> {
        match command {
            ManagementCommand::Content(ContentCommand::UpdateStreamCommit(request)) => {
                crate::management::codec::encode_payload(request)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported command for content update stream commit codec",
            )),
        }
    }
}

struct MessageResponseCodec {
    action_id: u32,
}

impl MessageResponseCodec {
    fn new(action_id: u32) -> Self {
        Self { action_id }
    }
}

impl ResponseCodec for MessageResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, self.action_id)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::Message(payload) => crate::management::codec::encode_payload(payload),
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content message codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let message: MessageResponse = crate::management::codec::decode_payload(payload)
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
                "Unsupported response payload for content message codec",
            )),
        }
    }
}

struct ContentListResponseCodec;

impl ResponseCodec for ContentListResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_LIST_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("items", FieldLimit::MaxEntries(MAX_PAGE_SIZE as usize)),
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            (
                "original_filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentList(payload) => {
                crate::management::codec::encode_payload(payload)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content list codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentListResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentList(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentList(payload) => {
                let mut values = FieldValues::new();
                values.insert_count("items", payload.items.len());
                values.insert_lens(
                    "id",
                    payload
                        .items
                        .iter()
                        .map(|item| item.id.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "alias",
                    payload
                        .items
                        .iter()
                        .map(|item| item.alias.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "mime",
                    payload
                        .items
                        .iter()
                        .map(|item| item.mime.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "original_filename",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.original_filename
                                .as_ref()
                                .map(|name| name.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "tags",
                    payload.items.iter().map(|item| item.tags.len()).collect(),
                );
                values.insert_lens(
                    "tag",
                    payload
                        .items
                        .iter()
                        .flat_map(|item| item.tags.iter())
                        .map(|tag| tag.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "nav_title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "nav_parent_id",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_parent_id
                                .as_ref()
                                .map(|id| id.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content list codec",
            )),
        }
    }
}

struct ContentNavIndexResponseCodec;

impl ResponseCodec for ContentNavIndexResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_NAV_INDEX_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("items", FieldLimit::MaxEntries(MAX_NAV_INDEX_ITEMS)),
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentNavIndex(payload) => {
                crate::management::codec::encode_payload(payload)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content nav index codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentNavIndexResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentNavIndex(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentNavIndex(payload) => {
                let mut values = FieldValues::new();
                values.insert_count("items", payload.items.len());
                values.insert_lens(
                    "id",
                    payload
                        .items
                        .iter()
                        .map(|item| item.id.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "alias",
                    payload
                        .items
                        .iter()
                        .map(|item| item.alias.chars().count())
                        .collect(),
                );
                values.insert_lens(
                    "title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "nav_title",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_title
                                .as_ref()
                                .map(|title| title.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                values.insert_lens(
                    "nav_parent_id",
                    payload
                        .items
                        .iter()
                        .map(|item| {
                            item.nav_parent_id
                                .as_ref()
                                .map(|id| id.chars().count())
                                .unwrap_or(0)
                        })
                        .collect(),
                );
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content nav index codec",
            )),
        }
    }
}

struct ContentReadResponseCodec;

impl ResponseCodec for ContentReadResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_READ_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
            ("tag", FieldLimit::MaxChars(MAX_TAG_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
            ("theme", FieldLimit::MaxChars(MAX_THEME_CHARS)),
            ("nav_title", FieldLimit::MaxChars(MAX_TITLE_CHARS)),
            ("nav_parent_id", FieldLimit::MaxChars(MAX_NAV_PARENT_CHARS)),
            (
                "original_filename",
                FieldLimit::MaxChars(MAX_ORIGINAL_FILENAME_CHARS),
            ),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentRead(payload) => {
                crate::management::codec::encode_payload(payload)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content read codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentReadResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentRead(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentRead(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("id", payload.id.chars().count());
                values.insert_len("alias", payload.alias.chars().count());
                if let Some(title) = &payload.title {
                    values.insert_len("title", title.chars().count());
                }
                values.insert_len("mime", payload.mime.chars().count());
                values.insert_count("tags", payload.tags.len());
                values.insert_lens(
                    "tag",
                    payload.tags.iter().map(|tag| tag.chars().count()).collect(),
                );
                if let Some(theme) = &payload.theme {
                    values.insert_len("theme", theme.chars().count());
                }
                if let Some(nav_title) = &payload.nav_title {
                    values.insert_len("nav_title", nav_title.chars().count());
                }
                if let Some(nav_parent_id) = &payload.nav_parent_id {
                    values.insert_len("nav_parent_id", nav_parent_id.chars().count());
                }
                if let Some(name) = &payload.original_filename {
                    values.insert_len("original_filename", name.chars().count());
                }
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content read codec",
            )),
        }
    }
}

struct ContentUploadResponseCodec {
    action_id: u32,
}

impl ContentUploadResponseCodec {
    fn new(action_id: u32) -> Self {
        Self { action_id }
    }
}

impl ResponseCodec for ContentUploadResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, self.action_id)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![
            ("id", FieldLimit::MaxChars(MAX_ID_CHARS)),
            ("alias", FieldLimit::MaxChars(MAX_ALIAS_CHARS)),
            ("mime", FieldLimit::MaxChars(MAX_MIME_CHARS)),
        ])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentUpload(payload) => {
                crate::management::codec::encode_payload(payload)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content upload codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: ContentUploadResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentUpload(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentUpload(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("id", payload.id.chars().count());
                values.insert_len("alias", payload.alias.chars().count());
                values.insert_len("mime", payload.mime.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for content upload codec",
            )),
        }
    }
}

struct BinaryPrevalidateResponseCodec;

impl ResponseCodec for BinaryPrevalidateResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, CONTENT_ACTION_BINARY_PREVALIDATE_OK)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![("message", FieldLimit::MaxChars(1024))])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentBinaryPrevalidate(payload) => {
                crate::management::codec::encode_payload(payload)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for binary prevalidate codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: BinaryPrevalidateResponse =
            crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentBinaryPrevalidate(response))
    }

    fn validate(&self, response: &ManagementResponse) -> Result<(), CodecError> {
        match &response.payload {
            ResponsePayload::ContentBinaryPrevalidate(payload) => {
                let mut values = FieldValues::new();
                values.insert_len("message", payload.message.chars().count());
                validate_field_limits(&self.limits(), &values)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for binary prevalidate codec",
            )),
        }
    }
}

struct UploadStreamInitResponseCodec {
    action_id: u32,
}

impl UploadStreamInitResponseCodec {
    fn new(action_id: u32) -> Self {
        Self { action_id }
    }
}

impl ResponseCodec for UploadStreamInitResponseCodec {
    fn key(&self) -> DomainActionKey {
        DomainActionKey::new(CONTENT_DOMAIN_ID, self.action_id)
    }

    fn limits(&self) -> FieldLimits {
        FieldLimits::new(vec![])
    }

    fn encode(&self, response: &ManagementResponse) -> Result<Vec<u8>, CodecError> {
        match &response.payload {
            ResponsePayload::ContentUploadStreamInit(payload) => {
                crate::management::codec::encode_payload(payload)
            }
            _ => Err(CodecError::new(
                ManagementErrorKind::Codec,
                "Unsupported response payload for upload stream init codec",
            )),
        }
    }

    fn decode(&self, payload: &[u8]) -> Result<ResponsePayload, CodecError> {
        let response: UploadStreamInitResponse = crate::management::codec::decode_payload(payload)?;
        Ok(ResponsePayload::ContentUploadStreamInit(response))
    }
}
