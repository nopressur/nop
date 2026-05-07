// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::{
    BinaryPrevalidateResponse, ContentListResponse, ContentNavIndexResponse, ContentReadResponse,
    ContentUploadResponse, UploadStreamInitResponse,
};
use crate::errors::{ManagementError, ManagementErrorKind};
use crate::roles::{RoleCommand, RoleListResponse, RoleShowResponse};
use crate::search::{SearchCommand, SearchFindResponse};
use crate::system::{ClearLogsResponse, LoggingConfigResponse, SystemCommand};
use crate::tags::{TagCommand, TagListResponse, TagShowResponse};
use crate::users::{
    PasswordSaltResponse, PasswordValidateResponse, UserCommand, UserListResponse,
    UserRolesListResponse, UserShowResponse,
};
use crate::wire::{WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use serde::{Deserialize, Serialize};

const MAX_MESSAGE_CHARS: usize = 1024;

#[derive(Debug, Clone)]
pub enum ManagementCommand {
    System(SystemCommand),
    Users(UserCommand),
    Tags(TagCommand),
    Roles(RoleCommand),
    Content(crate::content::ContentCommand),
    Search(SearchCommand),
}

impl ManagementCommand {
    pub fn domain_id(&self) -> u32 {
        match self {
            ManagementCommand::System(_) => crate::system::SYSTEM_DOMAIN_ID,
            ManagementCommand::Users(_) => crate::users::USERS_DOMAIN_ID,
            ManagementCommand::Tags(_) => crate::tags::TAGS_DOMAIN_ID,
            ManagementCommand::Roles(_) => crate::roles::ROLES_DOMAIN_ID,
            ManagementCommand::Content(_) => crate::content::CONTENT_DOMAIN_ID,
            ManagementCommand::Search(_) => crate::search::SEARCH_DOMAIN_ID,
        }
    }

    pub fn action_id(&self) -> u32 {
        match self {
            ManagementCommand::System(command) => command.action_id(),
            ManagementCommand::Users(command) => command.action_id(),
            ManagementCommand::Tags(command) => command.action_id(),
            ManagementCommand::Roles(command) => command.action_id(),
            ManagementCommand::Content(command) => command.action_id(),
            ManagementCommand::Search(command) => command.action_id(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagementRequest {
    pub workflow_id: u32,
    pub connection_id: u32,
    pub command: ManagementCommand,
    pub actor_email: Option<String>,
}

impl ManagementRequest {
    pub fn domain_id(&self) -> u32 {
        self.command.domain_id()
    }

    pub fn action_id(&self) -> u32 {
        self.command.action_id()
    }
}

#[derive(Debug, Clone)]
pub struct ManagementResponse {
    pub domain_id: u32,
    pub action_id: u32,
    pub workflow_id: u32,
    pub payload: ResponsePayload,
}

impl ManagementResponse {
    pub fn message(
        domain_id: u32,
        action_id: u32,
        workflow_id: u32,
        message: impl Into<String>,
    ) -> Result<Self, ManagementError> {
        let payload = ResponsePayload::Message(MessageResponse::new(message)?);
        Ok(Self {
            domain_id,
            action_id,
            workflow_id,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub enum ResponsePayload {
    Message(MessageResponse),
    SystemLoggingConfig(LoggingConfigResponse),
    SystemLogCleanup(ClearLogsResponse),
    UserList(UserListResponse),
    UserShow(UserShowResponse),
    UserRolesList(UserRolesListResponse),
    UserPasswordSalt(PasswordSaltResponse),
    UserPasswordValidate(PasswordValidateResponse),
    RoleList(RoleListResponse),
    RoleShow(RoleShowResponse),
    TagList(TagListResponse),
    TagShow(TagShowResponse),
    ContentList(ContentListResponse),
    ContentNavIndex(ContentNavIndexResponse),
    ContentRead(ContentReadResponse),
    ContentUpload(ContentUploadResponse),
    ContentBinaryPrevalidate(BinaryPrevalidateResponse),
    ContentUploadStreamInit(UploadStreamInitResponse),
    SearchFind(SearchFindResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Result<Self, ManagementError> {
        let message = message.into();
        let message_len = message.chars().count();
        if message_len > MAX_MESSAGE_CHARS {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                format!(
                    "Message exceeds {} characters (got {})",
                    MAX_MESSAGE_CHARS, message_len
                ),
            ));
        }
        Ok(Self { message })
    }
}

impl WireEncode for MessageResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.message)
    }
}

impl WireDecode for MessageResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let message = reader.read_string()?;
        Ok(Self { message })
    }
}
