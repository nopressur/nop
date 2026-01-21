// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::flat_storage::{read_sidecar, sidecar_path, write_sidecar_atomic};
use crate::management::codec::{FieldLimit, FieldLimits, FieldValues};
use crate::management::core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse,
};
use crate::management::registry::{DomainActionKey, ManagementHandler, ManagementRegistry};
use crate::management::roles::ensure_roles_exist;
use crate::management::yaml_store;
use crate::management::{
    OptionMap, WireDecode, WireEncode, WireError, WireReader, WireResult, WireWriter,
};
use crate::public::page_meta_cache::PageMetaCache;
use crate::security;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

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

const TAGS_FILE_NAME: &str = "tags.yaml";
const MAX_TAG_ID_CHARS: usize = 128;
const MAX_TAG_NAME_CHARS: usize = 256;
const MAX_ROLE_COUNT: usize = crate::roles::MAX_ROLE_COUNT;
const MAX_ROLE_CHARS: usize = crate::roles::MAX_ROLE_CHARS;
const MAX_TAG_COUNT: usize = 10000;
const MAX_ACCESS_RULE_CHARS: usize = 9;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessRule {
    Union,
    Intersect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRecord {
    pub name: String,
    #[serde(default)]
    pub roles: Vec<String>,
    pub access_rule: Option<AccessRule>,
}

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

impl WireEncode for AccessRule {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let value = match self {
            AccessRule::Union => 0,
            AccessRule::Intersect => 1,
        };
        writer.write_u32(value);
        Ok(())
    }
}

impl WireDecode for AccessRule {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        match reader.read_u32()? {
            0 => Ok(AccessRule::Union),
            1 => Ok(AccessRule::Intersect),
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
            access_rule.encode(writer)?;
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
            Some(AccessRule::decode(reader)?)
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
            value.encode(writer)?;
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
            Some(AccessRule::decode(reader)?)
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
        writer.write_vec(&self.tags, |writer, tag| tag.encode(writer))
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
            access_rule.encode(writer)?;
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
            Some(AccessRule::decode(reader)?)
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

#[derive(Debug)]
struct TagValidationError {
    message: String,
}

impl TagValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TagValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug)]
pub(crate) struct TagStoreError {
    message: String,
}

impl TagStoreError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TagStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TagStoreError {}

pub(crate) struct TagStore {
    tags_file: PathBuf,
    tags: RwLock<BTreeMap<String, TagRecord>>,
}

impl TagStore {
    pub fn new(state_sys_dir: PathBuf) -> Result<Self, TagStoreError> {
        let tags_file = security::validate_new_file_path(TAGS_FILE_NAME, &state_sys_dir)
            .map_err(|err| TagStoreError::new(format!("Invalid tag storage path: {}", err)))?;
        let tags = Self::load_from_disk(&tags_file)?;
        Ok(Self {
            tags_file,
            tags: RwLock::new(tags),
        })
    }

    pub fn snapshot(&self) -> Result<BTreeMap<String, TagRecord>, TagStoreError> {
        self.tags
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| TagStoreError::new("Tag store lock poisoned"))
    }

    pub fn persist(&self, tags: BTreeMap<String, TagRecord>) -> Result<(), TagStoreError> {
        Self::write_tags_file(&self.tags_file, &tags)?;
        let mut guard = self
            .tags
            .write()
            .map_err(|_| TagStoreError::new("Tag store lock poisoned"))?;
        *guard = tags;
        Ok(())
    }

    fn load_from_disk(tags_file: &Path) -> Result<BTreeMap<String, TagRecord>, TagStoreError> {
        let raw: Option<BTreeMap<String, TagRecord>> =
            yaml_store::read_yaml_file(tags_file, "tags")
                .map_err(|err| TagStoreError::new(err.to_string()))?;
        let raw = match raw {
            Some(raw) => raw,
            None => return Ok(BTreeMap::new()),
        };
        let normalized = normalize_tag_map(raw)?;
        Ok(normalized)
    }

    fn write_tags_file(
        tags_file: &Path,
        tags: &BTreeMap<String, TagRecord>,
    ) -> Result<(), TagStoreError> {
        yaml_store::write_yaml_file(tags_file, "tags", tags)
            .map_err(|err| TagStoreError::new(err.to_string()))
    }
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), crate::management::RegistryError> {
    registry.register_domain(crate::management::registry::DomainDescriptor {
        name: "tags",
        id: TAGS_DOMAIN_ID,
        actions: vec![
            crate::management::registry::ActionDescriptor {
                name: "add",
                id: TAG_ACTION_ADD,
            },
            crate::management::registry::ActionDescriptor {
                name: "change",
                id: TAG_ACTION_CHANGE,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete",
                id: TAG_ACTION_DELETE,
            },
            crate::management::registry::ActionDescriptor {
                name: "list",
                id: TAG_ACTION_LIST,
            },
            crate::management::registry::ActionDescriptor {
                name: "show",
                id: TAG_ACTION_SHOW,
            },
            crate::management::registry::ActionDescriptor {
                name: "add_ok",
                id: TAG_ACTION_ADD_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "add_err",
                id: TAG_ACTION_ADD_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "change_ok",
                id: TAG_ACTION_CHANGE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "change_err",
                id: TAG_ACTION_CHANGE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_ok",
                id: TAG_ACTION_DELETE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_err",
                id: TAG_ACTION_DELETE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_ok",
                id: TAG_ACTION_LIST_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_err",
                id: TAG_ACTION_LIST_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "show_ok",
                id: TAG_ACTION_SHOW_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "show_err",
                id: TAG_ACTION_SHOW_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_tags_request(request, context).await })
    });
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_CHANGE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(TAGS_DOMAIN_ID, TAG_ACTION_SHOW),
        handler,
    )?;

    register_request_codecs!(
        registry,
        [
            TagAddRequestCodec,
            TagChangeRequestCodec,
            TagDeleteRequestCodec,
            TagListRequestCodec,
            TagShowRequestCodec
        ]
    );

    register_response_codecs!(
        registry,
        [
            MessageResponseCodec::new(TAG_ACTION_ADD_OK),
            MessageResponseCodec::new(TAG_ACTION_ADD_ERR),
            MessageResponseCodec::new(TAG_ACTION_CHANGE_OK),
            MessageResponseCodec::new(TAG_ACTION_CHANGE_ERR),
            MessageResponseCodec::new(TAG_ACTION_DELETE_OK),
            MessageResponseCodec::new(TAG_ACTION_DELETE_ERR),
            MessageResponseCodec::new(TAG_ACTION_LIST_ERR),
            MessageResponseCodec::new(TAG_ACTION_SHOW_ERR),
            TagListResponseCodec,
            TagShowResponseCodec
        ]
    );

    Ok(())
}

async fn handle_tags_request(
    request: ManagementRequest,
    context: Arc<ManagementContext>,
) -> crate::management::errors::DomainResult<ManagementResponse> {
    let response = match request.command {
        ManagementCommand::Tags(TagCommand::Add(payload)) => {
            handle_add(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Tags(TagCommand::Change(payload)) => {
            handle_change(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Tags(TagCommand::Delete(payload)) => {
            handle_delete(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Tags(TagCommand::List(payload)) => {
            handle_list(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Tags(TagCommand::Show(payload)) => {
            handle_show(payload, request.workflow_id, &context).await
        }
        _ => response_err(
            TAG_ACTION_CHANGE_ERR,
            request.workflow_id,
            "Invalid tag command",
        ),
    };

    Ok(response)
}

async fn handle_add(
    payload: TagAddRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err.to_string());
    }
    let normalized_roles = match normalize_roles(&payload.roles) {
        Ok(roles) => roles,
        Err(err) => return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    if let Err(err) = ensure_roles_exist(context, &normalized_roles) {
        return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err);
    }
    let mut tags = match context.tag_store.snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    if tags.contains_key(&payload.id) {
        return response_err(TAG_ACTION_ADD_ERR, workflow_id, "Tag already exists");
    }
    tags.insert(
        payload.id.clone(),
        TagRecord {
            name: payload.name,
            roles: normalized_roles,
            access_rule: payload.access_rule,
        },
    );
    if let Err(err) = context.tag_store.persist(tags) {
        return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err.to_string());
    }
    response_ok(TAG_ACTION_ADD_OK, workflow_id, "Tag added successfully")
}

async fn handle_change(
    payload: TagChangeRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
    }
    let rename_to = payload
        .new_id
        .as_ref()
        .filter(|new_id| *new_id != &payload.id)
        .cloned();
    let mut tags = match context.tag_store.snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
    };
    if let Some(new_id) = &rename_to
        && tags.contains_key(new_id)
    {
        return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, "Tag id already exists");
    }
    let mut record = match tags.get(&payload.id).cloned() {
        Some(record) => record,
        None => {
            return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, "Tag not found");
        }
    };
    if let Some(name) = payload.name {
        record.name = name;
    }
    if let Some(roles) = payload.roles {
        match normalize_roles(&roles) {
            Ok(normalized) => {
                if let Err(err) = ensure_roles_exist(context, &normalized) {
                    return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err);
                }
                record.roles = normalized;
            }
            Err(err) => return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
        }
    }
    if payload.clear_access {
        record.access_rule = None;
    }
    if let Some(rule) = payload.access_rule {
        record.access_rule = Some(rule);
    }
    if let Some(new_id) = &rename_to {
        if let Err(err) = rename_tag_in_content(context, &payload.id, new_id).await {
            return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err);
        }
        tags.remove(&payload.id);
        tags.insert(new_id.clone(), record);
    } else {
        tags.insert(payload.id, record);
    }
    if let Err(err) = context.tag_store.persist(tags) {
        return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
    }
    if rename_to.is_some() {
        invalidate_cache(context).await;
    }
    response_ok(
        TAG_ACTION_CHANGE_OK,
        workflow_id,
        "Tag updated successfully",
    )
}

async fn handle_delete(
    payload: TagDeleteRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err.to_string());
    }
    let mut tags = match context.tag_store.snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err.to_string()),
    };
    if !tags.contains_key(&payload.id) {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, "Tag not found");
    }
    if let Err(err) = remove_tag_from_content(context, &payload.id).await {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err);
    }
    tags.remove(&payload.id);
    if let Err(err) = context.tag_store.persist(tags) {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err.to_string());
    }
    invalidate_cache(context).await;
    response_ok(
        TAG_ACTION_DELETE_OK,
        workflow_id,
        "Tag deleted successfully",
    )
}

async fn handle_list(
    _payload: TagListRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let tags = match context.tag_store.snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_LIST_ERR, workflow_id, &err.to_string()),
    };
    let summaries = tags
        .iter()
        .map(|(id, record)| TagSummary {
            id: id.clone(),
            name: record.name.clone(),
        })
        .collect();
    response_tag_list(workflow_id, summaries)
}

async fn handle_show(
    payload: TagShowRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(TAG_ACTION_SHOW_ERR, workflow_id, &err.to_string());
    }
    let tags = match context.tag_store.snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
    };
    let record = match tags.get(&payload.id) {
        Some(record) => record,
        None => return response_err(TAG_ACTION_SHOW_ERR, workflow_id, "Tag not found"),
    };
    response_tag_show(
        workflow_id,
        TagShowResponse {
            id: payload.id,
            name: record.name.clone(),
            roles: record.roles.clone(),
            access_rule: record.access_rule.clone(),
        },
    )
}

define_domain_responses!(TAGS_DOMAIN_ID);

fn response_tag_list(workflow_id: u32, tags: Vec<TagSummary>) -> ManagementResponse {
    ManagementResponse {
        domain_id: TAGS_DOMAIN_ID,
        action_id: TAG_ACTION_LIST_OK,
        workflow_id,
        payload: crate::management::ResponsePayload::TagList(TagListResponse { tags }),
    }
}

fn response_tag_show(workflow_id: u32, payload: TagShowResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: TAGS_DOMAIN_ID,
        action_id: TAG_ACTION_SHOW_OK,
        workflow_id,
        payload: crate::management::ResponsePayload::TagShow(payload),
    }
}

impl TagAddRequest {
    fn validate(&self) -> Result<(), TagValidationError> {
        validate_tag_id(&self.id)?;
        validate_tag_name(&self.name)?;
        validate_roles(&self.roles)?;
        Ok(())
    }
}

impl TagChangeRequest {
    fn validate(&self) -> Result<(), TagValidationError> {
        validate_tag_id(&self.id)?;
        if self.name.is_none()
            && self.roles.is_none()
            && self.access_rule.is_none()
            && !self.clear_access
            && self.new_id.is_none()
        {
            return Err(TagValidationError::new(
                "Tag change requires --new-id, --name, --roles, --access, or --clear-access",
            ));
        }
        if self.clear_access && self.access_rule.is_some() {
            return Err(TagValidationError::new(
                "--clear-access cannot be used with --access",
            ));
        }
        if let Some(new_id) = &self.new_id {
            validate_tag_id(new_id)?;
        }
        if let Some(name) = &self.name {
            validate_tag_name(name)?;
        }
        if let Some(roles) = &self.roles {
            validate_roles(roles)?;
        }
        Ok(())
    }
}

impl TagDeleteRequest {
    fn validate(&self) -> Result<(), TagValidationError> {
        validate_tag_id(&self.id)
    }
}

impl TagListRequest {
    fn validate(&self) -> Result<(), TagValidationError> {
        Ok(())
    }
}

impl TagShowRequest {
    fn validate(&self) -> Result<(), TagValidationError> {
        validate_tag_id(&self.id)
    }
}

async fn remove_tag_from_content(context: &ManagementContext, tag_id: &str) -> Result<(), String> {
    let cache = get_cache(context).await?;
    let objects = cache.list_objects();
    for object in objects {
        if !object.tags.iter().any(|tag| tag == tag_id) {
            continue;
        }
        let sidecar_path = sidecar_path(
            &context.runtime_paths.content_dir,
            object.key.id,
            object.key.version,
        );
        let mut sidecar = read_sidecar(&sidecar_path)
            .map_err(|err| format!("Failed to read sidecar {}: {}", sidecar_path.display(), err))?;
        let before = sidecar.tags.len();
        sidecar.tags.retain(|tag| tag != tag_id);
        if sidecar.tags.len() == before {
            continue;
        }
        write_sidecar_atomic(&sidecar_path, &sidecar).map_err(|err| {
            format!(
                "Failed to update sidecar {}: {}",
                sidecar_path.display(),
                err
            )
        })?;
    }

    Ok(())
}

async fn rename_tag_in_content(
    context: &ManagementContext,
    tag_id: &str,
    new_id: &str,
) -> Result<(), String> {
    let cache = get_cache(context).await?;
    let objects = cache.list_objects();
    for object in objects {
        if !object.tags.iter().any(|tag| tag == tag_id) {
            continue;
        }
        let sidecar_path = sidecar_path(
            &context.runtime_paths.content_dir,
            object.key.id,
            object.key.version,
        );
        let mut sidecar = read_sidecar(&sidecar_path)
            .map_err(|err| format!("Failed to read sidecar {}: {}", sidecar_path.display(), err))?;
        let mut updated = Vec::with_capacity(sidecar.tags.len());
        let mut seen = std::collections::HashSet::new();
        let mut changed = false;
        for tag in &sidecar.tags {
            let value = if tag == tag_id {
                changed = true;
                new_id
            } else {
                tag.as_str()
            };
            let value = value.to_string();
            if seen.insert(value.clone()) {
                updated.push(value);
            }
        }
        if !changed {
            continue;
        }
        sidecar.tags = updated;
        write_sidecar_atomic(&sidecar_path, &sidecar).map_err(|err| {
            format!(
                "Failed to update sidecar {}: {}",
                sidecar_path.display(),
                err
            )
        })?;
    }

    Ok(())
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

fn validate_tag_id(id: &str) -> Result<(), TagValidationError> {
    if id.is_empty() {
        return Err(TagValidationError::new("Tag id is required"));
    }
    if id.chars().count() > MAX_TAG_ID_CHARS {
        return Err(TagValidationError::new(format!(
            "Tag id must be at most {} characters",
            MAX_TAG_ID_CHARS
        )));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '/')
    {
        return Err(TagValidationError::new(
            "Tag id contains invalid characters",
        ));
    }
    Ok(())
}

fn validate_tag_name(name: &str) -> Result<(), TagValidationError> {
    if name.is_empty() {
        return Err(TagValidationError::new("Tag name is required"));
    }
    let len = name.chars().count();
    if len > MAX_TAG_NAME_CHARS {
        return Err(TagValidationError::new(format!(
            "Tag name must be at most {} characters",
            MAX_TAG_NAME_CHARS
        )));
    }
    Ok(())
}

fn validate_roles(roles: &[String]) -> Result<(), TagValidationError> {
    normalize_roles(roles).map(|_| ())
}

fn normalize_roles(roles: &[String]) -> Result<Vec<String>, TagValidationError> {
    crate::roles::normalize_roles(roles).map_err(|err| TagValidationError::new(err.to_string()))
}

fn normalize_tag_map(
    tags: BTreeMap<String, TagRecord>,
) -> Result<BTreeMap<String, TagRecord>, TagStoreError> {
    if tags.len() > MAX_TAG_COUNT {
        return Err(TagStoreError::new(format!(
            "Tags must be at most {} entries",
            MAX_TAG_COUNT
        )));
    }
    let mut normalized = BTreeMap::new();
    for (id, record) in tags {
        validate_tag_id(&id).map_err(|err| TagStoreError::new(err.to_string()))?;
        validate_tag_name(&record.name).map_err(|err| TagStoreError::new(err.to_string()))?;
        let roles =
            normalize_roles(&record.roles).map_err(|err| TagStoreError::new(err.to_string()))?;
        normalized.insert(
            id,
            TagRecord {
                name: record.name,
                roles,
                access_rule: record.access_rule,
            },
        );
    }
    Ok(normalized)
}

fn tag_add_field_values(request: &TagAddRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("id", request.id.chars().count());
    values.insert_len("name", request.name.chars().count());
    values.insert_count("roles", request.roles.len());
    values.insert_lens(
        "role",
        request
            .roles
            .iter()
            .map(|role| role.chars().count())
            .collect(),
    );
    if let Some(rule) = &request.access_rule {
        values.insert_len("access_rule", access_rule_len(rule));
    }
    values
}

fn tag_change_field_values(request: &TagChangeRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("id", request.id.chars().count());
    if let Some(new_id) = &request.new_id {
        values.insert_len("new_id", new_id.chars().count());
    }
    if let Some(name) = &request.name {
        values.insert_len("name", name.chars().count());
    }
    if let Some(roles) = &request.roles {
        values.insert_count("roles", roles.len());
        values.insert_lens(
            "role",
            roles.iter().map(|role| role.chars().count()).collect(),
        );
    }
    if let Some(rule) = &request.access_rule {
        values.insert_len("access_rule", access_rule_len(rule));
    }
    values
}

fn tag_id_field_values(id: &str) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("id", id.chars().count());
    values
}

fn tag_list_response_values(response: &TagListResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_count("tags", response.tags.len());
    values.insert_lens(
        "id",
        response
            .tags
            .iter()
            .map(|tag| tag.id.chars().count())
            .collect(),
    );
    values.insert_lens(
        "name",
        response
            .tags
            .iter()
            .map(|tag| tag.name.chars().count())
            .collect(),
    );
    values
}

fn tag_show_response_values(response: &TagShowResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("id", response.id.chars().count());
    values.insert_len("name", response.name.chars().count());
    values.insert_count("roles", response.roles.len());
    values.insert_lens(
        "role",
        response
            .roles
            .iter()
            .map(|role| role.chars().count())
            .collect(),
    );
    if let Some(rule) = &response.access_rule {
        values.insert_len("access_rule", access_rule_len(rule));
    }
    values
}

fn access_rule_len(rule: &AccessRule) -> usize {
    match rule {
        AccessRule::Union => "union".chars().count(),
        AccessRule::Intersect => "intersect".chars().count(),
    }
}

define_request_codec!(
    TagAddRequestCodec,
    domain = Tags,
    command = TagCommand,
    variant = Add,
    domain_id = TAGS_DOMAIN_ID,
    action_id = TAG_ACTION_ADD,
    request = TagAddRequest,
    limits = FieldLimits::new(vec![
        ("id", FieldLimit::MaxChars(MAX_TAG_ID_CHARS)),
        ("new_id", FieldLimit::MaxChars(MAX_TAG_ID_CHARS)),
        ("name", FieldLimit::MaxChars(MAX_TAG_NAME_CHARS)),
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
        ("access_rule", FieldLimit::MaxChars(MAX_ACCESS_RULE_CHARS)),
    ]),
    values = |request| tag_add_field_values(request),
    error = "Unsupported command for tag add codec",
);

define_request_codec!(
    TagChangeRequestCodec,
    domain = Tags,
    command = TagCommand,
    variant = Change,
    domain_id = TAGS_DOMAIN_ID,
    action_id = TAG_ACTION_CHANGE,
    request = TagChangeRequest,
    limits = FieldLimits::new(vec![
        ("id", FieldLimit::MaxChars(MAX_TAG_ID_CHARS)),
        ("name", FieldLimit::MaxChars(MAX_TAG_NAME_CHARS)),
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
        ("access_rule", FieldLimit::MaxChars(MAX_ACCESS_RULE_CHARS)),
    ]),
    values = |request| tag_change_field_values(request),
    error = "Unsupported command for tag change codec",
);

define_request_codec!(
    TagDeleteRequestCodec,
    domain = Tags,
    command = TagCommand,
    variant = Delete,
    domain_id = TAGS_DOMAIN_ID,
    action_id = TAG_ACTION_DELETE,
    request = TagDeleteRequest,
    limits = FieldLimits::new(vec![("id", FieldLimit::MaxChars(MAX_TAG_ID_CHARS))]),
    values = |request| tag_id_field_values(&request.id),
    error = "Unsupported command for tag delete codec",
);

define_request_codec!(
    TagListRequestCodec,
    domain = Tags,
    command = TagCommand,
    variant = List,
    domain_id = TAGS_DOMAIN_ID,
    action_id = TAG_ACTION_LIST,
    request = TagListRequest,
    limits = FieldLimits::new(Vec::new()),
    values = |_request| FieldValues::new(),
    error = "Unsupported command for tag list codec",
);

define_request_codec!(
    TagShowRequestCodec,
    domain = Tags,
    command = TagCommand,
    variant = Show,
    domain_id = TAGS_DOMAIN_ID,
    action_id = TAG_ACTION_SHOW,
    request = TagShowRequest,
    limits = FieldLimits::new(vec![("id", FieldLimit::MaxChars(MAX_TAG_ID_CHARS))]),
    values = |request| tag_id_field_values(&request.id),
    error = "Unsupported command for tag show codec",
);

define_message_response_codec!(
    MessageResponseCodec,
    domain_id = TAGS_DOMAIN_ID,
    error = "Unsupported response payload for tag message codec",
);

define_response_codec!(
    TagListResponseCodec,
    domain_id = TAGS_DOMAIN_ID,
    action_id = TAG_ACTION_LIST_OK,
    payload = TagList,
    response = TagListResponse,
    limits = FieldLimits::new(vec![
        ("tags", FieldLimit::MaxEntries(MAX_TAG_COUNT)),
        ("id", FieldLimit::MaxChars(MAX_TAG_ID_CHARS)),
        ("name", FieldLimit::MaxChars(MAX_TAG_NAME_CHARS)),
    ]),
    values = |payload| tag_list_response_values(payload),
    error = "Unsupported response payload for tag list codec",
);

define_response_codec!(
    TagShowResponseCodec,
    domain_id = TAGS_DOMAIN_ID,
    action_id = TAG_ACTION_SHOW_OK,
    payload = TagShow,
    response = TagShowResponse,
    limits = FieldLimits::new(vec![
        ("id", FieldLimit::MaxChars(MAX_TAG_ID_CHARS)),
        ("name", FieldLimit::MaxChars(MAX_TAG_NAME_CHARS)),
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
        ("access_rule", FieldLimit::MaxChars(MAX_ACCESS_RULE_CHARS)),
    ]),
    values = |payload| tag_show_response_values(payload),
    error = "Unsupported response payload for tag show codec",
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, AuthMethod, Config, JwtConfig, LocalAuthConfig, LoggingConfig,
        LoggingRotationConfig, NavigationConfig, PasswordHashingConfig, RenderingConfig,
        SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig, UploadConfig, UsersConfig,
    };
    use crate::content::flat_storage::{
        ContentId, ContentSidecar, ContentVersion, blob_path, read_sidecar, sidecar_path,
        write_sidecar_atomic,
    };
    use crate::management::ResponsePayload;
    use crate::management::codec::RequestCodec;
    use crate::management::{ManagementBus, ManagementContext};
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn build_test_context(root: &Path) -> ManagementContext {
        let config = Config {
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
        };
        let content = serde_yaml::to_string(&config).expect("serialize config");
        std::fs::write(root.join("config.yaml"), content).expect("write config");
        std::fs::write(root.join("users.yaml"), "{}\n").expect("write users");
        std::fs::create_dir_all(root.join("state").join("sys")).expect("state/sys");
        std::fs::write(
            root.join("state").join("sys").join("roles.yaml"),
            "- admin\n- editor\n",
        )
        .expect("write roles");

        let validated = Config::load_and_validate(root).expect("validate config");
        let runtime_paths =
            crate::runtime_paths::RuntimePaths::from_root(root, &validated).expect("runtime paths");
        ManagementContext::from_components(
            runtime_paths.root.clone(),
            Arc::new(validated),
            runtime_paths,
        )
        .expect("context")
    }

    #[test]
    fn tag_id_charset_enforced() {
        let request = TagAddRequest {
            id: "Invalid Tag".to_string(),
            name: "Name".to_string(),
            roles: vec![],
            access_rule: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn tag_name_limit_enforced() {
        let request = TagAddRequest {
            id: "valid".to_string(),
            name: "a".repeat(MAX_TAG_NAME_CHARS + 1),
            roles: vec![],
            access_rule: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn tag_roles_limit_enforced() {
        let roles = vec!["role".to_string(); MAX_ROLE_COUNT + 1];
        let request = TagAddRequest {
            id: "valid".to_string(),
            name: "Name".to_string(),
            roles,
            access_rule: None,
        };
        assert!(request.validate().is_err());
    }

    #[tokio::test]
    async fn tag_add_and_list_roundtrip() {
        let fixture = TestFixtureRoot::new_unique("tags-add-list").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::management::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let add = ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
            id: "news/alerts".to_string(),
            name: "News Alerts".to_string(),
            roles: vec!["editor".to_string()],
            access_rule: Some(AccessRule::Union),
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 1, add)
            .await
            .expect("add response");
        assert_eq!(response.domain_id, TAGS_DOMAIN_ID);
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let list = ManagementCommand::Tags(TagCommand::List(TagListRequest {}));
        let response = bus
            .send(crate::management::next_connection_id(), 2, list)
            .await
            .expect("list response");
        match response.payload {
            ResponsePayload::TagList(payload) => {
                assert_eq!(payload.tags.len(), 1);
                assert_eq!(payload.tags[0].id, "news/alerts");
            }
            _ => panic!("Expected tag list response"),
        }
    }

    #[tokio::test]
    async fn tag_delete_removes_content_tags() {
        let fixture = TestFixtureRoot::new_unique("tags-delete-cascade").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::management::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let content_id = ContentId(42);
        let version = ContentVersion(0);
        let content_dir = fixture.content_dir();
        let blob = blob_path(&content_dir, content_id, version);
        std::fs::create_dir_all(blob.parent().expect("blob parent")).expect("content shard");
        std::fs::write(&blob, "# Tagged content\n").expect("write blob");

        let sidecar_path = sidecar_path(&content_dir, content_id, version);
        let sidecar = ContentSidecar {
            alias: "docs/tagged".to_string(),
            title: Some("Tagged".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec!["release/alpha".to_string()],
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: Some("tagged.md".to_string()),
            theme: None,
        };
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");

        let add = ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
            id: "release/alpha".to_string(),
            name: "Release Alpha".to_string(),
            roles: vec![],
            access_rule: None,
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 1, add)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let delete = ManagementCommand::Tags(TagCommand::Delete(TagDeleteRequest {
            id: "release/alpha".to_string(),
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 2, delete)
            .await
            .expect("delete response");
        assert_eq!(response.action_id, TAG_ACTION_DELETE_OK);

        let updated = read_sidecar(&sidecar_path).expect("read sidecar");
        assert!(updated.tags.is_empty());
    }

    #[tokio::test]
    async fn tag_rename_updates_content_tags() {
        let fixture = TestFixtureRoot::new_unique("tags-rename").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::management::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let content_id = ContentId(7);
        let version = ContentVersion(0);
        let content_dir = fixture.content_dir();
        let blob = blob_path(&content_dir, content_id, version);
        std::fs::create_dir_all(blob.parent().expect("blob parent")).expect("content shard");
        std::fs::write(&blob, "# Tagged content\n").expect("write blob");

        let sidecar_path = sidecar_path(&content_dir, content_id, version);
        let sidecar = ContentSidecar {
            alias: "docs/rename".to_string(),
            title: Some("Rename".to_string()),
            mime: "text/markdown".to_string(),
            tags: vec!["release/alpha".to_string()],
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: Some("rename.md".to_string()),
            theme: None,
        };
        write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");

        let add = ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
            id: "release/alpha".to_string(),
            name: "Release Alpha".to_string(),
            roles: vec![],
            access_rule: None,
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 1, add)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let change = ManagementCommand::Tags(TagCommand::Change(TagChangeRequest {
            id: "release/alpha".to_string(),
            new_id: Some("release/beta".to_string()),
            name: None,
            roles: None,
            access_rule: None,
            clear_access: false,
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 2, change)
            .await
            .expect("change response");
        assert_eq!(response.action_id, TAG_ACTION_CHANGE_OK);

        let updated = read_sidecar(&sidecar_path).expect("read sidecar");
        assert_eq!(updated.tags, vec!["release/beta".to_string()]);

        let tags_content =
            std::fs::read_to_string(fixture.state_dir().join("sys").join(TAGS_FILE_NAME))
                .expect("read tags");
        let tags: BTreeMap<String, TagRecord> =
            serde_yaml::from_str(&tags_content).expect("parse tags");
        assert!(tags.contains_key("release/beta"));
        assert!(!tags.contains_key("release/alpha"));
    }

    #[tokio::test]
    async fn tag_rename_rejects_collision() {
        let fixture = TestFixtureRoot::new_unique("tags-rename-collision").unwrap();
        fixture.init_runtime_layout().unwrap();
        let context = build_test_context(fixture.path());
        let registry = crate::management::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let add_a = ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
            id: "tag-a".to_string(),
            name: "Tag A".to_string(),
            roles: vec![],
            access_rule: None,
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 1, add_a)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let add_b = ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
            id: "tag-b".to_string(),
            name: "Tag B".to_string(),
            roles: vec![],
            access_rule: None,
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 2, add_b)
            .await
            .expect("add response");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

        let change = ManagementCommand::Tags(TagCommand::Change(TagChangeRequest {
            id: "tag-a".to_string(),
            new_id: Some("tag-b".to_string()),
            name: None,
            roles: None,
            access_rule: None,
            clear_access: false,
        }));
        let response = bus
            .send(crate::management::next_connection_id(), 3, change)
            .await
            .expect("change response");
        assert_eq!(response.action_id, TAG_ACTION_CHANGE_ERR);
    }

    #[test]
    fn tag_store_persists_to_disk() {
        let fixture = TestFixtureRoot::new_unique("tags-store").unwrap();
        fixture.init_runtime_layout().unwrap();
        let state_sys_dir = fixture.state_dir().join("sys");
        let store = TagStore::new(state_sys_dir.clone()).expect("tag store");

        let mut tags = BTreeMap::new();
        tags.insert(
            "release/notes".to_string(),
            TagRecord {
                name: "Release Notes".to_string(),
                roles: vec!["editor".to_string()],
                access_rule: Some(AccessRule::Union),
            },
        );
        store.persist(tags).expect("persist tags");

        let content =
            std::fs::read_to_string(state_sys_dir.join(TAGS_FILE_NAME)).expect("read tags file");
        assert!(content.contains("release/notes"));
        assert!(content.contains("Release Notes"));
    }

    #[test]
    fn tag_codec_limits_enforced() {
        let codec = TagAddRequestCodec;
        let request = TagAddRequest {
            id: "a".repeat(MAX_TAG_ID_CHARS + 1),
            name: "Name".to_string(),
            roles: vec![],
            access_rule: None,
        };
        let command = ManagementCommand::Tags(TagCommand::Add(request));
        let err = codec.validate(&command).unwrap_err();
        assert!(err.to_string().contains("Tag id"));
    }
}
