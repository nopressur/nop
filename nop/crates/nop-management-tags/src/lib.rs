// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop_management_contract::core::{
    ManagementCommand, ManagementRequest, ManagementResponse, ResponsePayload,
};
use nop_management_contract::{
    FieldLimit, FieldLimits, FieldValues, define_domain_responses, define_message_response_codec,
    define_request_codec, define_response_codec,
};
use nop_management_errors::DomainResult;
use nop_management_workflows::capabilities::{ConfigAccess, PageCacheAccess, RoleStoreAccess};
use nop_management_workflows::tags as tag_workflows;
use nop_management_yaml as yaml_store;
use nop_roles::{AccessRule, MAX_ROLE_CHARS, MAX_ROLE_COUNT};
use nop_security_paths::validate_new_file_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub use nop_management_contract::tags::{
    TAG_ACTION_ADD, TAG_ACTION_ADD_ERR, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE,
    TAG_ACTION_CHANGE_ERR, TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE, TAG_ACTION_DELETE_ERR,
    TAG_ACTION_DELETE_OK, TAG_ACTION_LIST, TAG_ACTION_LIST_ERR, TAG_ACTION_LIST_OK,
    TAG_ACTION_SHOW, TAG_ACTION_SHOW_ERR, TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID, TagAddRequest,
    TagChangeRequest, TagCommand, TagDeleteRequest, TagListRequest, TagListResponse,
    TagShowRequest, TagShowResponse, TagSummary,
};

const TAGS_FILE_NAME: &str = "tags.yaml";
const MAX_TAG_ID_CHARS: usize = 128;
const MAX_TAG_NAME_CHARS: usize = 256;
const MAX_TAG_COUNT: usize = 10000;
const MAX_ACCESS_RULE_CHARS: usize = 9;

pub trait TagStoreProvider {
    fn tags_snapshot(&self) -> Result<BTreeMap<String, TagRecord>, String>;
    fn persist_tags(&self, tags: BTreeMap<String, TagRecord>) -> Result<(), String>;
}

pub trait TagsContext: TagStoreProvider + RoleStoreAccess + PageCacheAccess + ConfigAccess {}

impl<T> TagsContext for T where
    T: TagStoreProvider + RoleStoreAccess + PageCacheAccess + ConfigAccess
{
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRecord {
    pub name: String,
    #[serde(default)]
    pub roles: Vec<String>,
    pub access_rule: Option<AccessRule>,
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
pub struct TagStoreError {
    message: String,
}

impl TagStoreError {
    pub fn new(message: impl Into<String>) -> Self {
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

pub struct TagStore {
    tags_file: PathBuf,
    tags: RwLock<BTreeMap<String, TagRecord>>,
}

impl TagStore {
    pub fn new(state_sys_dir: PathBuf) -> Result<Self, TagStoreError> {
        let tags_file = validate_new_file_path(TAGS_FILE_NAME, &state_sys_dir)
            .map_err(|err| TagStoreError::new(format!("Invalid tag storage path: {}", err)))?;
        let (tags, should_persist) = Self::load_from_disk(&tags_file)?;
        let store = Self {
            tags_file,
            tags: RwLock::new(tags),
        };
        if should_persist {
            let snapshot = store
                .snapshot()
                .map_err(|err| TagStoreError::new(format!("Failed to load tags: {}", err)))?;
            store.persist(snapshot)?;
        }
        Ok(store)
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

    fn load_from_disk(
        tags_file: &Path,
    ) -> Result<(BTreeMap<String, TagRecord>, bool), TagStoreError> {
        let raw: Option<BTreeMap<String, TagRecord>> =
            yaml_store::read_yaml_file(tags_file, "tags")
                .map_err(|err| TagStoreError::new(err.to_string()))?;
        let raw = match raw {
            Some(raw) => raw,
            None => return Ok((BTreeMap::new(), false)),
        };
        let (normalized, should_persist) = normalize_tag_map(raw)?;
        Ok((normalized, should_persist))
    }

    fn write_tags_file(
        tags_file: &Path,
        tags: &BTreeMap<String, TagRecord>,
    ) -> Result<(), TagStoreError> {
        yaml_store::write_yaml_file(tags_file, "tags", tags)
            .map_err(|err| TagStoreError::new(err.to_string()))
    }
}

pub async fn handle_tags_request<C>(
    request: ManagementRequest,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: TagsContext,
{
    let response = match request.command {
        ManagementCommand::Tags(TagCommand::Add(payload)) => {
            handle_add(payload, request.workflow_id, context).await
        }
        ManagementCommand::Tags(TagCommand::Change(payload)) => {
            handle_change(payload, request.workflow_id, context).await
        }
        ManagementCommand::Tags(TagCommand::Delete(payload)) => {
            handle_delete(payload, request.workflow_id, context).await
        }
        ManagementCommand::Tags(TagCommand::List(payload)) => {
            handle_list(payload, request.workflow_id, context).await
        }
        ManagementCommand::Tags(TagCommand::Show(payload)) => {
            handle_show(payload, request.workflow_id, context).await
        }
        _ => response_err(
            TAG_ACTION_CHANGE_ERR,
            request.workflow_id,
            "Invalid tag command",
        ),
    };

    Ok(response)
}

async fn handle_add<C>(payload: TagAddRequest, workflow_id: u32, context: &C) -> ManagementResponse
where
    C: TagsContext,
{
    if let Err(err) = validate_tag_add(&payload) {
        return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err.to_string());
    }
    let normalized_roles = match normalize_roles(&payload.roles) {
        Ok(roles) => roles,
        Err(err) => return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    if let Err(err) = ensure_roles_exist(context, &normalized_roles) {
        return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err);
    }
    let mut tags = match context.tags_snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err),
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
    if let Err(err) = context.persist_tags(tags) {
        return response_err(TAG_ACTION_ADD_ERR, workflow_id, &err);
    }
    response_ok(TAG_ACTION_ADD_OK, workflow_id, "Tag added successfully")
}

async fn handle_change<C>(
    payload: TagChangeRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: TagsContext,
{
    if let Err(err) = validate_tag_change(&payload) {
        return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
    }
    let rename_to = payload
        .new_id
        .as_ref()
        .filter(|new_id| *new_id != &payload.id)
        .cloned();
    let mut tags = match context.tags_snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err),
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
        if let Err(err) = tag_workflows::rename_tag_in_content(context, &payload.id, new_id).await {
            return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err);
        }
        tags.remove(&payload.id);
        tags.insert(new_id.clone(), record);
    } else {
        tags.insert(payload.id, record);
    }
    if let Err(err) = context.persist_tags(tags) {
        return response_err(TAG_ACTION_CHANGE_ERR, workflow_id, &err);
    }
    if rename_to.is_some() {
        tag_workflows::invalidate_cache(context).await;
    }
    response_ok(
        TAG_ACTION_CHANGE_OK,
        workflow_id,
        "Tag updated successfully",
    )
}

async fn handle_delete<C>(
    payload: TagDeleteRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: TagsContext,
{
    if let Err(err) = validate_tag_delete(&payload) {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err.to_string());
    }
    let mut tags = match context.tags_snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err),
    };
    if !tags.contains_key(&payload.id) {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, "Tag not found");
    }
    if let Err(err) = tag_workflows::remove_tag_from_content(context, &payload.id).await {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err);
    }
    tags.remove(&payload.id);
    if let Err(err) = context.persist_tags(tags) {
        return response_err(TAG_ACTION_DELETE_ERR, workflow_id, &err);
    }
    tag_workflows::invalidate_cache(context).await;
    response_ok(
        TAG_ACTION_DELETE_OK,
        workflow_id,
        "Tag deleted successfully",
    )
}

async fn handle_list<C>(
    _payload: TagListRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: TagStoreProvider,
{
    let tags = match context.tags_snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_LIST_ERR, workflow_id, &err),
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

async fn handle_show<C>(
    payload: TagShowRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: TagStoreProvider,
{
    if let Err(err) = validate_tag_show(&payload) {
        return response_err(TAG_ACTION_SHOW_ERR, workflow_id, &err.to_string());
    }
    let tags = match context.tags_snapshot() {
        Ok(tags) => tags,
        Err(err) => return response_err(TAG_ACTION_SHOW_ERR, workflow_id, &err),
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
        payload: ResponsePayload::TagList(TagListResponse { tags }),
    }
}

fn response_tag_show(workflow_id: u32, payload: TagShowResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: TAGS_DOMAIN_ID,
        action_id: TAG_ACTION_SHOW_OK,
        workflow_id,
        payload: ResponsePayload::TagShow(payload),
    }
}

fn validate_tag_add(request: &TagAddRequest) -> Result<(), TagValidationError> {
    validate_tag_id(&request.id)?;
    validate_tag_name(&request.name)?;
    validate_roles(&request.roles)?;
    Ok(())
}

fn validate_tag_change(request: &TagChangeRequest) -> Result<(), TagValidationError> {
    validate_tag_id(&request.id)?;
    if request.name.is_none()
        && request.roles.is_none()
        && request.access_rule.is_none()
        && !request.clear_access
        && request.new_id.is_none()
    {
        return Err(TagValidationError::new(
            "Tag change requires --new-id, --name, --roles, --access, or --clear-access",
        ));
    }
    if request.clear_access && request.access_rule.is_some() {
        return Err(TagValidationError::new(
            "--clear-access cannot be used with --access",
        ));
    }
    if let Some(new_id) = &request.new_id {
        validate_tag_id(new_id)?;
    }
    if let Some(name) = &request.name {
        validate_tag_name(name)?;
    }
    if let Some(roles) = &request.roles {
        validate_roles(roles)?;
    }
    Ok(())
}

fn validate_tag_delete(request: &TagDeleteRequest) -> Result<(), TagValidationError> {
    validate_tag_id(&request.id)
}

fn validate_tag_list(_request: &TagListRequest) -> Result<(), TagValidationError> {
    Ok(())
}

fn validate_tag_show(request: &TagShowRequest) -> Result<(), TagValidationError> {
    validate_tag_id(&request.id)
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
    nop_roles::normalize_roles(roles).map_err(|err| TagValidationError::new(err.to_string()))
}

fn normalize_tag_map(
    tags: BTreeMap<String, TagRecord>,
) -> Result<(BTreeMap<String, TagRecord>, bool), TagStoreError> {
    if tags.len() > MAX_TAG_COUNT {
        return Err(TagStoreError::new(format!(
            "Tags must be at most {} entries",
            MAX_TAG_COUNT
        )));
    }
    let mut normalized = BTreeMap::new();
    let mut should_persist = false;
    for (id, record) in tags {
        validate_tag_id(&id).map_err(|err| TagStoreError::new(err.to_string()))?;
        validate_tag_name(&record.name).map_err(|err| TagStoreError::new(err.to_string()))?;
        let roles =
            normalize_roles(&record.roles).map_err(|err| TagStoreError::new(err.to_string()))?;
        if roles != record.roles {
            should_persist = true;
        }
        normalized.insert(
            id,
            TagRecord {
                name: record.name,
                roles,
                access_rule: record.access_rule,
            },
        );
    }
    Ok((normalized, should_persist))
}

fn ensure_roles_exist<C>(context: &C, roles: &[String]) -> Result<(), String>
where
    C: RoleStoreAccess + ?Sized,
{
    let available = context.roles_snapshot()?;
    for role in roles {
        if !available.contains(role) {
            return Err(format!("Role '{}' does not exist", role));
        }
    }
    Ok(())
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
    validate = |request| validate_tag_add(request),
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
    validate = |request| validate_tag_change(request),
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
    validate = |request| validate_tag_delete(request),
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
    validate = |request| validate_tag_list(request),
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
    validate = |request| validate_tag_show(request),
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
    use nop_management_contract::RequestCodec;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        dir.push(format!(
            "nop-tags-store-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn tag_id_charset_enforced() {
        let request = TagAddRequest {
            id: "Invalid Tag".to_string(),
            name: "Name".to_string(),
            roles: vec![],
            access_rule: None,
        };
        assert!(validate_tag_add(&request).is_err());
    }

    #[test]
    fn tag_name_limit_enforced() {
        let request = TagAddRequest {
            id: "valid".to_string(),
            name: "a".repeat(MAX_TAG_NAME_CHARS + 1),
            roles: vec![],
            access_rule: None,
        };
        assert!(validate_tag_add(&request).is_err());
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
        assert!(validate_tag_add(&request).is_err());
    }

    #[test]
    fn tag_store_persists_to_disk() {
        let state_dir = temp_dir("tags-store");
        let store = TagStore::new(state_dir.clone()).expect("tag store");

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

        let content = fs::read_to_string(state_dir.join(TAGS_FILE_NAME)).expect("read tags file");
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
        let err = codec.validate(&command).expect_err("expected error");
        assert!(err.to_string().contains("Tag id"));
    }
}
