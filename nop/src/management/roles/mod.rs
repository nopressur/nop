// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::codec::{FieldLimit, FieldLimits, FieldValues};
use crate::management::core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse,
};
use crate::management::errors::DomainResult;
use crate::management::registry::{DomainActionKey, ManagementHandler, ManagementRegistry};
use crate::management::yaml_store;
use crate::management::{WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use crate::roles::{
    ADMIN_ROLE, MAX_ROLE_CHARS, MAX_ROLE_COUNT, RoleValidationError, normalize_role,
};
use crate::security;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

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

const ROLES_FILE_NAME: &str = "roles.yaml";

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

impl RoleAddRequest {
    fn validate(&self) -> Result<(), RoleValidationError> {
        validate_role_name(&self.role)
    }
}

impl RoleChangeRequest {
    fn validate(&self) -> Result<(), RoleValidationError> {
        validate_role_name(&self.role)?;
        validate_role_name(&self.new_role)?;
        Ok(())
    }
}

impl RoleDeleteRequest {
    fn validate(&self) -> Result<(), RoleValidationError> {
        validate_role_name(&self.role)
    }
}

impl RoleListRequest {
    fn validate(&self) -> Result<(), RoleValidationError> {
        Ok(())
    }
}

impl RoleShowRequest {
    fn validate(&self) -> Result<(), RoleValidationError> {
        validate_role_name(&self.role)
    }
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

#[derive(Debug)]
pub(crate) struct RoleStoreError {
    message: String,
}

impl RoleStoreError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RoleStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RoleStoreError {}

pub(crate) struct RoleStore {
    roles_file: PathBuf,
    roles: RwLock<BTreeSet<String>>,
}

impl RoleStore {
    pub fn new(state_sys_dir: PathBuf) -> Result<Self, RoleStoreError> {
        let roles_file = security::validate_new_file_path(ROLES_FILE_NAME, &state_sys_dir)
            .map_err(|err| RoleStoreError::new(format!("Invalid role storage path: {}", err)))?;
        let (roles, should_persist) = Self::load_from_disk(&roles_file)?;
        let store = Self {
            roles_file,
            roles: RwLock::new(roles),
        };
        if should_persist {
            let snapshot = store
                .snapshot()
                .map_err(|err| RoleStoreError::new(format!("Failed to load roles: {}", err)))?;
            store.persist(snapshot)?;
        }
        Ok(store)
    }

    pub fn snapshot(&self) -> Result<BTreeSet<String>, RoleStoreError> {
        self.roles
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| RoleStoreError::new("Role store lock poisoned"))
    }

    pub fn persist(&self, roles: BTreeSet<String>) -> Result<(), RoleStoreError> {
        Self::write_roles_file(&self.roles_file, &roles)?;
        let mut guard = self
            .roles
            .write()
            .map_err(|_| RoleStoreError::new("Role store lock poisoned"))?;
        *guard = roles;
        Ok(())
    }

    fn load_from_disk(roles_file: &Path) -> Result<(BTreeSet<String>, bool), RoleStoreError> {
        let raw: Option<Vec<String>> = yaml_store::read_yaml_file(roles_file, "roles")
            .map_err(|err| RoleStoreError::new(err.to_string()))?;
        let raw = match raw {
            Some(raw) => raw,
            None => return Ok((default_roles(), true)),
        };
        if raw.len() > MAX_ROLE_COUNT {
            return Err(RoleStoreError::new(format!(
                "Roles must be at most {} entries",
                MAX_ROLE_COUNT
            )));
        }
        let mut roles = BTreeSet::new();
        for role in raw {
            let normalized =
                normalize_role(&role).map_err(|err| RoleStoreError::new(err.to_string()))?;
            roles.insert(normalized);
        }
        let mut should_persist = false;
        if !roles.contains(ADMIN_ROLE) {
            roles.insert(ADMIN_ROLE.to_string());
            should_persist = true;
        }
        Ok((roles, should_persist))
    }

    fn write_roles_file(roles_file: &Path, roles: &BTreeSet<String>) -> Result<(), RoleStoreError> {
        yaml_store::write_yaml_file(roles_file, "roles", roles)
            .map_err(|err| RoleStoreError::new(err.to_string()))
    }
}

fn default_roles() -> BTreeSet<String> {
    let mut roles = BTreeSet::new();
    roles.insert(ADMIN_ROLE.to_string());
    roles
}

pub fn register(registry: &mut ManagementRegistry) -> Result<(), crate::management::RegistryError> {
    registry.register_domain(crate::management::registry::DomainDescriptor {
        name: "roles",
        id: ROLES_DOMAIN_ID,
        actions: vec![
            crate::management::registry::ActionDescriptor {
                name: "add",
                id: ROLE_ACTION_ADD,
            },
            crate::management::registry::ActionDescriptor {
                name: "change",
                id: ROLE_ACTION_CHANGE,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete",
                id: ROLE_ACTION_DELETE,
            },
            crate::management::registry::ActionDescriptor {
                name: "list",
                id: ROLE_ACTION_LIST,
            },
            crate::management::registry::ActionDescriptor {
                name: "show",
                id: ROLE_ACTION_SHOW,
            },
            crate::management::registry::ActionDescriptor {
                name: "add_ok",
                id: ROLE_ACTION_ADD_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "add_err",
                id: ROLE_ACTION_ADD_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "change_ok",
                id: ROLE_ACTION_CHANGE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "change_err",
                id: ROLE_ACTION_CHANGE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_ok",
                id: ROLE_ACTION_DELETE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_err",
                id: ROLE_ACTION_DELETE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_ok",
                id: ROLE_ACTION_LIST_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_err",
                id: ROLE_ACTION_LIST_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "show_ok",
                id: ROLE_ACTION_SHOW_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "show_err",
                id: ROLE_ACTION_SHOW_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_roles_request(request, context).await })
    });
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_CHANGE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(ROLES_DOMAIN_ID, ROLE_ACTION_SHOW),
        handler,
    )?;

    register_request_codecs!(
        registry,
        [
            RoleAddRequestCodec,
            RoleChangeRequestCodec,
            RoleDeleteRequestCodec,
            RoleListRequestCodec,
            RoleShowRequestCodec
        ]
    );

    register_response_codecs!(
        registry,
        [
            MessageResponseCodec::new(ROLE_ACTION_ADD_OK),
            MessageResponseCodec::new(ROLE_ACTION_ADD_ERR),
            MessageResponseCodec::new(ROLE_ACTION_CHANGE_OK),
            MessageResponseCodec::new(ROLE_ACTION_CHANGE_ERR),
            MessageResponseCodec::new(ROLE_ACTION_DELETE_OK),
            MessageResponseCodec::new(ROLE_ACTION_DELETE_ERR),
            MessageResponseCodec::new(ROLE_ACTION_LIST_ERR),
            MessageResponseCodec::new(ROLE_ACTION_SHOW_ERR),
            RoleListResponseCodec,
            RoleShowResponseCodec
        ]
    );

    Ok(())
}

async fn handle_roles_request(
    request: ManagementRequest,
    context: Arc<ManagementContext>,
) -> DomainResult<ManagementResponse> {
    let workflow_id = request.workflow_id;
    let response = match request.command {
        ManagementCommand::Roles(RoleCommand::Add(payload)) => {
            handle_add(payload, workflow_id, &context).await
        }
        ManagementCommand::Roles(RoleCommand::Change(payload)) => {
            handle_change(payload, workflow_id, &context).await
        }
        ManagementCommand::Roles(RoleCommand::Delete(payload)) => {
            handle_delete(payload, workflow_id, &context).await
        }
        ManagementCommand::Roles(RoleCommand::List(payload)) => {
            handle_list(payload, workflow_id, &context).await
        }
        ManagementCommand::Roles(RoleCommand::Show(payload)) => {
            handle_show(payload, workflow_id, &context).await
        }
        _ => response_err(
            ROLE_ACTION_ADD_ERR,
            workflow_id,
            "Unsupported command for role domain",
        ),
    };
    Ok(response)
}

async fn handle_add(
    payload: RoleAddRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(ROLE_ACTION_ADD_ERR, workflow_id, &err.to_string());
    }
    let role = match normalize_role(&payload.role) {
        Ok(role) => role,
        Err(err) => return response_err(ROLE_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    if role == ADMIN_ROLE {
        return response_err(
            ROLE_ACTION_ADD_ERR,
            workflow_id,
            "Admin role already exists",
        );
    }
    let mut roles = match context.role_store.snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    if roles.len() >= MAX_ROLE_COUNT {
        return response_err(
            ROLE_ACTION_ADD_ERR,
            workflow_id,
            &format!("Roles must be at most {} entries", MAX_ROLE_COUNT),
        );
    }
    if roles.contains(&role) {
        return response_err(ROLE_ACTION_ADD_ERR, workflow_id, "Role already exists");
    }
    roles.insert(role.clone());
    if let Err(err) = context.role_store.persist(roles) {
        return response_err(ROLE_ACTION_ADD_ERR, workflow_id, &err.to_string());
    }
    response_ok(ROLE_ACTION_ADD_OK, workflow_id, "Role created successfully")
}

async fn handle_change(
    payload: RoleChangeRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
    }
    let role = match normalize_role(&payload.role) {
        Ok(role) => role,
        Err(err) => return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
    };
    let new_role = match normalize_role(&payload.new_role) {
        Ok(role) => role,
        Err(err) => return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
    };
    if role == ADMIN_ROLE || new_role == ADMIN_ROLE {
        return response_err(
            ROLE_ACTION_CHANGE_ERR,
            workflow_id,
            "Admin role cannot be renamed",
        );
    }
    if role == new_role {
        return response_err(
            ROLE_ACTION_CHANGE_ERR,
            workflow_id,
            "Role name is unchanged",
        );
    }

    let mut roles = match context.role_store.snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
    };
    if !roles.contains(&role) {
        return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, "Role not found");
    }
    if roles.contains(&new_role) {
        return response_err(
            ROLE_ACTION_CHANGE_ERR,
            workflow_id,
            "New role already exists",
        );
    }

    let tags_changed = if roles.len() >= MAX_ROLE_COUNT {
        roles.remove(&role);
        roles.insert(new_role.clone());
        if let Err(err) = context.role_store.persist(roles) {
            return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
        }
        let tags_changed = match replace_role_in_tags(context, &role, &new_role) {
            Ok(changed) => changed,
            Err(err) => return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err),
        };
        if let Err(err) = replace_role_in_users(context, &role, &new_role).await {
            return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err);
        }
        tags_changed
    } else {
        roles.insert(new_role.clone());
        if let Err(err) = context.role_store.persist(roles.clone()) {
            return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
        }
        let tags_changed = match replace_role_in_tags(context, &role, &new_role) {
            Ok(changed) => changed,
            Err(err) => return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err),
        };
        if let Err(err) = replace_role_in_users(context, &role, &new_role).await {
            return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err);
        }
        roles.remove(&role);
        if let Err(err) = context.role_store.persist(roles) {
            return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
        }
        tags_changed
    };
    if tags_changed {
        invalidate_cache(context).await;
    }
    response_ok(
        ROLE_ACTION_CHANGE_OK,
        workflow_id,
        "Role updated successfully",
    )
}

async fn handle_delete(
    payload: RoleDeleteRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, &err.to_string());
    }
    let role = match normalize_role(&payload.role) {
        Ok(role) => role,
        Err(err) => return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, &err.to_string()),
    };
    if role == ADMIN_ROLE {
        return response_err(
            ROLE_ACTION_DELETE_ERR,
            workflow_id,
            "Admin role cannot be removed",
        );
    }
    let roles = match context.role_store.snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, &err.to_string()),
    };
    if !roles.contains(&role) {
        return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, "Role not found");
    }
    let tags_changed = match remove_role_from_tags(context, &role) {
        Ok(changed) => changed,
        Err(err) => return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, &err),
    };
    if let Err(err) = remove_role_from_users(context, &role).await {
        return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, &err);
    }
    let mut updated_roles = roles;
    updated_roles.remove(&role);
    if let Err(err) = context.role_store.persist(updated_roles) {
        return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, &err.to_string());
    }
    if tags_changed {
        invalidate_cache(context).await;
    }
    response_ok(
        ROLE_ACTION_DELETE_OK,
        workflow_id,
        "Role deleted successfully",
    )
}

async fn handle_list(
    _payload: RoleListRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    let roles = match context.role_store.snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_LIST_ERR, workflow_id, &err.to_string()),
    };
    response_role_list(workflow_id, roles.into_iter().collect())
}

async fn handle_show(
    payload: RoleShowRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(ROLE_ACTION_SHOW_ERR, workflow_id, &err.to_string());
    }
    let role = match normalize_role(&payload.role) {
        Ok(role) => role,
        Err(err) => return response_err(ROLE_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
    };
    let roles = match context.role_store.snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
    };
    if !roles.contains(&role) {
        return response_err(ROLE_ACTION_SHOW_ERR, workflow_id, "Role not found");
    }
    response_role_show(workflow_id, RoleShowResponse { role })
}

define_domain_responses!(ROLES_DOMAIN_ID);

fn response_role_list(workflow_id: u32, roles: Vec<String>) -> ManagementResponse {
    ManagementResponse {
        domain_id: ROLES_DOMAIN_ID,
        action_id: ROLE_ACTION_LIST_OK,
        workflow_id,
        payload: crate::management::ResponsePayload::RoleList(RoleListResponse { roles }),
    }
}

fn response_role_show(workflow_id: u32, payload: RoleShowResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: ROLES_DOMAIN_ID,
        action_id: ROLE_ACTION_SHOW_OK,
        workflow_id,
        payload: crate::management::ResponsePayload::RoleShow(payload),
    }
}

pub(crate) fn ensure_roles_exist(
    context: &ManagementContext,
    roles: &[String],
) -> Result<(), String> {
    let available = context
        .role_store
        .snapshot()
        .map_err(|err| err.to_string())?;
    for role in roles {
        if !available.contains(role) {
            return Err(format!("Role '{}' does not exist", role));
        }
    }
    Ok(())
}

fn replace_role_in_tags(
    context: &ManagementContext,
    from_role: &str,
    to_role: &str,
) -> Result<bool, String> {
    let mut tags = context
        .tag_store
        .snapshot()
        .map_err(|err| err.to_string())?;
    let mut changed = false;
    for record in tags.values_mut() {
        if record.roles.is_empty() {
            continue;
        }
        let mut seen = HashSet::new();
        let mut updated = Vec::with_capacity(record.roles.len());
        for role in &record.roles {
            let candidate = if role == from_role { to_role } else { role };
            if seen.insert(candidate.to_string()) {
                updated.push(candidate.to_string());
            }
        }
        if updated != record.roles {
            record.roles = updated;
            changed = true;
        }
    }
    if changed {
        context
            .tag_store
            .persist(tags)
            .map_err(|err| err.to_string())?;
    }
    Ok(changed)
}

fn remove_role_from_tags(context: &ManagementContext, role: &str) -> Result<bool, String> {
    let mut tags = context
        .tag_store
        .snapshot()
        .map_err(|err| err.to_string())?;
    let mut changed = false;
    for record in tags.values_mut() {
        if record.roles.is_empty() {
            continue;
        }
        let before = record.roles.len();
        record.roles.retain(|item| item != role);
        if record.roles.len() != before {
            changed = true;
        }
    }
    if changed {
        context
            .tag_store
            .persist(tags)
            .map_err(|err| err.to_string())?;
    }
    Ok(changed)
}

async fn replace_role_in_users(
    context: &ManagementContext,
    from_role: &str,
    to_role: &str,
) -> Result<(), String> {
    let user_services = match context.user_services.as_ref() {
        Some(services) => services,
        None => return Ok(()),
    };
    let users = user_services.list_users().map_err(|err| err.to_string())?;
    for user in users {
        if user.roles.is_empty() {
            continue;
        }
        let mut seen = HashSet::new();
        let mut updated = Vec::with_capacity(user.roles.len());
        for role in &user.roles {
            let candidate = if role == from_role { to_role } else { role };
            if seen.insert(candidate.to_string()) {
                updated.push(candidate.to_string());
            }
        }
        if updated != user.roles {
            user_services
                .update_user_complete(&user.email, None, None, Some(updated))
                .await
                .map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

async fn remove_role_from_users(context: &ManagementContext, role: &str) -> Result<(), String> {
    let user_services = match context.user_services.as_ref() {
        Some(services) => services,
        None => return Ok(()),
    };
    let users = user_services.list_users().map_err(|err| err.to_string())?;
    for user in users {
        if user.roles.is_empty() {
            continue;
        }
        let before = user.roles.len();
        let updated: Vec<String> = user
            .roles
            .iter()
            .filter(|item| item.as_str() != role)
            .cloned()
            .collect();
        if updated.len() != before {
            user_services
                .update_user_complete(&user.email, None, None, Some(updated))
                .await
                .map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

async fn invalidate_cache(context: &ManagementContext) {
    if let Some(cache) = context.page_cache.as_ref()
        && let Err(err) = cache.invalidate().await
    {
        log::error!("Failed to invalidate page cache: {}", err);
    }
}

fn validate_role_name(role: &str) -> Result<(), RoleValidationError> {
    normalize_role(role).map(|_| ())
}

define_request_codec!(
    RoleAddRequestCodec,
    domain = Roles,
    command = RoleCommand,
    variant = Add,
    domain_id = ROLES_DOMAIN_ID,
    action_id = ROLE_ACTION_ADD,
    request = RoleAddRequest,
    limits = FieldLimits::new(vec![("role", FieldLimit::MaxChars(MAX_ROLE_CHARS))]),
    values = |request| role_add_field_values(request),
    error = "Unsupported command for role add codec",
);

define_request_codec!(
    RoleChangeRequestCodec,
    domain = Roles,
    command = RoleCommand,
    variant = Change,
    domain_id = ROLES_DOMAIN_ID,
    action_id = ROLE_ACTION_CHANGE,
    request = RoleChangeRequest,
    limits = FieldLimits::new(vec![
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
        ("new_role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |request| role_change_field_values(request),
    error = "Unsupported command for role change codec",
);

define_request_codec!(
    RoleDeleteRequestCodec,
    domain = Roles,
    command = RoleCommand,
    variant = Delete,
    domain_id = ROLES_DOMAIN_ID,
    action_id = ROLE_ACTION_DELETE,
    request = RoleDeleteRequest,
    limits = FieldLimits::new(vec![("role", FieldLimit::MaxChars(MAX_ROLE_CHARS))]),
    values = |request| role_delete_field_values(request),
    error = "Unsupported command for role delete codec",
);

define_request_codec!(
    RoleListRequestCodec,
    domain = Roles,
    command = RoleCommand,
    variant = List,
    domain_id = ROLES_DOMAIN_ID,
    action_id = ROLE_ACTION_LIST,
    request = RoleListRequest,
    limits = FieldLimits::new(Vec::new()),
    values = |_request| FieldValues::new(),
    error = "Unsupported command for role list codec",
);

define_request_codec!(
    RoleShowRequestCodec,
    domain = Roles,
    command = RoleCommand,
    variant = Show,
    domain_id = ROLES_DOMAIN_ID,
    action_id = ROLE_ACTION_SHOW,
    request = RoleShowRequest,
    limits = FieldLimits::new(vec![("role", FieldLimit::MaxChars(MAX_ROLE_CHARS))]),
    values = |request| role_show_field_values(request),
    error = "Unsupported command for role show codec",
);

define_message_response_codec!(
    MessageResponseCodec,
    domain_id = ROLES_DOMAIN_ID,
    error = "Unsupported response payload for role message codec",
);

define_response_codec!(
    RoleListResponseCodec,
    domain_id = ROLES_DOMAIN_ID,
    action_id = ROLE_ACTION_LIST_OK,
    payload = RoleList,
    response = RoleListResponse,
    limits = FieldLimits::new(vec![
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |payload| role_list_response_field_values(payload),
    error = "Unsupported response payload for role list codec",
);

define_response_codec!(
    RoleShowResponseCodec,
    domain_id = ROLES_DOMAIN_ID,
    action_id = ROLE_ACTION_SHOW_OK,
    payload = RoleShow,
    response = RoleShowResponse,
    limits = FieldLimits::new(vec![("role", FieldLimit::MaxChars(MAX_ROLE_CHARS))]),
    values = |payload| role_show_response_field_values(payload),
    error = "Unsupported response payload for role show codec",
);

fn role_add_field_values(request: &RoleAddRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("role", request.role.chars().count());
    values
}

fn role_change_field_values(request: &RoleChangeRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("role", request.role.chars().count());
    values.insert_len("new_role", request.new_role.chars().count());
    values
}

fn role_delete_field_values(request: &RoleDeleteRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("role", request.role.chars().count());
    values
}

fn role_show_field_values(request: &RoleShowRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("role", request.role.chars().count());
    values
}

fn role_list_response_field_values(response: &RoleListResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_count("roles", response.roles.len());
    values.insert_lens(
        "role",
        response
            .roles
            .iter()
            .map(|role| role.chars().count())
            .collect(),
    );
    values
}

fn role_show_response_field_values(response: &RoleShowResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("role", response.role.chars().count());
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config, test_server_list,
    };
    use crate::iam::{MemoryUserStore, User, UserServices};
    use crate::management::{
        ManagementBus, ManagementCommand, ManagementContext, RoleCommand, RoleDeleteRequest,
    };
    use crate::util::test_fixtures::TestFixtureRoot;
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Arc;

    #[derive(Deserialize)]
    struct TagRecordFixture {
        #[serde(default)]
        roles: Vec<String>,
    }

    fn build_test_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: test_server_list(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: test_local_users_config(),
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
                description: "Test".to_string(),
            },
            upload: UploadConfig {
                max_file_size_mb: 100,
                allowed_extensions: vec!["md".to_string()],
            },
            streaming: StreamingConfig { enabled: false },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            dev_mode: None,
        }
    }

    #[test]
    fn role_store_creates_admin_role() {
        let fixture = TestFixtureRoot::new_unique("role-store").unwrap();
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        let store = RoleStore::new(runtime_paths.state_sys_dir.clone()).expect("role store");
        let roles = store.snapshot().expect("role snapshot");
        assert!(roles.contains(ADMIN_ROLE));
        let roles_path = runtime_paths.state_sys_dir.join("roles.yaml");
        assert!(roles_path.exists());
    }

    #[tokio::test]
    async fn role_delete_cascades_tags_and_users() {
        let fixture = TestFixtureRoot::new_unique("role-delete").unwrap();
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");

        fs::write(
            runtime_paths.state_sys_dir.join("roles.yaml"),
            "- admin\n- editor\n",
        )
        .expect("write roles");
        fs::write(
            runtime_paths.state_sys_dir.join("tags.yaml"),
            "docs:\n  name: Docs\n  roles:\n    - editor\n",
        )
        .expect("write tags");

        let config = build_test_config();
        let store = Arc::new(MemoryUserStore::from_users(vec![User {
            email: "editor@example.com".to_string(),
            name: "Editor".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec!["editor".to_string()],
            password_version: 1,
        }]));
        let user_services = UserServices::new_with_store(&config, store).expect("user services");
        let user_services = Arc::new(user_services);
        let context = ManagementContext::from_components_with_user_services(
            runtime_paths.root.clone(),
            Arc::new(config),
            runtime_paths.clone(),
            Some(user_services.clone()),
        )
        .expect("context");
        let registry = crate::management::build_default_registry().expect("registry");
        let bus = ManagementBus::start(registry, context);

        let response = bus
            .send(
                crate::management::next_connection_id(),
                1,
                ManagementCommand::Roles(RoleCommand::Delete(RoleDeleteRequest {
                    role: "editor".to_string(),
                })),
            )
            .await
            .expect("role delete");
        assert_eq!(response.action_id, ROLE_ACTION_DELETE_OK);

        let tags_content =
            fs::read_to_string(runtime_paths.state_sys_dir.join("tags.yaml")).expect("read tags");
        let tags: BTreeMap<String, TagRecordFixture> =
            serde_yaml::from_str(&tags_content).expect("parse tags");
        let docs_roles = tags.get("docs").expect("docs tag").roles.clone();
        assert!(docs_roles.is_empty());

        let users = user_services.list_users().expect("list users");
        let editor = users
            .into_iter()
            .find(|user| user.email == "editor@example.com")
            .expect("user");
        assert!(editor.roles.is_empty());
    }
}
