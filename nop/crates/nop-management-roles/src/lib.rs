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
use nop_management_workflows::capabilities::{
    PageCacheAccess, RoleStoreAccess, TagStoreAccess, UserServicesAccess,
};
use nop_management_workflows::roles as role_workflows;
use nop_management_yaml as yaml_store;
use nop_roles::{ADMIN_ROLE, MAX_ROLE_CHARS, MAX_ROLE_COUNT, RoleValidationError, normalize_role};
use nop_security_paths::validate_new_file_path;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub use nop_management_contract::roles::{
    ROLE_ACTION_ADD, ROLE_ACTION_ADD_ERR, ROLE_ACTION_ADD_OK, ROLE_ACTION_CHANGE,
    ROLE_ACTION_CHANGE_ERR, ROLE_ACTION_CHANGE_OK, ROLE_ACTION_DELETE, ROLE_ACTION_DELETE_ERR,
    ROLE_ACTION_DELETE_OK, ROLE_ACTION_LIST, ROLE_ACTION_LIST_ERR, ROLE_ACTION_LIST_OK,
    ROLE_ACTION_SHOW, ROLE_ACTION_SHOW_ERR, ROLE_ACTION_SHOW_OK, ROLES_DOMAIN_ID, RoleAddRequest,
    RoleChangeRequest, RoleCommand, RoleDeleteRequest, RoleListRequest, RoleListResponse,
    RoleShowRequest, RoleShowResponse,
};

const ROLES_FILE_NAME: &str = "roles.yaml";

pub trait RolesContext:
    RoleStoreAccess + TagStoreAccess + UserServicesAccess + PageCacheAccess
{
}

impl<T> RolesContext for T where
    T: RoleStoreAccess + TagStoreAccess + UserServicesAccess + PageCacheAccess
{
}

fn validate_role_add(request: &RoleAddRequest) -> Result<(), RoleValidationError> {
    validate_role_name(&request.role)
}

fn validate_role_change(request: &RoleChangeRequest) -> Result<(), RoleValidationError> {
    validate_role_name(&request.role)?;
    validate_role_name(&request.new_role)?;
    Ok(())
}

fn validate_role_delete(request: &RoleDeleteRequest) -> Result<(), RoleValidationError> {
    validate_role_name(&request.role)
}

fn validate_role_list(_request: &RoleListRequest) -> Result<(), RoleValidationError> {
    Ok(())
}

fn validate_role_show(request: &RoleShowRequest) -> Result<(), RoleValidationError> {
    validate_role_name(&request.role)
}

#[derive(Debug)]
pub struct RoleStoreError {
    message: String,
}

impl RoleStoreError {
    pub fn new(message: impl Into<String>) -> Self {
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

pub struct RoleStore {
    roles_file: PathBuf,
    roles: RwLock<BTreeSet<String>>,
}

impl RoleStore {
    pub fn new(state_sys_dir: PathBuf) -> Result<Self, RoleStoreError> {
        let roles_file = validate_new_file_path(ROLES_FILE_NAME, &state_sys_dir)
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
        let mut should_persist = false;
        let raw_len = raw.len();
        for role in raw {
            let normalized =
                normalize_role(&role).map_err(|err| RoleStoreError::new(err.to_string()))?;
            if normalized != role {
                should_persist = true;
            }
            roles.insert(normalized);
        }
        if roles.len() != raw_len {
            should_persist = true;
        }
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

pub async fn handle_roles_request<C>(
    request: ManagementRequest,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: RolesContext,
{
    let workflow_id = request.workflow_id;
    let response = match request.command {
        ManagementCommand::Roles(RoleCommand::Add(payload)) => {
            handle_add(payload, workflow_id, context).await
        }
        ManagementCommand::Roles(RoleCommand::Change(payload)) => {
            handle_change(payload, workflow_id, context).await
        }
        ManagementCommand::Roles(RoleCommand::Delete(payload)) => {
            handle_delete(payload, workflow_id, context).await
        }
        ManagementCommand::Roles(RoleCommand::List(payload)) => {
            handle_list(payload, workflow_id, context).await
        }
        ManagementCommand::Roles(RoleCommand::Show(payload)) => {
            handle_show(payload, workflow_id, context).await
        }
        _ => response_err(
            ROLE_ACTION_ADD_ERR,
            workflow_id,
            "Unsupported command for role domain",
        ),
    };
    Ok(response)
}

async fn handle_add<C>(payload: RoleAddRequest, workflow_id: u32, context: &C) -> ManagementResponse
where
    C: RoleStoreAccess + ?Sized,
{
    if let Err(err) = validate_role_add(&payload) {
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
    let mut roles = match context.roles_snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_ADD_ERR, workflow_id, &err),
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
    if let Err(err) = context.persist_roles(roles) {
        return response_err(ROLE_ACTION_ADD_ERR, workflow_id, &err);
    }
    response_ok(ROLE_ACTION_ADD_OK, workflow_id, "Role created successfully")
}

async fn handle_change<C>(
    payload: RoleChangeRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: RolesContext,
{
    if let Err(err) = validate_role_change(&payload) {
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

    if let Err(err) = role_workflows::rename_role(context, &role, &new_role).await {
        return response_err(ROLE_ACTION_CHANGE_ERR, workflow_id, &err);
    }
    response_ok(
        ROLE_ACTION_CHANGE_OK,
        workflow_id,
        "Role updated successfully",
    )
}

async fn handle_delete<C>(
    payload: RoleDeleteRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: RolesContext,
{
    if let Err(err) = validate_role_delete(&payload) {
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
    if let Err(err) = role_workflows::delete_role(context, &role).await {
        return response_err(ROLE_ACTION_DELETE_ERR, workflow_id, &err);
    }
    response_ok(
        ROLE_ACTION_DELETE_OK,
        workflow_id,
        "Role deleted successfully",
    )
}

async fn handle_list<C>(
    _payload: RoleListRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: RoleStoreAccess + ?Sized,
{
    let roles = match context.roles_snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_LIST_ERR, workflow_id, &err),
    };
    response_role_list(workflow_id, roles.into_iter().collect())
}

async fn handle_show<C>(
    payload: RoleShowRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: RoleStoreAccess + ?Sized,
{
    if let Err(err) = validate_role_show(&payload) {
        return response_err(ROLE_ACTION_SHOW_ERR, workflow_id, &err.to_string());
    }
    let role = match normalize_role(&payload.role) {
        Ok(role) => role,
        Err(err) => return response_err(ROLE_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
    };
    let roles = match context.roles_snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(ROLE_ACTION_SHOW_ERR, workflow_id, &err),
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
        payload: ResponsePayload::RoleList(RoleListResponse { roles }),
    }
}

fn response_role_show(workflow_id: u32, payload: RoleShowResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: ROLES_DOMAIN_ID,
        action_id: ROLE_ACTION_SHOW_OK,
        workflow_id,
        payload: ResponsePayload::RoleShow(payload),
    }
}

pub fn ensure_roles_exist<C>(context: &C, roles: &[String]) -> Result<(), String>
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
    validate = |request| validate_role_add(request),
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
    validate = |request| validate_role_change(request),
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
    validate = |request| validate_role_delete(request),
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
    validate = |request| validate_role_list(request),
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
    validate = |request| validate_role_show(request),
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
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        dir.push(format!(
            "nop-role-store-{}-{}-{}",
            label,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn role_store_creates_admin_role() {
        let state_dir = temp_dir("role-store");
        let store = RoleStore::new(state_dir.clone()).expect("role store");
        let roles = store.snapshot().expect("role snapshot");
        assert!(roles.contains(ADMIN_ROLE));
        let roles_path = state_dir.join(ROLES_FILE_NAME);
        assert!(roles_path.exists());
    }
}
