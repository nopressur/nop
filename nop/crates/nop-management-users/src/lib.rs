// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use async_trait::async_trait;
use nop_config::{Argon2Params, PasswordHashingParams, ValidatedUsersConfig};
use nop_iam_passwords::{
    PasswordProviderBlock, build_password_provider_block, derive_back_end_hash, generate_salt_hex,
    validate_hex_field, validate_password_complexity,
};
use nop_library::{
    MAX_EMAIL_CHARS, MAX_NAME_CHARS, validate_and_sanitize_user_name,
    validate_email_field as validate_email_field_shared,
};
use nop_management_contract::core::{
    ManagementCommand, ManagementRequest, ManagementResponse, ResponsePayload,
};
use nop_management_contract::{
    FieldLimit, FieldLimits, FieldValues, define_domain_responses, define_message_response_codec,
    define_request_codec, define_response_codec,
};
use nop_management_errors::{DomainResult, ManagementError, ManagementErrorKind};
use nop_management_workflows::capabilities::RoleStoreAccess;
use nop_roles::{
    MAX_ROLE_CHARS, MAX_ROLE_COUNT, normalize_role as normalize_role_impl,
    normalize_roles as normalize_roles_impl,
};
use std::fmt;
use std::time::Duration;

pub use nop_management_contract::users::{
    PasswordPayload, PasswordSaltResponse, PasswordValidateResponse, USER_ACTION_ADD,
    USER_ACTION_ADD_ERR, USER_ACTION_ADD_OK, USER_ACTION_CHANGE, USER_ACTION_CHANGE_ERR,
    USER_ACTION_CHANGE_OK, USER_ACTION_DELETE, USER_ACTION_DELETE_ERR, USER_ACTION_DELETE_OK,
    USER_ACTION_LIST, USER_ACTION_LIST_ERR, USER_ACTION_LIST_OK, USER_ACTION_PASSWORD_SALT,
    USER_ACTION_PASSWORD_SALT_ERR, USER_ACTION_PASSWORD_SALT_OK, USER_ACTION_PASSWORD_SET,
    USER_ACTION_PASSWORD_SET_ERR, USER_ACTION_PASSWORD_SET_OK, USER_ACTION_PASSWORD_UPDATE,
    USER_ACTION_PASSWORD_UPDATE_ERR, USER_ACTION_PASSWORD_UPDATE_OK, USER_ACTION_PASSWORD_VALIDATE,
    USER_ACTION_PASSWORD_VALIDATE_ERR, USER_ACTION_PASSWORD_VALIDATE_OK, USER_ACTION_ROLE_ADD,
    USER_ACTION_ROLE_ADD_ERR, USER_ACTION_ROLE_ADD_OK, USER_ACTION_ROLE_REMOVE,
    USER_ACTION_ROLE_REMOVE_ERR, USER_ACTION_ROLE_REMOVE_OK, USER_ACTION_ROLES_LIST,
    USER_ACTION_ROLES_LIST_ERR, USER_ACTION_ROLES_LIST_OK, USER_ACTION_SHOW, USER_ACTION_SHOW_ERR,
    USER_ACTION_SHOW_OK, USERS_DOMAIN_ID, UserAddRequest, UserChangeRequest, UserCommand,
    UserDeleteRequest, UserListRequest, UserListResponse, UserPasswordSaltRequest,
    UserPasswordSetRequest, UserPasswordUpdateRequest, UserPasswordValidateRequest,
    UserRoleAddRequest, UserRoleRemoveRequest, UserRolesListRequest, UserRolesListResponse,
    UserShowRequest, UserShowResponse, UserSummary,
};

const PASSWORD_FRONT_END_HASH_CHARS: usize = 128;
const PASSWORD_SALT_CHARS: usize = 64;
const MAX_PASSWORD_CHARS: usize = 1024;
const MAX_CHANGE_TOKEN_CHARS: usize = 128;
const PASSWORD_SALT_TTL_SECONDS: u64 = 600;
const MAX_USER_COUNT: usize = 10000;
const USER_MUTATION_QUEUE_FULL_MESSAGE: &str = "User mutation queue is full; retry.";

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub email: String,
    pub name: String,
    pub password: Option<PasswordProviderBlock>,
    pub legacy_password_hash: Option<String>,
    pub roles: Vec<String>,
    pub password_version: u32,
}

#[derive(Debug, Clone)]
pub struct PasswordChangeToken {
    pub email: String,
    pub next_front_end_salt: String,
}

pub trait UsersConfigAccess {
    fn users_config(&self) -> &ValidatedUsersConfig;
}

#[async_trait]
pub trait BlockingRunner {
    async fn run_blocking<F, R>(&self, context: &'static str, task: F) -> Result<R, String>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static;
}

#[async_trait]
pub trait UserServicesAccess {
    fn password_params(&self) -> Result<&PasswordHashingParams, String>;
    fn list_users(&self) -> Result<Vec<UserRecord>, String>;
    fn get_user(&self, email: &str) -> Result<Option<UserRecord>, String>;
    async fn password_validate(&self, email: &str, front_end_hash: &str) -> Result<bool, String>;
    async fn add_user(
        &self,
        email: &str,
        name: &str,
        password: PasswordProviderBlock,
        roles: Vec<String>,
    ) -> Result<(), String>;
    async fn update_user_complete(
        &self,
        email: &str,
        name: Option<&str>,
        password: Option<PasswordProviderBlock>,
        roles: Option<Vec<String>>,
    ) -> Result<(), String>;
    async fn delete_user(&self, email: &str) -> Result<(), String>;
    async fn issue_password_change_token(
        &self,
        email: &str,
        next_front_end_salt: String,
        ttl: Duration,
    ) -> Result<(String, PasswordChangeToken), String>;
    async fn get_password_change_token(
        &self,
        change_token: &str,
    ) -> Result<Option<PasswordChangeToken>, String>;
    async fn invalidate_password_change_token(&self, change_token: &str) -> Result<(), String>;
}

pub trait UsersContext:
    UsersConfigAccess + UserServicesAccess + RoleStoreAccess + BlockingRunner
{
}

impl<T> UsersContext for T where
    T: UsersConfigAccess + UserServicesAccess + RoleStoreAccess + BlockingRunner
{
}

#[derive(Debug)]
struct UserValidationError {
    message: String,
}

impl UserValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for UserValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub async fn handle_users_request<C>(
    request: ManagementRequest,
    context: &C,
) -> DomainResult<ManagementResponse>
where
    C: UsersContext,
{
    let response = match request.command {
        ManagementCommand::Users(UserCommand::Add(payload)) => {
            handle_add(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::Change(payload)) => {
            handle_change(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::Delete(payload)) => {
            handle_delete(
                payload,
                request.workflow_id,
                context,
                request.actor_email.as_deref(),
            )
            .await
        }
        ManagementCommand::Users(UserCommand::PasswordSet(payload)) => {
            handle_password_set(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::List(payload)) => {
            handle_list(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::Show(payload)) => {
            handle_show(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::PasswordSalt(payload)) => {
            handle_password_salt(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::PasswordValidate(payload)) => {
            handle_password_validate(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::PasswordUpdate(payload)) => {
            handle_password_update(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::RoleAdd(payload)) => {
            handle_role_add(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::RoleRemove(payload)) => {
            handle_role_remove(payload, request.workflow_id, context).await
        }
        ManagementCommand::Users(UserCommand::RolesList(payload)) => {
            handle_roles_list(payload, request.workflow_id, context).await
        }
        _ => response_err(
            USER_ACTION_CHANGE_ERR,
            request.workflow_id,
            "Invalid user command",
        ),
    };

    Ok(response)
}

async fn handle_add<C>(payload: UserAddRequest, workflow_id: u32, context: &C) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_add(&payload) {
        return response_err(USER_ACTION_ADD_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ADD_ERR, workflow_id, &message);
    }
    let UserAddRequest {
        email: raw_email,
        name,
        password,
        roles: raw_roles,
        change_token,
    } = payload;
    let email = match normalize_email(&raw_email) {
        Ok(email) => email,
        Err(err) => return response_err(USER_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    let roles = match normalize_roles(&raw_roles) {
        Ok(roles) => roles,
        Err(err) => return response_err(USER_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    let sanitized_name = match sanitize_user_name(&name) {
        Ok(name) => name,
        Err(err) => return response_err(USER_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    };
    if let Err(err) = ensure_roles_exist(context, &roles) {
        return response_err(USER_ACTION_ADD_ERR, workflow_id, &err);
    }
    let password_block = match build_password_block(context, &email, password, change_token).await {
        Ok(block) => block,
        Err(err) => return response_err(USER_ACTION_ADD_ERR, workflow_id, &err),
    };

    match context
        .add_user(&email, &sanitized_name, password_block, roles)
        .await
    {
        Ok(_) => response_ok(USER_ACTION_ADD_OK, workflow_id, "User added successfully"),
        Err(err) => response_mutation_err(USER_ACTION_ADD_ERR, workflow_id, &err),
    }
}

async fn handle_change<C>(
    payload: UserChangeRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_change(&payload) {
        return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &message);
    }
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
    };
    let roles = match payload.roles.as_ref() {
        Some(roles) => match normalize_roles(roles) {
            Ok(roles) => Some(roles),
            Err(err) => return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
        },
        None => None,
    };
    let sanitized_name = match payload.name.as_deref() {
        Some(name) => match sanitize_user_name(name) {
            Ok(name) => Some(name),
            Err(err) => return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
        },
        None => None,
    };
    if let Some(roles) = roles.as_ref()
        && let Err(err) = ensure_roles_exist(context, roles)
    {
        return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err);
    }

    match context
        .update_user_complete(&email, sanitized_name.as_deref(), None, roles)
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_CHANGE_OK,
            workflow_id,
            "User updated successfully",
        ),
        Err(err) => response_mutation_err(USER_ACTION_CHANGE_ERR, workflow_id, &err),
    }
}

async fn handle_delete<C>(
    payload: UserDeleteRequest,
    workflow_id: u32,
    context: &C,
    actor_email: Option<&str>,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_delete(&payload) {
        return response_err(USER_ACTION_DELETE_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_DELETE_ERR, workflow_id, &message);
    }
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => return response_err(USER_ACTION_DELETE_ERR, workflow_id, &err.to_string()),
    };
    if let Some(actor_email) = actor_email {
        let actor_email = match normalize_email(actor_email) {
            Ok(email) => email,
            Err(err) => {
                log::warn!("User delete actor email normalization failed: {}", err);
                return response_err(
                    USER_ACTION_DELETE_ERR,
                    workflow_id,
                    "Unable to validate current user",
                );
            }
        };
        if actor_email == email {
            return response_err(
                USER_ACTION_DELETE_ERR,
                workflow_id,
                "You cannot delete your own account",
            );
        }
    }

    match context.delete_user(&email).await {
        Ok(_) => response_ok(
            USER_ACTION_DELETE_OK,
            workflow_id,
            "User deleted successfully",
        ),
        Err(err) => response_mutation_err(USER_ACTION_DELETE_ERR, workflow_id, &err),
    }
}

async fn handle_password_set<C>(
    payload: UserPasswordSetRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_password_set(&payload) {
        return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &message);
    }
    let UserPasswordSetRequest {
        email: raw_email,
        password,
        change_token,
    } = payload;
    let email = match normalize_email(&raw_email) {
        Ok(email) => email,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err.to_string());
        }
    };
    let password_block = match build_password_block(context, &email, password, change_token).await {
        Ok(block) => block,
        Err(err) => return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err),
    };

    match context
        .update_user_complete(&email, None, Some(password_block), None)
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_PASSWORD_SET_OK,
            workflow_id,
            "Password updated successfully",
        ),
        Err(err) => response_mutation_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err),
    }
}

async fn handle_password_salt<C>(
    payload: UserPasswordSaltRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_password_salt(&payload) {
        return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &message);
    }
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
        }
    };
    let params = match context.password_params() {
        Ok(params) => params.clone(),
        Err(err) => return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err),
    };
    let front_end_len = params.front_end.salt_len;
    let current_front_end_salt = match context.get_user(&email) {
        Ok(Some(user)) => match user.password.as_ref() {
            Some(block) => block.front_end_salt.clone(),
            None => {
                if user.legacy_password_hash.is_some() {
                    log::warn!(
                        "Legacy password hash ignored for user {} (reset required)",
                        email
                    );
                } else {
                    log::warn!("User {} has no password provider block", email);
                }
                match generate_salt_hex(front_end_len) {
                    Ok(salt) => salt,
                    Err(err) => {
                        return response_err(
                            USER_ACTION_PASSWORD_SALT_ERR,
                            workflow_id,
                            &err.to_string(),
                        );
                    }
                }
            }
        },
        Ok(None) => match generate_salt_hex(front_end_len) {
            Ok(salt) => salt,
            Err(err) => {
                return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
            }
        },
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err);
        }
    };
    let next_front_end_salt = match generate_salt_hex(front_end_len) {
        Ok(salt) => salt,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
        }
    };
    let (change_token, _token) = match context
        .issue_password_change_token(
            &email,
            next_front_end_salt.clone(),
            Duration::from_secs(PASSWORD_SALT_TTL_SECONDS),
        )
        .await
    {
        Ok(value) => value,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err);
        }
    };

    response_password_salt(
        workflow_id,
        PasswordSaltResponse {
            change_token,
            current_front_end_salt,
            next_front_end_salt,
            expires_in_seconds: PASSWORD_SALT_TTL_SECONDS,
        },
    )
}

async fn handle_password_validate<C>(
    payload: UserPasswordValidateRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_password_validate(&payload) {
        return response_err(
            USER_ACTION_PASSWORD_VALIDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_VALIDATE_ERR, workflow_id, &message);
    }
    let params = match context.password_params() {
        Ok(params) => params.clone(),
        Err(err) => return response_err(USER_ACTION_PASSWORD_VALIDATE_ERR, workflow_id, &err),
    };
    if let Err(err) = validate_front_end_hash_exact(&payload.front_end_hash, &params.front_end) {
        return response_err(
            USER_ACTION_PASSWORD_VALIDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => {
            return response_err(
                USER_ACTION_PASSWORD_VALIDATE_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let front_end_hash = payload.front_end_hash;
    let valid = match context.password_validate(&email, &front_end_hash).await {
        Ok(valid) => valid,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_VALIDATE_ERR, workflow_id, &err);
        }
    };

    response_password_validate(workflow_id, PasswordValidateResponse { valid })
}

async fn handle_password_update<C>(
    payload: UserPasswordUpdateRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_password_update(&payload) {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &message);
    }
    let UserPasswordUpdateRequest {
        email: raw_email,
        current_front_end_hash,
        new_front_end_hash,
        new_front_end_salt,
        change_token,
    } = payload;
    let params = match context.password_params() {
        Ok(params) => params.clone(),
        Err(err) => return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err),
    };
    if let Err(err) = validate_front_end_hash_exact(&current_front_end_hash, &params.front_end) {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(err) = validate_front_end_hash_exact(&new_front_end_hash, &params.front_end) {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(err) = validate_front_end_salt_exact(&new_front_end_salt, &params.front_end) {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    let email = match normalize_email(&raw_email) {
        Ok(email) => email,
        Err(err) => {
            return response_err(
                USER_ACTION_PASSWORD_UPDATE_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    if let Err(err) =
        validate_change_token_payload(context, &email, &change_token, &new_front_end_salt).await
    {
        return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err);
    }

    let email_for_validate = email.clone();
    let valid = match context
        .password_validate(&email_for_validate, &current_front_end_hash)
        .await
    {
        Ok(valid) => valid,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err);
        }
    };
    if !valid {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            "Current password is invalid",
        );
    }

    let back_end_salt = match generate_salt_hex(params.back_end.salt_len) {
        Ok(salt) => salt,
        Err(err) => {
            return response_err(
                USER_ACTION_PASSWORD_UPDATE_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let back_end_salt_for_hash = back_end_salt.clone();
    let stored_hash = match context
        .run_blocking("derive password hash", move || {
            derive_back_end_hash(
                &new_front_end_hash,
                &back_end_salt_for_hash,
                &params.back_end,
            )
            .map_err(|err| err.to_string())
        })
        .await
    {
        Ok(result) => match result {
            Ok(hash) => hash,
            Err(err) => return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err),
        },
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err);
        }
    };
    let password_block = PasswordProviderBlock {
        front_end_salt: new_front_end_salt,
        back_end_salt,
        stored_hash,
    };

    if let Err(err) = context
        .update_user_complete(&email, None, Some(password_block), None)
        .await
    {
        return response_mutation_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err);
    }

    if let Err(err) = context
        .invalidate_password_change_token(&change_token)
        .await
    {
        log::warn!("Password change token invalidate failed: {}", err);
    }

    response_ok(
        USER_ACTION_PASSWORD_UPDATE_OK,
        workflow_id,
        "Password updated successfully",
    )
}

async fn handle_list<C>(
    _payload: UserListRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_LIST_ERR, workflow_id, &message);
    }
    let users = match context.list_users() {
        Ok(users) => users,
        Err(err) => return response_err(USER_ACTION_LIST_ERR, workflow_id, &err),
    };

    let mut summaries = Vec::with_capacity(users.len());
    for user in users {
        let email = match normalize_email(&user.email) {
            Ok(email) => email,
            Err(err) => return response_err(USER_ACTION_LIST_ERR, workflow_id, &err.to_string()),
        };
        summaries.push(UserSummary {
            email,
            name: user.name.clone(),
        });
    }

    response_user_list(workflow_id, summaries)
}

async fn handle_show<C>(
    payload: UserShowRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_show(&payload) {
        return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_SHOW_ERR, workflow_id, &message);
    }
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
    };
    let users = match context.list_users() {
        Ok(users) => users,
        Err(err) => return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err),
    };

    let user = match users
        .into_iter()
        .find(|user| user.email.to_lowercase() == email)
    {
        Some(user) => user,
        None => return response_err(USER_ACTION_SHOW_ERR, workflow_id, "User not found"),
    };

    let roles = match normalize_roles(&user.roles) {
        Ok(roles) => roles,
        Err(err) => return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
    };

    response_user_show(
        workflow_id,
        UserShowResponse {
            email,
            name: user.name,
            roles,
        },
    )
}

async fn handle_role_add<C>(
    payload: UserRoleAddRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_role_add(&payload) {
        return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &message);
    }
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err.to_string()),
    };
    let role = match normalize_role(&payload.role) {
        Ok(role) => role,
        Err(err) => return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err.to_string()),
    };
    if let Err(err) = ensure_roles_exist(context, std::slice::from_ref(&role)) {
        return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err);
    }

    let users = match context.list_users() {
        Ok(users) => users,
        Err(err) => return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err),
    };
    let user = match users
        .into_iter()
        .find(|user| user.email.to_lowercase() == email)
    {
        Some(user) => user,
        None => return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, "User not found"),
    };

    let mut roles = match normalize_roles(&user.roles) {
        Ok(roles) => roles,
        Err(err) => return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err.to_string()),
    };
    if !roles.contains(&role) {
        roles.push(role);
    }
    if roles.len() > MAX_ROLE_COUNT {
        return response_err(
            USER_ACTION_ROLE_ADD_ERR,
            workflow_id,
            &format!("Roles must be at most {} entries", MAX_ROLE_COUNT),
        );
    }

    match context
        .update_user_complete(&email, None, None, Some(roles))
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_ROLE_ADD_OK,
            workflow_id,
            "Role added successfully",
        ),
        Err(err) => response_mutation_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err),
    }
}

async fn handle_role_remove<C>(
    payload: UserRoleRemoveRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(err) = validate_user_role_remove(&payload) {
        return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &message);
    }
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => {
            return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err.to_string());
        }
    };
    let role = match normalize_role(&payload.role) {
        Ok(role) => role,
        Err(err) => {
            return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err.to_string());
        }
    };

    let users = match context.list_users() {
        Ok(users) => users,
        Err(err) => {
            return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err);
        }
    };
    let user = match users
        .into_iter()
        .find(|user| user.email.to_lowercase() == email)
    {
        Some(user) => user,
        None => return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, "User not found"),
    };

    let mut roles = match normalize_roles(&user.roles) {
        Ok(roles) => roles,
        Err(err) => {
            return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err.to_string());
        }
    };
    if !roles.iter().any(|existing| existing == &role) {
        return response_err(
            USER_ACTION_ROLE_REMOVE_ERR,
            workflow_id,
            "Role not assigned to user",
        );
    }
    roles.retain(|existing| existing != &role);

    match context
        .update_user_complete(&email, None, None, Some(roles))
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_ROLE_REMOVE_OK,
            workflow_id,
            "Role removed successfully",
        ),
        Err(err) => response_mutation_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err),
    }
}

async fn handle_roles_list<C>(
    _payload: UserRolesListRequest,
    workflow_id: u32,
    context: &C,
) -> ManagementResponse
where
    C: UsersContext,
{
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ROLES_LIST_ERR, workflow_id, &message);
    }
    let roles = match context.roles_snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(USER_ACTION_ROLES_LIST_ERR, workflow_id, &err),
    };
    response_roles_list(workflow_id, roles.into_iter().collect())
}

fn ensure_local_auth<C>(context: &C) -> Result<(), String>
where
    C: UsersConfigAccess,
{
    match context.users_config() {
        ValidatedUsersConfig::Local(_) => Ok(()),
        ValidatedUsersConfig::Oidc(_) => {
            Err("User management requires local authentication".to_string())
        }
    }
}

async fn build_password_block<C>(
    context: &C,
    email: &str,
    payload: PasswordPayload,
    change_token: Option<String>,
) -> Result<PasswordProviderBlock, String>
where
    C: UsersContext,
{
    let params = context.password_params()?.clone();
    match payload {
        PasswordPayload::Plaintext { plaintext } => {
            if let Some(local) = context.users_config().local()
                && local.password_complexity_enabled
            {
                validate_password_complexity(&plaintext)?;
            }
            let params = params.clone();
            context
                .run_blocking("hash password", move || {
                    build_password_provider_block(&plaintext, &params)
                        .map_err(|err| err.to_string())
                })
                .await?
        }
        PasswordPayload::FrontEndHash {
            front_end_hash,
            front_end_salt,
        } => {
            validate_front_end_hash_exact(&front_end_hash, &params.front_end)
                .map_err(|err| err.to_string())?;
            validate_front_end_salt_exact(&front_end_salt, &params.front_end)
                .map_err(|err| err.to_string())?;
            let change_token =
                change_token.ok_or_else(|| "change_token is required".to_string())?;
            validate_change_token_payload(context, email, &change_token, &front_end_salt).await?;
            let back_end_salt =
                generate_salt_hex(params.back_end.salt_len).map_err(|err| err.to_string())?;
            let back_end_salt_for_hash = back_end_salt.clone();
            let params_back_end = params.back_end.clone();
            let stored_hash = context
                .run_blocking("derive password hash", move || {
                    derive_back_end_hash(&front_end_hash, &back_end_salt_for_hash, &params_back_end)
                        .map_err(|err| err.to_string())
                })
                .await??;
            Ok(PasswordProviderBlock {
                front_end_salt,
                back_end_salt,
                stored_hash,
            })
        }
    }
}

async fn validate_change_token_payload<C>(
    context: &C,
    email: &str,
    change_token: &str,
    expected_front_end_salt: &str,
) -> Result<(), String>
where
    C: UserServicesAccess,
{
    let token = context
        .get_password_change_token(change_token)
        .await?
        .ok_or_else(|| "change_token is invalid or expired".to_string())?;
    if token.email != email {
        return Err("change_token does not match user".to_string());
    }
    if token.next_front_end_salt != expected_front_end_salt {
        return Err("front_end_salt does not match change_token".to_string());
    }
    Ok(())
}

fn response_mutation_err(action_id: u32, workflow_id: u32, message: &str) -> ManagementResponse {
    if message == USER_MUTATION_QUEUE_FULL_MESSAGE {
        let error = ManagementError::new(
            ManagementErrorKind::Busy,
            Some(USERS_DOMAIN_ID),
            Some(action_id),
            message,
        );
        log::warn!("{}", error);
    }
    response_err(action_id, workflow_id, message)
}

define_domain_responses!(
    USERS_DOMAIN_ID,
    ok_fallback = "User management success",
    err_fallback = "User management error"
);

fn response_user_list(workflow_id: u32, users: Vec<UserSummary>) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_LIST_OK,
        workflow_id,
        payload: ResponsePayload::UserList(UserListResponse { users }),
    }
}

fn response_user_show(workflow_id: u32, payload: UserShowResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_SHOW_OK,
        workflow_id,
        payload: ResponsePayload::UserShow(payload),
    }
}

fn response_roles_list(workflow_id: u32, roles: Vec<String>) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_ROLES_LIST_OK,
        workflow_id,
        payload: ResponsePayload::UserRolesList(UserRolesListResponse { roles }),
    }
}

fn response_password_salt(workflow_id: u32, payload: PasswordSaltResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_PASSWORD_SALT_OK,
        workflow_id,
        payload: ResponsePayload::UserPasswordSalt(payload),
    }
}

fn response_password_validate(
    workflow_id: u32,
    payload: PasswordValidateResponse,
) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_PASSWORD_VALIDATE_OK,
        workflow_id,
        payload: ResponsePayload::UserPasswordValidate(payload),
    }
}

fn validate_user_add(request: &UserAddRequest) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    validate_name(&request.name)?;
    validate_password_payload(&request.password)?;
    validate_roles(&request.roles)?;
    validate_change_token(request.change_token.as_ref())?;
    Ok(())
}

fn validate_user_change(request: &UserChangeRequest) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    if request.name.is_none() && request.roles.is_none() {
        return Err(UserValidationError::new(
            "User change requires --name, --roles, or --clear-roles",
        ));
    }
    if let Some(name) = &request.name {
        validate_name(name)?;
    }
    if let Some(roles) = &request.roles {
        validate_roles(roles)?;
    }
    Ok(())
}

fn validate_user_delete(request: &UserDeleteRequest) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)
}

fn validate_user_password_set(request: &UserPasswordSetRequest) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    validate_password_payload(&request.password)?;
    validate_change_token(request.change_token.as_ref())?;
    Ok(())
}

fn validate_user_password_salt(
    request: &UserPasswordSaltRequest,
) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    Ok(())
}

fn validate_user_password_validate(
    request: &UserPasswordValidateRequest,
) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    validate_front_end_hash(&request.front_end_hash)?;
    Ok(())
}

fn validate_user_password_update(
    request: &UserPasswordUpdateRequest,
) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    validate_front_end_hash(&request.current_front_end_hash)?;
    validate_front_end_hash(&request.new_front_end_hash)?;
    validate_front_end_salt(&request.new_front_end_salt)?;
    validate_change_token(Some(&request.change_token))?;
    Ok(())
}

fn validate_user_list(_request: &UserListRequest) -> Result<(), UserValidationError> {
    Ok(())
}

fn validate_user_show(request: &UserShowRequest) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)
}

fn validate_user_role_add(request: &UserRoleAddRequest) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    validate_role(&request.role)?;
    Ok(())
}

fn validate_user_role_remove(request: &UserRoleRemoveRequest) -> Result<(), UserValidationError> {
    validate_email_field(&request.email)?;
    validate_role(&request.role)?;
    Ok(())
}

fn validate_user_roles_list(_request: &UserRolesListRequest) -> Result<(), UserValidationError> {
    Ok(())
}

fn normalize_email(email: &str) -> Result<String, UserValidationError> {
    let normalized = email.trim().to_lowercase();
    validate_email_field_shared(&normalized).map_err(UserValidationError::new)?;
    Ok(normalized)
}

fn validate_email_field(email: &str) -> Result<(), UserValidationError> {
    normalize_email(email).map(|_| ())
}

fn sanitize_user_name(name: &str) -> Result<String, UserValidationError> {
    validate_and_sanitize_user_name(name).map_err(UserValidationError::new)
}

fn validate_name(name: &str) -> Result<(), UserValidationError> {
    sanitize_user_name(name).map(|_| ())
}

fn validate_password_payload(payload: &PasswordPayload) -> Result<(), UserValidationError> {
    match payload {
        PasswordPayload::Plaintext { plaintext } => validate_plaintext_password(plaintext),
        PasswordPayload::FrontEndHash {
            front_end_hash,
            front_end_salt,
        } => {
            validate_front_end_hash(front_end_hash)?;
            validate_front_end_salt(front_end_salt)?;
            Ok(())
        }
    }
}

fn validate_plaintext_password(password: &str) -> Result<(), UserValidationError> {
    if password.is_empty() {
        return Err(UserValidationError::new("Password is required"));
    }
    if password.chars().count() > MAX_PASSWORD_CHARS {
        return Err(UserValidationError::new(format!(
            "Password must be at most {} characters",
            MAX_PASSWORD_CHARS
        )));
    }
    Ok(())
}

fn validate_front_end_hash(hash: &str) -> Result<(), UserValidationError> {
    validate_hex_field_max("front_end_hash", hash, PASSWORD_FRONT_END_HASH_CHARS)
}

fn validate_front_end_salt(salt: &str) -> Result<(), UserValidationError> {
    validate_hex_field_max("front_end_salt", salt, PASSWORD_SALT_CHARS)
}

fn expected_front_end_hash_chars(params: &Argon2Params) -> usize {
    params.output_len as usize * 2
}

fn expected_front_end_salt_chars(params: &Argon2Params) -> usize {
    params.salt_len as usize * 2
}

fn validate_front_end_hash_exact(
    hash: &str,
    params: &Argon2Params,
) -> Result<(), UserValidationError> {
    let expected_len = expected_front_end_hash_chars(params);
    validate_hex_field("front_end_hash", hash, expected_len)
        .map_err(|err| UserValidationError::new(err.to_string()))
}

fn validate_front_end_salt_exact(
    salt: &str,
    params: &Argon2Params,
) -> Result<(), UserValidationError> {
    let expected_len = expected_front_end_salt_chars(params);
    validate_hex_field("front_end_salt", salt, expected_len)
        .map_err(|err| UserValidationError::new(err.to_string()))
}

fn validate_hex_field_max(
    label: &str,
    value: &str,
    max_len: usize,
) -> Result<(), UserValidationError> {
    if value.is_empty() {
        return Err(UserValidationError::new(format!("{} is required", label)));
    }
    let len = value.chars().count();
    if len > max_len {
        return Err(UserValidationError::new(format!(
            "{} must be at most {} hex characters",
            label, max_len
        )));
    }
    if !len.is_multiple_of(2) {
        return Err(UserValidationError::new(format!(
            "{} must have an even number of hex characters",
            label
        )));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(UserValidationError::new(format!(
            "{} must contain only hex characters",
            label
        )));
    }
    Ok(())
}

fn validate_change_token(change_token: Option<&String>) -> Result<(), UserValidationError> {
    if let Some(token) = change_token {
        if token.is_empty() {
            return Err(UserValidationError::new("change_token is required"));
        }
        if token.chars().count() > MAX_CHANGE_TOKEN_CHARS {
            return Err(UserValidationError::new(format!(
                "change_token must be at most {} characters",
                MAX_CHANGE_TOKEN_CHARS
            )));
        }
    }
    Ok(())
}

fn validate_roles(roles: &[String]) -> Result<(), UserValidationError> {
    normalize_roles(roles).map(|_| ())
}

fn normalize_roles(roles: &[String]) -> Result<Vec<String>, UserValidationError> {
    normalize_roles_impl(roles).map_err(|err| UserValidationError::new(err.to_string()))
}

fn normalize_role(role: &str) -> Result<String, UserValidationError> {
    normalize_role_impl(role).map_err(|err| UserValidationError::new(err.to_string()))
}

fn validate_role(role: &str) -> Result<(), UserValidationError> {
    normalize_role(role).map(|_| ())
}

fn user_add_field_values(request: &UserAddRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
    values.insert_len("name", request.name.chars().count());
    password_payload_field_values(&request.password, &mut values);
    if let Some(change_token) = &request.change_token {
        values.insert_len("change_token", change_token.chars().count());
    }
    values.insert_count("roles", request.roles.len());
    values.insert_lens(
        "role",
        request
            .roles
            .iter()
            .map(|role| role.chars().count())
            .collect(),
    );
    values
}

fn user_change_field_values(request: &UserChangeRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
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
    values
}

fn user_delete_field_values(request: &UserDeleteRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
    values
}

fn user_password_set_field_values(request: &UserPasswordSetRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
    password_payload_field_values(&request.password, &mut values);
    if let Some(change_token) = &request.change_token {
        values.insert_len("change_token", change_token.chars().count());
    }
    values
}

fn user_password_salt_field_values(request: &UserPasswordSaltRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
    values
}

fn user_password_validate_field_values(request: &UserPasswordValidateRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
    values.insert_len("front_end_hash", request.front_end_hash.chars().count());
    values
}

fn user_password_update_field_values(request: &UserPasswordUpdateRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
    values.insert_len(
        "current_front_end_hash",
        request.current_front_end_hash.chars().count(),
    );
    values.insert_len(
        "new_front_end_hash",
        request.new_front_end_hash.chars().count(),
    );
    values.insert_len(
        "new_front_end_salt",
        request.new_front_end_salt.chars().count(),
    );
    values.insert_len("change_token", request.change_token.chars().count());
    values
}

fn user_show_field_values(request: &UserShowRequest) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", request.email.chars().count());
    values
}

fn user_role_field_values(email: &str, role: &str) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", email.chars().count());
    values.insert_len("role", role.chars().count());
    values
}

fn user_list_response_values(response: &UserListResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_count("users", response.users.len());
    values.insert_lens(
        "email",
        response
            .users
            .iter()
            .map(|user| user.email.chars().count())
            .collect(),
    );
    values.insert_lens(
        "name",
        response
            .users
            .iter()
            .map(|user| user.name.chars().count())
            .collect(),
    );
    values
}

fn user_show_response_values(response: &UserShowResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("email", response.email.chars().count());
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
    values
}

fn user_roles_list_response_values(response: &UserRolesListResponse) -> FieldValues {
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

fn password_payload_field_values(payload: &PasswordPayload, values: &mut FieldValues) {
    match payload {
        PasswordPayload::Plaintext { plaintext } => {
            values.insert_len("password", plaintext.chars().count());
        }
        PasswordPayload::FrontEndHash {
            front_end_hash,
            front_end_salt,
        } => {
            values.insert_len("front_end_hash", front_end_hash.chars().count());
            values.insert_len("front_end_salt", front_end_salt.chars().count());
        }
    }
}

define_request_codec!(
    UserAddCodec,
    domain = Users,
    command = UserCommand,
    variant = Add,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_ADD,
    request = UserAddRequest,
    validate = |request| validate_user_add(request),
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        (
            "name",
            FieldLimit::Range {
                min: 2,
                max: MAX_NAME_CHARS,
            },
        ),
        ("password", FieldLimit::MaxChars(MAX_PASSWORD_CHARS)),
        (
            "front_end_hash",
            FieldLimit::MaxChars(PASSWORD_FRONT_END_HASH_CHARS),
        ),
        ("front_end_salt", FieldLimit::MaxChars(PASSWORD_SALT_CHARS)),
        ("change_token", FieldLimit::MaxChars(MAX_CHANGE_TOKEN_CHARS)),
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |request| user_add_field_values(request),
    error = "Unsupported request for add codec",
);

define_request_codec!(
    UserChangeCodec,
    domain = Users,
    command = UserCommand,
    variant = Change,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_CHANGE,
    request = UserChangeRequest,
    validate = |request| validate_user_change(request),
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        (
            "name",
            FieldLimit::Range {
                min: 2,
                max: MAX_NAME_CHARS,
            },
        ),
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |request| user_change_field_values(request),
    error = "Unsupported request for change codec",
);

define_request_codec!(
    UserDeleteCodec,
    domain = Users,
    command = UserCommand,
    variant = Delete,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_DELETE,
    request = UserDeleteRequest,
    validate = |request| validate_user_delete(request),
    limits = FieldLimits::new(vec![("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS))]),
    values = |request| user_delete_field_values(request),
    error = "Unsupported request for delete codec",
);

define_request_codec!(
    UserPasswordSetCodec,
    domain = Users,
    command = UserCommand,
    variant = PasswordSet,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_SET,
    request = UserPasswordSetRequest,
    validate = |request| validate_user_password_set(request),
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        ("password", FieldLimit::MaxChars(MAX_PASSWORD_CHARS)),
        (
            "front_end_hash",
            FieldLimit::MaxChars(PASSWORD_FRONT_END_HASH_CHARS),
        ),
        ("front_end_salt", FieldLimit::MaxChars(PASSWORD_SALT_CHARS)),
        ("change_token", FieldLimit::MaxChars(MAX_CHANGE_TOKEN_CHARS)),
    ]),
    values = |request| user_password_set_field_values(request),
    error = "Unsupported request for password_set codec",
);

define_request_codec!(
    UserListCodec,
    domain = Users,
    command = UserCommand,
    variant = List,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_LIST,
    request = UserListRequest,
    validate = |request| validate_user_list(request),
    limits = FieldLimits::new(Vec::new()),
    values = |_request| FieldValues::new(),
    error = "Unsupported request for list codec",
);

define_request_codec!(
    UserShowCodec,
    domain = Users,
    command = UserCommand,
    variant = Show,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_SHOW,
    request = UserShowRequest,
    validate = |request| validate_user_show(request),
    limits = FieldLimits::new(vec![("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS))]),
    values = |request| user_show_field_values(request),
    error = "Unsupported request for show codec",
);

define_request_codec!(
    UserRoleAddCodec,
    domain = Users,
    command = UserCommand,
    variant = RoleAdd,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_ROLE_ADD,
    request = UserRoleAddRequest,
    validate = |request| validate_user_role_add(request),
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |request| user_role_field_values(&request.email, &request.role),
    error = "Unsupported request for role_add codec",
);

define_request_codec!(
    UserRoleRemoveCodec,
    domain = Users,
    command = UserCommand,
    variant = RoleRemove,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_ROLE_REMOVE,
    request = UserRoleRemoveRequest,
    validate = |request| validate_user_role_remove(request),
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |request| user_role_field_values(&request.email, &request.role),
    error = "Unsupported request for role_remove codec",
);

define_request_codec!(
    UserRolesListCodec,
    domain = Users,
    command = UserCommand,
    variant = RolesList,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_ROLES_LIST,
    request = UserRolesListRequest,
    validate = |request| validate_user_roles_list(request),
    limits = FieldLimits::new(Vec::new()),
    values = |_request| FieldValues::new(),
    error = "Unsupported request for roles_list codec",
);

define_request_codec!(
    UserPasswordSaltCodec,
    domain = Users,
    command = UserCommand,
    variant = PasswordSalt,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_SALT,
    request = UserPasswordSaltRequest,
    validate = |request| validate_user_password_salt(request),
    limits = FieldLimits::new(vec![("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS))]),
    values = |request| user_password_salt_field_values(request),
    error = "Unsupported request for password_salt codec",
);

define_request_codec!(
    UserPasswordValidateCodec,
    domain = Users,
    command = UserCommand,
    variant = PasswordValidate,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_VALIDATE,
    request = UserPasswordValidateRequest,
    validate = |request| validate_user_password_validate(request),
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        (
            "front_end_hash",
            FieldLimit::MaxChars(PASSWORD_FRONT_END_HASH_CHARS),
        ),
    ]),
    values = |request| user_password_validate_field_values(request),
    error = "Unsupported request for password_validate codec",
);

define_request_codec!(
    UserPasswordUpdateCodec,
    domain = Users,
    command = UserCommand,
    variant = PasswordUpdate,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_UPDATE,
    request = UserPasswordUpdateRequest,
    validate = |request| validate_user_password_update(request),
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        (
            "current_front_end_hash",
            FieldLimit::MaxChars(PASSWORD_FRONT_END_HASH_CHARS),
        ),
        (
            "new_front_end_hash",
            FieldLimit::MaxChars(PASSWORD_FRONT_END_HASH_CHARS),
        ),
        (
            "new_front_end_salt",
            FieldLimit::MaxChars(PASSWORD_SALT_CHARS)
        ),
        ("change_token", FieldLimit::MaxChars(MAX_CHANGE_TOKEN_CHARS)),
    ]),
    values = |request| user_password_update_field_values(request),
    error = "Unsupported request for password_update codec",
);

define_message_response_codec!(
    MessageResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    error = "Unsupported response payload for user message codec",
);

define_response_codec!(
    UserListResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_LIST_OK,
    payload = UserList,
    response = UserListResponse,
    limits = FieldLimits::new(vec![
        ("users", FieldLimit::MaxEntries(MAX_USER_COUNT)),
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        ("name", FieldLimit::MaxChars(MAX_NAME_CHARS)),
    ]),
    values = |payload| user_list_response_values(payload),
    error = "Unsupported response payload for user list codec",
);

define_response_codec!(
    UserShowResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_SHOW_OK,
    payload = UserShow,
    response = UserShowResponse,
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        ("name", FieldLimit::MaxChars(MAX_NAME_CHARS)),
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |payload| user_show_response_values(payload),
    error = "Unsupported response payload for user show codec",
);

define_response_codec!(
    UserRolesListResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_ROLES_LIST_OK,
    payload = UserRolesList,
    response = UserRolesListResponse,
    limits = FieldLimits::new(vec![
        ("roles", FieldLimit::MaxEntries(MAX_ROLE_COUNT)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |payload| user_roles_list_response_values(payload),
    error = "Unsupported response payload for roles list codec",
);

define_response_codec!(
    PasswordSaltResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_SALT_OK,
    payload = UserPasswordSalt,
    response = PasswordSaltResponse,
    limits = FieldLimits::new(vec![
        ("change_token", FieldLimit::MaxChars(MAX_CHANGE_TOKEN_CHARS)),
        (
            "current_front_end_salt",
            FieldLimit::MaxChars(PASSWORD_SALT_CHARS)
        ),
        (
            "next_front_end_salt",
            FieldLimit::MaxChars(PASSWORD_SALT_CHARS)
        ),
    ]),
    values = |payload| password_salt_response_values(payload),
    error = "Unsupported response payload for password salt codec",
);

define_response_codec!(
    PasswordValidateResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_VALIDATE_OK,
    payload = UserPasswordValidate,
    response = PasswordValidateResponse,
    limits = FieldLimits::new(vec![("valid", FieldLimit::Range { min: 0, max: 1 })]),
    values = |_payload| FieldValues::new(),
    error = "Unsupported response payload for password validate codec",
);

fn password_salt_response_values(response: &PasswordSaltResponse) -> FieldValues {
    let mut values = FieldValues::new();
    values.insert_len("change_token", response.change_token.chars().count());
    values.insert_len(
        "current_front_end_salt",
        response.current_front_end_salt.chars().count(),
    );
    values.insert_len(
        "next_front_end_salt",
        response.next_front_end_salt.chars().count(),
    );
    values
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

#[cfg(test)]
mod tests {
    use super::*;
    use nop_config::PasswordHashingParams;
    use nop_management_contract::codec::ResponseCodec;
    use nop_management_contract::core::MessageResponse;

    fn password_payload_sample() -> PasswordPayload {
        PasswordPayload::Plaintext {
            plaintext: "password".to_string(),
        }
    }

    #[test]
    fn add_request_rejects_long_email() {
        let request = UserAddRequest {
            email: "a".repeat(MAX_EMAIL_CHARS + 1),
            name: "Name".to_string(),
            password: password_payload_sample(),
            roles: vec![],
            change_token: None,
        };
        assert!(validate_user_add(&request).is_err());
    }

    #[test]
    fn add_request_rejects_invalid_email() {
        let request = UserAddRequest {
            email: "not-an-email".to_string(),
            name: "Name".to_string(),
            password: password_payload_sample(),
            roles: vec![],
            change_token: None,
        };
        assert!(validate_user_add(&request).is_err());
    }

    #[test]
    fn change_request_requires_field() {
        let request = UserChangeRequest {
            email: "user@example.com".to_string(),
            name: None,
            roles: None,
        };
        assert!(validate_user_change(&request).is_err());
    }

    #[test]
    fn roles_limit_enforced() {
        let roles = vec!["r".to_string(); MAX_ROLE_COUNT + 1];
        let request = UserAddRequest {
            email: "user@example.com".to_string(),
            name: "Name".to_string(),
            password: password_payload_sample(),
            roles,
            change_token: None,
        };
        assert!(validate_user_add(&request).is_err());
    }

    #[test]
    fn add_request_rejects_invalid_password_prehash() {
        let request = UserAddRequest {
            email: "user@example.com".to_string(),
            name: "Name".to_string(),
            password: PasswordPayload::Plaintext {
                plaintext: "".to_string(),
            },
            roles: vec![],
            change_token: None,
        };
        assert!(validate_user_add(&request).is_err());
    }

    #[test]
    fn front_end_hash_requires_exact_length() {
        let params = PasswordHashingParams::default();
        let expected_len = expected_front_end_hash_chars(&params.front_end);
        let valid_hash = "aa".repeat(expected_len / 2);
        let short_hash = "aa".repeat((expected_len / 2).saturating_sub(1));

        assert!(validate_front_end_hash_exact(&valid_hash, &params.front_end).is_ok());
        assert!(validate_front_end_hash_exact(&short_hash, &params.front_end).is_err());
    }

    #[test]
    fn front_end_salt_requires_exact_length() {
        let params = PasswordHashingParams::default();
        let expected_len = expected_front_end_salt_chars(&params.front_end);
        let valid_salt = "aa".repeat(expected_len / 2);
        let short_salt = "aa".repeat((expected_len / 2).saturating_sub(1));

        assert!(validate_front_end_salt_exact(&valid_salt, &params.front_end).is_ok());
        assert!(validate_front_end_salt_exact(&short_salt, &params.front_end).is_err());
    }

    #[test]
    fn role_charset_enforced() {
        let request = UserAddRequest {
            email: "user@example.com".to_string(),
            name: "Name".to_string(),
            password: password_payload_sample(),
            roles: vec!["invalid!".to_string()],
            change_token: None,
        };
        assert!(validate_user_add(&request).is_err());
    }

    #[test]
    fn message_response_validates_length() {
        let codec = MessageResponseCodec::new(USER_ACTION_ADD_OK);
        let response = ManagementResponse {
            domain_id: USERS_DOMAIN_ID,
            action_id: USER_ACTION_ADD_OK,
            workflow_id: 1,
            payload: ResponsePayload::Message(MessageResponse {
                message: "x".repeat(1025),
            }),
        };
        assert!(codec.validate(&response).is_err());
    }
}
