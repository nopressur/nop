// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{Argon2Params, ValidatedUsersConfig};
use crate::iam::{
    PasswordProviderBlock, UserServices, build_password_provider_block, derive_back_end_hash,
    generate_salt_hex,
};
use crate::management::blocking::BlockingError;
use crate::management::codec::{FieldLimit, FieldLimits, FieldValues};
use crate::management::core::{
    ManagementCommand, ManagementContext, ManagementRequest, ManagementResponse,
};
use crate::management::errors::DomainResult;
use crate::management::registry::{DomainActionKey, ManagementHandler, ManagementRegistry};
use crate::management::roles::ensure_roles_exist;
use crate::management::{OptionMap, WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use crate::security;
use crate::security::{
    MAX_EMAIL_CHARS, MAX_NAME_CHARS, validate_email_field as validate_email_field_shared,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

pub const USERS_DOMAIN_ID: u32 = 1;

pub const USER_ACTION_ADD: u32 = 1;
pub const USER_ACTION_CHANGE: u32 = 2;
pub const USER_ACTION_DELETE: u32 = 3;
pub const USER_ACTION_PASSWORD_SET: u32 = 4;
pub const USER_ACTION_LIST: u32 = 5;
pub const USER_ACTION_SHOW: u32 = 6;
pub const USER_ACTION_ROLE_ADD: u32 = 7;
pub const USER_ACTION_ROLE_REMOVE: u32 = 8;
pub const USER_ACTION_ROLES_LIST: u32 = 9;
pub const USER_ACTION_PASSWORD_SALT: u32 = 10;
pub const USER_ACTION_PASSWORD_VALIDATE: u32 = 11;
pub const USER_ACTION_PASSWORD_UPDATE: u32 = 12;

pub const USER_ACTION_ADD_OK: u32 = 101;
pub const USER_ACTION_ADD_ERR: u32 = 102;
pub const USER_ACTION_CHANGE_OK: u32 = 201;
pub const USER_ACTION_CHANGE_ERR: u32 = 202;
pub const USER_ACTION_DELETE_OK: u32 = 301;
pub const USER_ACTION_DELETE_ERR: u32 = 302;
pub const USER_ACTION_PASSWORD_SET_OK: u32 = 401;
pub const USER_ACTION_PASSWORD_SET_ERR: u32 = 402;
pub const USER_ACTION_LIST_OK: u32 = 501;
pub const USER_ACTION_LIST_ERR: u32 = 502;
pub const USER_ACTION_SHOW_OK: u32 = 601;
pub const USER_ACTION_SHOW_ERR: u32 = 602;
pub const USER_ACTION_ROLE_ADD_OK: u32 = 701;
pub const USER_ACTION_ROLE_ADD_ERR: u32 = 702;
pub const USER_ACTION_ROLE_REMOVE_OK: u32 = 801;
pub const USER_ACTION_ROLE_REMOVE_ERR: u32 = 802;
pub const USER_ACTION_ROLES_LIST_OK: u32 = 901;
pub const USER_ACTION_ROLES_LIST_ERR: u32 = 902;
pub const USER_ACTION_PASSWORD_SALT_OK: u32 = 1001;
pub const USER_ACTION_PASSWORD_SALT_ERR: u32 = 1002;
pub const USER_ACTION_PASSWORD_VALIDATE_OK: u32 = 1101;
pub const USER_ACTION_PASSWORD_VALIDATE_ERR: u32 = 1102;
pub const USER_ACTION_PASSWORD_UPDATE_OK: u32 = 1201;
pub const USER_ACTION_PASSWORD_UPDATE_ERR: u32 = 1202;

const MIN_NAME_CHARS: usize = 2;
const PASSWORD_FRONT_END_HASH_CHARS: usize = 128;
const PASSWORD_SALT_CHARS: usize = 64;
const MAX_PASSWORD_CHARS: usize = 1024;
const MAX_CHANGE_TOKEN_CHARS: usize = 128;
const PASSWORD_SALT_TTL_SECONDS: u64 = 600;
const MAX_ROLE_COUNT: usize = crate::roles::MAX_ROLE_COUNT;
const MAX_ROLE_CHARS: usize = crate::roles::MAX_ROLE_CHARS;
const MAX_USER_COUNT: usize = 10000;

#[derive(Debug, Clone)]
pub enum UserCommand {
    Add(UserAddRequest),
    Change(UserChangeRequest),
    Delete(UserDeleteRequest),
    PasswordSet(UserPasswordSetRequest),
    PasswordSalt(UserPasswordSaltRequest),
    PasswordValidate(UserPasswordValidateRequest),
    PasswordUpdate(UserPasswordUpdateRequest),
    List(UserListRequest),
    Show(UserShowRequest),
    RoleAdd(UserRoleAddRequest),
    RoleRemove(UserRoleRemoveRequest),
    RolesList(UserRolesListRequest),
}

impl UserCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            UserCommand::Add(_) => USER_ACTION_ADD,
            UserCommand::Change(_) => USER_ACTION_CHANGE,
            UserCommand::Delete(_) => USER_ACTION_DELETE,
            UserCommand::PasswordSet(_) => USER_ACTION_PASSWORD_SET,
            UserCommand::PasswordSalt(_) => USER_ACTION_PASSWORD_SALT,
            UserCommand::PasswordValidate(_) => USER_ACTION_PASSWORD_VALIDATE,
            UserCommand::PasswordUpdate(_) => USER_ACTION_PASSWORD_UPDATE,
            UserCommand::List(_) => USER_ACTION_LIST,
            UserCommand::Show(_) => USER_ACTION_SHOW,
            UserCommand::RoleAdd(_) => USER_ACTION_ROLE_ADD,
            UserCommand::RoleRemove(_) => USER_ACTION_ROLE_REMOVE,
            UserCommand::RolesList(_) => USER_ACTION_ROLES_LIST,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAddRequest {
    pub email: String,
    pub name: String,
    pub password: PasswordPayload,
    pub roles: Vec<String>,
    pub change_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserChangeRequest {
    pub email: String,
    pub name: Option<String>,
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDeleteRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPasswordSetRequest {
    pub email: String,
    pub password: PasswordPayload,
    pub change_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPasswordSaltRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPasswordValidateRequest {
    pub email: String,
    pub front_end_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPasswordUpdateRequest {
    pub email: String,
    pub current_front_end_hash: String,
    pub new_front_end_hash: String,
    pub new_front_end_salt: String,
    pub change_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserShowRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleAddRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleRemoveRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRolesListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PasswordPayload {
    Plaintext {
        plaintext: String,
    },
    FrontEndHash {
        front_end_hash: String,
        front_end_salt: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    pub email: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListResponse {
    pub users: Vec<UserSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserShowResponse {
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRolesListResponse {
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordSaltResponse {
    pub change_token: String,
    pub current_front_end_salt: String,
    pub next_front_end_salt: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordValidateResponse {
    pub valid: bool,
}

impl WireEncode for UserAddRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.change_token.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.email)?;
        writer.write_string(&self.name)?;
        self.password.encode(writer)?;
        writer.write_vec(&self.roles, |writer, role| writer.write_string(role))?;
        if let Some(value) = &self.change_token {
            writer.write_string(value)?;
        }
        Ok(())
    }
}

impl WireDecode for UserAddRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        Ok(Self {
            email: reader.read_string()?,
            name: reader.read_string()?,
            password: PasswordPayload::decode(reader)?,
            roles: reader.read_vec(|reader| reader.read_string())?,
            change_token: if flags[0] {
                Some(reader.read_string()?)
            } else {
                None
            },
        })
    }
}

impl WireEncode for UserChangeRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.name.is_some(), self.roles.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.email)?;
        if let Some(value) = &self.name {
            writer.write_string(value)?;
        }
        if let Some(value) = &self.roles {
            writer.write_vec(value, |writer, role| writer.write_string(role))?;
        }
        Ok(())
    }
}

impl WireDecode for UserChangeRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 2)?;
        let email = reader.read_string()?;
        let name = if flags[0] {
            Some(reader.read_string()?)
        } else {
            None
        };
        let roles = if flags[1] {
            Some(reader.read_vec(|reader| reader.read_string())?)
        } else {
            None
        };
        Ok(Self { email, name, roles })
    }
}

impl WireEncode for UserDeleteRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)
    }
}

impl WireDecode for UserDeleteRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
        })
    }
}

impl WireEncode for UserPasswordSetRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.change_token.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.email)?;
        self.password.encode(writer)?;
        if let Some(value) = &self.change_token {
            writer.write_string(value)?;
        }
        Ok(())
    }
}

impl WireDecode for UserPasswordSetRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        Ok(Self {
            email: reader.read_string()?,
            password: PasswordPayload::decode(reader)?,
            change_token: if flags[0] {
                Some(reader.read_string()?)
            } else {
                None
            },
        })
    }
}

impl WireEncode for UserPasswordSaltRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)
    }
}

impl WireDecode for UserPasswordSaltRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
        })
    }
}

impl WireEncode for UserPasswordValidateRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)?;
        writer.write_string(&self.front_end_hash)?;
        Ok(())
    }
}

impl WireDecode for UserPasswordValidateRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
            front_end_hash: reader.read_string()?,
        })
    }
}

impl WireEncode for UserPasswordUpdateRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)?;
        writer.write_string(&self.current_front_end_hash)?;
        writer.write_string(&self.new_front_end_hash)?;
        writer.write_string(&self.new_front_end_salt)?;
        writer.write_string(&self.change_token)?;
        Ok(())
    }
}

impl WireDecode for UserPasswordUpdateRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
            current_front_end_hash: reader.read_string()?,
            new_front_end_hash: reader.read_string()?,
            new_front_end_salt: reader.read_string()?,
            change_token: reader.read_string()?,
        })
    }
}

impl WireEncode for PasswordPayload {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        match self {
            PasswordPayload::Plaintext { plaintext } => {
                writer.write_u8(0);
                writer.write_string(plaintext)
            }
            PasswordPayload::FrontEndHash {
                front_end_hash,
                front_end_salt,
            } => {
                writer.write_u8(1);
                writer.write_string(front_end_hash)?;
                writer.write_string(front_end_salt)
            }
        }
    }
}

impl WireDecode for PasswordPayload {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let tag = reader.read_u8()?;
        match tag {
            0 => Ok(PasswordPayload::Plaintext {
                plaintext: reader.read_string()?,
            }),
            1 => Ok(PasswordPayload::FrontEndHash {
                front_end_hash: reader.read_string()?,
                front_end_salt: reader.read_string()?,
            }),
            _ => Err(crate::management::WireError::new(format!(
                "Invalid password payload tag: {}",
                tag
            ))),
        }
    }
}

impl WireEncode for UserListRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for UserListRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for UserShowRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)
    }
}

impl WireDecode for UserShowRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
        })
    }
}

impl WireEncode for UserRoleAddRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)?;
        writer.write_string(&self.role)?;
        Ok(())
    }
}

impl WireDecode for UserRoleAddRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
            role: reader.read_string()?,
        })
    }
}

impl WireEncode for UserRoleRemoveRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)?;
        writer.write_string(&self.role)?;
        Ok(())
    }
}

impl WireDecode for UserRoleRemoveRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
            role: reader.read_string()?,
        })
    }
}

impl WireEncode for UserRolesListRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for UserRolesListRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}

impl WireEncode for UserSummary {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)?;
        writer.write_string(&self.name)?;
        Ok(())
    }
}

impl WireDecode for UserSummary {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
            name: reader.read_string()?,
        })
    }
}

impl WireEncode for UserListResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_vec(&self.users, |writer, user| user.encode(writer))
    }
}

impl WireDecode for UserListResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            users: reader.read_vec(UserSummary::decode)?,
        })
    }
}

impl WireEncode for UserShowResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.email)?;
        writer.write_string(&self.name)?;
        writer.write_vec(&self.roles, |writer, role| writer.write_string(role))?;
        Ok(())
    }
}

impl WireDecode for UserShowResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            email: reader.read_string()?,
            name: reader.read_string()?,
            roles: reader.read_vec(|reader| reader.read_string())?,
        })
    }
}

impl WireEncode for UserRolesListResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_vec(&self.roles, |writer, role| writer.write_string(role))
    }
}

impl WireDecode for UserRolesListResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            roles: reader.read_vec(|reader| reader.read_string())?,
        })
    }
}

impl WireEncode for PasswordSaltResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.change_token)?;
        writer.write_string(&self.current_front_end_salt)?;
        writer.write_string(&self.next_front_end_salt)?;
        writer.write_u64(self.expires_in_seconds);
        Ok(())
    }
}

impl WireDecode for PasswordSaltResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            change_token: reader.read_string()?,
            current_front_end_salt: reader.read_string()?,
            next_front_end_salt: reader.read_string()?,
            expires_in_seconds: reader.read_u64()?,
        })
    }
}

impl WireEncode for PasswordValidateResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_bool(self.valid);
        Ok(())
    }
}

impl WireDecode for PasswordValidateResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {
            valid: reader.read_bool()?,
        })
    }
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

pub fn register(registry: &mut ManagementRegistry) -> Result<(), crate::management::RegistryError> {
    registry.register_domain(crate::management::registry::DomainDescriptor {
        name: "users",
        id: USERS_DOMAIN_ID,
        actions: vec![
            crate::management::registry::ActionDescriptor {
                name: "add",
                id: USER_ACTION_ADD,
            },
            crate::management::registry::ActionDescriptor {
                name: "change",
                id: USER_ACTION_CHANGE,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete",
                id: USER_ACTION_DELETE,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_set",
                id: USER_ACTION_PASSWORD_SET,
            },
            crate::management::registry::ActionDescriptor {
                name: "list",
                id: USER_ACTION_LIST,
            },
            crate::management::registry::ActionDescriptor {
                name: "show",
                id: USER_ACTION_SHOW,
            },
            crate::management::registry::ActionDescriptor {
                name: "role_add",
                id: USER_ACTION_ROLE_ADD,
            },
            crate::management::registry::ActionDescriptor {
                name: "role_remove",
                id: USER_ACTION_ROLE_REMOVE,
            },
            crate::management::registry::ActionDescriptor {
                name: "roles_list",
                id: USER_ACTION_ROLES_LIST,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_salt",
                id: USER_ACTION_PASSWORD_SALT,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_validate",
                id: USER_ACTION_PASSWORD_VALIDATE,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_update",
                id: USER_ACTION_PASSWORD_UPDATE,
            },
            crate::management::registry::ActionDescriptor {
                name: "add_ok",
                id: USER_ACTION_ADD_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "add_err",
                id: USER_ACTION_ADD_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "change_ok",
                id: USER_ACTION_CHANGE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "change_err",
                id: USER_ACTION_CHANGE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_ok",
                id: USER_ACTION_DELETE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "delete_err",
                id: USER_ACTION_DELETE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_set_ok",
                id: USER_ACTION_PASSWORD_SET_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_set_err",
                id: USER_ACTION_PASSWORD_SET_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_salt_ok",
                id: USER_ACTION_PASSWORD_SALT_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_salt_err",
                id: USER_ACTION_PASSWORD_SALT_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_validate_ok",
                id: USER_ACTION_PASSWORD_VALIDATE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_validate_err",
                id: USER_ACTION_PASSWORD_VALIDATE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_update_ok",
                id: USER_ACTION_PASSWORD_UPDATE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "password_update_err",
                id: USER_ACTION_PASSWORD_UPDATE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_ok",
                id: USER_ACTION_LIST_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "list_err",
                id: USER_ACTION_LIST_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "show_ok",
                id: USER_ACTION_SHOW_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "show_err",
                id: USER_ACTION_SHOW_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "role_add_ok",
                id: USER_ACTION_ROLE_ADD_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "role_add_err",
                id: USER_ACTION_ROLE_ADD_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "role_remove_ok",
                id: USER_ACTION_ROLE_REMOVE_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "role_remove_err",
                id: USER_ACTION_ROLE_REMOVE_ERR,
            },
            crate::management::registry::ActionDescriptor {
                name: "roles_list_ok",
                id: USER_ACTION_ROLES_LIST_OK,
            },
            crate::management::registry::ActionDescriptor {
                name: "roles_list_err",
                id: USER_ACTION_ROLES_LIST_ERR,
            },
        ],
    })?;

    let handler: ManagementHandler = Arc::new(|request, context| {
        Box::pin(async move { handle_users_request(request, context).await })
    });

    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_CHANGE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_DELETE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SET),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_SALT),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_VALIDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_PASSWORD_UPDATE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_LIST),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_SHOW),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ROLE_ADD),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ROLE_REMOVE),
        handler.clone(),
    )?;
    registry.register_handler(
        DomainActionKey::new(USERS_DOMAIN_ID, USER_ACTION_ROLES_LIST),
        handler,
    )?;

    register_request_codecs!(
        registry,
        [
            UserAddCodec,
            UserChangeCodec,
            UserDeleteCodec,
            UserPasswordSetCodec,
            UserPasswordSaltCodec,
            UserPasswordValidateCodec,
            UserPasswordUpdateCodec,
            UserListCodec,
            UserShowCodec,
            UserRoleAddCodec,
            UserRoleRemoveCodec,
            UserRolesListCodec
        ]
    );

    register_response_codecs!(
        registry,
        [
            MessageResponseCodec::new(USER_ACTION_ADD_OK),
            MessageResponseCodec::new(USER_ACTION_ADD_ERR),
            MessageResponseCodec::new(USER_ACTION_CHANGE_OK),
            MessageResponseCodec::new(USER_ACTION_CHANGE_ERR),
            MessageResponseCodec::new(USER_ACTION_DELETE_OK),
            MessageResponseCodec::new(USER_ACTION_DELETE_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_SET_OK),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_SET_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_UPDATE_OK),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_UPDATE_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_SALT_ERR),
            MessageResponseCodec::new(USER_ACTION_PASSWORD_VALIDATE_ERR),
            MessageResponseCodec::new(USER_ACTION_LIST_ERR),
            MessageResponseCodec::new(USER_ACTION_SHOW_ERR),
            MessageResponseCodec::new(USER_ACTION_ROLE_ADD_OK),
            MessageResponseCodec::new(USER_ACTION_ROLE_ADD_ERR),
            MessageResponseCodec::new(USER_ACTION_ROLE_REMOVE_OK),
            MessageResponseCodec::new(USER_ACTION_ROLE_REMOVE_ERR),
            MessageResponseCodec::new(USER_ACTION_ROLES_LIST_ERR),
            UserListResponseCodec,
            UserShowResponseCodec,
            UserRolesListResponseCodec,
            PasswordSaltResponseCodec,
            PasswordValidateResponseCodec
        ]
    );

    Ok(())
}

async fn handle_users_request(
    request: ManagementRequest,
    context: Arc<ManagementContext>,
) -> DomainResult<ManagementResponse> {
    let response = match request.command {
        ManagementCommand::Users(UserCommand::Add(payload)) => {
            handle_add(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::Change(payload)) => {
            handle_change(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::Delete(payload)) => {
            handle_delete(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::PasswordSet(payload)) => {
            handle_password_set(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::PasswordSalt(payload)) => {
            handle_password_salt(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::PasswordValidate(payload)) => {
            handle_password_validate(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::PasswordUpdate(payload)) => {
            handle_password_update(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::List(payload)) => {
            handle_list(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::Show(payload)) => {
            handle_show(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::RoleAdd(payload)) => {
            handle_role_add(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::RoleRemove(payload)) => {
            handle_role_remove(payload, request.workflow_id, &context).await
        }
        ManagementCommand::Users(UserCommand::RolesList(payload)) => {
            handle_roles_list(payload, request.workflow_id, &context).await
        }
        _ => response_err(
            USER_ACTION_CHANGE_ERR,
            request.workflow_id,
            "Invalid user command",
        ),
    };

    Ok(response)
}

async fn handle_add(
    payload: UserAddRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_ADD_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ADD_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_ADD_ERR, workflow_id, &err),
    };
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
    let password_block = match build_password_block(
        context,
        user_services.as_ref(),
        &email,
        password,
        change_token,
    )
    .await
    {
        Ok(block) => block,
        Err(err) => return response_err(USER_ACTION_ADD_ERR, workflow_id, &err),
    };

    match user_services
        .add_user(&email, &sanitized_name, password_block, roles)
        .await
    {
        Ok(_) => response_ok(USER_ACTION_ADD_OK, workflow_id, "User added successfully"),
        Err(err) => response_err(USER_ACTION_ADD_ERR, workflow_id, &err.to_string()),
    }
}

async fn handle_change(
    payload: UserChangeRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err),
    };
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

    match user_services
        .update_user_complete(&email, sanitized_name.as_deref(), None, roles)
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_CHANGE_OK,
            workflow_id,
            "User updated successfully",
        ),
        Err(err) => response_err(USER_ACTION_CHANGE_ERR, workflow_id, &err.to_string()),
    }
}

async fn handle_delete(
    payload: UserDeleteRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_DELETE_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_DELETE_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_DELETE_ERR, workflow_id, &err),
    };
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => return response_err(USER_ACTION_DELETE_ERR, workflow_id, &err.to_string()),
    };

    match user_services.delete_user(&email).await {
        Ok(_) => response_ok(
            USER_ACTION_DELETE_OK,
            workflow_id,
            "User deleted successfully",
        ),
        Err(err) => response_err(USER_ACTION_DELETE_ERR, workflow_id, &err.to_string()),
    }
}

async fn handle_password_set(
    payload: UserPasswordSetRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err),
    };
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
    let password_block = match build_password_block(
        context,
        user_services.as_ref(),
        &email,
        password,
        change_token,
    )
    .await
    {
        Ok(block) => block,
        Err(err) => return response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err),
    };

    match user_services
        .update_user_complete(&email, None, Some(password_block), None)
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_PASSWORD_SET_OK,
            workflow_id,
            "Password updated successfully",
        ),
        Err(err) => response_err(USER_ACTION_PASSWORD_SET_ERR, workflow_id, &err.to_string()),
    }
}

async fn handle_password_salt(
    payload: UserPasswordSaltRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err),
    };
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
        }
    };
    let params = user_services.password_params().clone();
    let front_end_len = params.front_end.salt_len;
    let current_front_end_salt = match user_services.get_user(&email) {
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
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
        }
    };
    let next_front_end_salt = match generate_salt_hex(front_end_len) {
        Ok(salt) => salt,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, &err.to_string());
        }
    };
    let (change_token, _token) = match user_services
        .password_change_store()
        .issue(
            &email,
            next_front_end_salt.clone(),
            Duration::from_secs(PASSWORD_SALT_TTL_SECONDS),
        )
        .await
    {
        Ok(value) => value,
        Err(err) => {
            return response_err(USER_ACTION_PASSWORD_SALT_ERR, workflow_id, err.message());
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

async fn handle_password_validate(
    payload: UserPasswordValidateRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(
            USER_ACTION_PASSWORD_VALIDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_VALIDATE_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_PASSWORD_VALIDATE_ERR, workflow_id, &err),
    };
    if let Err(err) = validate_front_end_hash_exact(
        &payload.front_end_hash,
        &user_services.password_params().front_end,
    ) {
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
    let user_services = user_services.clone();
    let valid = match context
        .blocking_pool
        .run_blocking("validate password", move || {
            user_services
                .password_validate(&email, &front_end_hash)
                .map_err(|err| err.to_string())
        })
        .await
    {
        Ok(result) => match result {
            Ok(valid) => valid,
            Err(err) => {
                return response_err(USER_ACTION_PASSWORD_VALIDATE_ERR, workflow_id, &err);
            }
        },
        Err(err) => {
            return response_err(
                USER_ACTION_PASSWORD_VALIDATE_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };

    response_password_validate(workflow_id, PasswordValidateResponse { valid })
}

async fn handle_password_update(
    payload: UserPasswordUpdateRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err),
    };
    let UserPasswordUpdateRequest {
        email: raw_email,
        current_front_end_hash,
        new_front_end_hash,
        new_front_end_salt,
        change_token,
    } = payload;
    if let Err(err) = validate_front_end_hash_exact(
        &current_front_end_hash,
        &user_services.password_params().front_end,
    ) {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(err) = validate_front_end_hash_exact(
        &new_front_end_hash,
        &user_services.password_params().front_end,
    ) {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }
    if let Err(err) = validate_front_end_salt_exact(
        &new_front_end_salt,
        &user_services.password_params().front_end,
    ) {
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
    if let Err(err) = validate_change_token_payload(
        user_services.as_ref(),
        &email,
        &change_token,
        &new_front_end_salt,
    )
    .await
    {
        return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err);
    }

    let user_services_for_validate = user_services.clone();
    let email_for_validate = email.clone();
    let valid = match context
        .blocking_pool
        .run_blocking("validate password", move || {
            user_services_for_validate
                .password_validate(&email_for_validate, &current_front_end_hash)
                .map_err(|err| err.to_string())
        })
        .await
    {
        Ok(result) => match result {
            Ok(valid) => valid,
            Err(err) => {
                return response_err(USER_ACTION_PASSWORD_UPDATE_ERR, workflow_id, &err);
            }
        },
        Err(err) => {
            return response_err(
                USER_ACTION_PASSWORD_UPDATE_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    if !valid {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            "Current password is invalid",
        );
    }

    let params = user_services.password_params().clone();
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
        .blocking_pool
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
            return response_err(
                USER_ACTION_PASSWORD_UPDATE_ERR,
                workflow_id,
                &err.to_string(),
            );
        }
    };
    let password_block = PasswordProviderBlock {
        front_end_salt: new_front_end_salt,
        back_end_salt,
        stored_hash,
    };

    if let Err(err) = user_services
        .update_user_complete(&email, None, Some(password_block), None)
        .await
    {
        return response_err(
            USER_ACTION_PASSWORD_UPDATE_ERR,
            workflow_id,
            &err.to_string(),
        );
    }

    if let Err(err) = user_services
        .password_change_store()
        .invalidate(&change_token)
        .await
    {
        log::warn!("Password change token invalidate failed: {}", err.message());
    }

    response_ok(
        USER_ACTION_PASSWORD_UPDATE_OK,
        workflow_id,
        "Password updated successfully",
    )
}

async fn handle_list(
    _payload: UserListRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_LIST_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_LIST_ERR, workflow_id, &err),
    };
    let users = match user_services.list_users() {
        Ok(users) => users,
        Err(err) => return response_err(USER_ACTION_LIST_ERR, workflow_id, &err.to_string()),
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

async fn handle_show(
    payload: UserShowRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_SHOW_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err),
    };
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(err) => return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
    };
    let users = match user_services.list_users() {
        Ok(users) => users,
        Err(err) => return response_err(USER_ACTION_SHOW_ERR, workflow_id, &err.to_string()),
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

async fn handle_role_add(
    payload: UserRoleAddRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err),
    };
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

    let users = match user_services.list_users() {
        Ok(users) => users,
        Err(err) => return response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err.to_string()),
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

    match user_services
        .update_user_complete(&email, None, None, Some(roles))
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_ROLE_ADD_OK,
            workflow_id,
            "Role added successfully",
        ),
        Err(err) => response_err(USER_ACTION_ROLE_ADD_ERR, workflow_id, &err.to_string()),
    }
}

async fn handle_role_remove(
    payload: UserRoleRemoveRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(err) = payload.validate() {
        return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err.to_string());
    }
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &message);
    }
    let user_services = match get_user_services(context) {
        Ok(service) => service,
        Err(err) => return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err),
    };
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

    let users = match user_services.list_users() {
        Ok(users) => users,
        Err(err) => {
            return response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err.to_string());
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

    match user_services
        .update_user_complete(&email, None, None, Some(roles))
        .await
    {
        Ok(_) => response_ok(
            USER_ACTION_ROLE_REMOVE_OK,
            workflow_id,
            "Role removed successfully",
        ),
        Err(err) => response_err(USER_ACTION_ROLE_REMOVE_ERR, workflow_id, &err.to_string()),
    }
}

async fn handle_roles_list(
    _payload: UserRolesListRequest,
    workflow_id: u32,
    context: &ManagementContext,
) -> ManagementResponse {
    if let Err(message) = ensure_local_auth(context) {
        return response_err(USER_ACTION_ROLES_LIST_ERR, workflow_id, &message);
    }
    let roles = match context.role_store.snapshot() {
        Ok(roles) => roles,
        Err(err) => return response_err(USER_ACTION_ROLES_LIST_ERR, workflow_id, &err.to_string()),
    };
    response_roles_list(workflow_id, roles.into_iter().collect())
}

fn ensure_local_auth(context: &ManagementContext) -> Result<(), String> {
    match &context.config.users {
        ValidatedUsersConfig::Local(_) => Ok(()),
        ValidatedUsersConfig::Oidc(_) => {
            Err("User management requires local authentication".to_string())
        }
    }
}

fn get_user_services(context: &ManagementContext) -> Result<Arc<UserServices>, String> {
    context
        .user_services
        .as_ref()
        .cloned()
        .ok_or_else(|| "User services are not available".to_string())
}

async fn build_password_block(
    context: &ManagementContext,
    user_services: &UserServices,
    email: &str,
    payload: PasswordPayload,
    change_token: Option<String>,
) -> Result<PasswordProviderBlock, String> {
    let params = user_services.password_params().clone();
    match payload {
        PasswordPayload::Plaintext { plaintext } => {
            let params = params.clone();
            context
                .blocking_pool
                .run_blocking("hash password", move || {
                    build_password_provider_block(&plaintext, &params)
                        .map_err(|err| err.to_string())
                })
                .await
                .map_err(map_blocking_error)?
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
            validate_change_token_payload(user_services, email, &change_token, &front_end_salt)
                .await?;
            let back_end_salt =
                generate_salt_hex(params.back_end.salt_len).map_err(|err| err.to_string())?;
            let back_end_salt_for_hash = back_end_salt.clone();
            let params_back_end = params.back_end.clone();
            let stored_hash = context
                .blocking_pool
                .run_blocking("derive password hash", move || {
                    derive_back_end_hash(&front_end_hash, &back_end_salt_for_hash, &params_back_end)
                        .map_err(|err| err.to_string())
                })
                .await
                .map_err(map_blocking_error)??;
            Ok(PasswordProviderBlock {
                front_end_salt,
                back_end_salt,
                stored_hash,
            })
        }
    }
}

async fn validate_change_token_payload(
    user_services: &UserServices,
    email: &str,
    change_token: &str,
    expected_front_end_salt: &str,
) -> Result<(), String> {
    let token = user_services
        .password_change_store()
        .get(change_token)
        .await
        .map_err(|err| err.message().to_string())?
        .ok_or_else(|| "change_token is invalid or expired".to_string())?;
    if token.email != email {
        return Err("change_token does not match user".to_string());
    }
    if token.next_front_end_salt != expected_front_end_salt {
        return Err("front_end_salt does not match change_token".to_string());
    }
    Ok(())
}

fn map_blocking_error(err: BlockingError) -> String {
    format!("Password hashing failed: {}", err)
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
        payload: crate::management::ResponsePayload::UserList(UserListResponse { users }),
    }
}

fn response_user_show(workflow_id: u32, payload: UserShowResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_SHOW_OK,
        workflow_id,
        payload: crate::management::ResponsePayload::UserShow(payload),
    }
}

fn response_roles_list(workflow_id: u32, roles: Vec<String>) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_ROLES_LIST_OK,
        workflow_id,
        payload: crate::management::ResponsePayload::UserRolesList(UserRolesListResponse { roles }),
    }
}

fn response_password_salt(workflow_id: u32, payload: PasswordSaltResponse) -> ManagementResponse {
    ManagementResponse {
        domain_id: USERS_DOMAIN_ID,
        action_id: USER_ACTION_PASSWORD_SALT_OK,
        workflow_id,
        payload: crate::management::ResponsePayload::UserPasswordSalt(payload),
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
        payload: crate::management::ResponsePayload::UserPasswordValidate(payload),
    }
}

impl UserAddRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        validate_name(&self.name)?;
        validate_password_payload(&self.password)?;
        validate_roles(&self.roles)?;
        validate_change_token(self.change_token.as_ref())?;
        Ok(())
    }
}

impl UserChangeRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        if self.name.is_none() && self.roles.is_none() {
            return Err(UserValidationError::new(
                "User change requires --name, --roles, or --clear-roles",
            ));
        }
        if let Some(name) = &self.name {
            validate_name(name)?;
        }
        if let Some(roles) = &self.roles {
            validate_roles(roles)?;
        }
        Ok(())
    }
}

impl UserDeleteRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)
    }
}

impl UserPasswordSetRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        validate_password_payload(&self.password)?;
        validate_change_token(self.change_token.as_ref())?;
        Ok(())
    }
}

impl UserPasswordSaltRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        Ok(())
    }
}

impl UserPasswordValidateRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        validate_front_end_hash(&self.front_end_hash)?;
        Ok(())
    }
}

impl UserPasswordUpdateRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        validate_front_end_hash(&self.current_front_end_hash)?;
        validate_front_end_hash(&self.new_front_end_hash)?;
        validate_front_end_salt(&self.new_front_end_salt)?;
        validate_change_token(Some(&self.change_token))?;
        Ok(())
    }
}

impl UserListRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        Ok(())
    }
}

impl UserShowRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)
    }
}

impl UserRoleAddRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        validate_role(&self.role)?;
        Ok(())
    }
}

impl UserRoleRemoveRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        validate_email_field(&self.email)?;
        validate_role(&self.role)?;
        Ok(())
    }
}

impl UserRolesListRequest {
    fn validate(&self) -> Result<(), UserValidationError> {
        Ok(())
    }
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
    security::validate_and_sanitize_user_name(name).map_err(UserValidationError::new)
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
    validate_hex_field("front_end_hash", hash, PASSWORD_FRONT_END_HASH_CHARS)
}

fn validate_front_end_salt(salt: &str) -> Result<(), UserValidationError> {
    validate_hex_field("front_end_salt", salt, PASSWORD_SALT_CHARS)
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
    crate::iam::validate_hex_field("front_end_hash", hash, expected_len)
        .map_err(|err| UserValidationError::new(err.to_string()))
}

fn validate_front_end_salt_exact(
    salt: &str,
    params: &Argon2Params,
) -> Result<(), UserValidationError> {
    let expected_len = expected_front_end_salt_chars(params);
    crate::iam::validate_hex_field("front_end_salt", salt, expected_len)
        .map_err(|err| UserValidationError::new(err.to_string()))
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

fn validate_hex_field(
    label: &str,
    value: &str,
    max_chars: usize,
) -> Result<(), UserValidationError> {
    if value.is_empty() {
        return Err(UserValidationError::new(format!("{} is required", label)));
    }
    let char_count = value.chars().count();
    if char_count > max_chars {
        return Err(UserValidationError::new(format!(
            "{} must be at most {} characters",
            label, max_chars
        )));
    }
    if !char_count.is_multiple_of(2) {
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

fn validate_roles(roles: &[String]) -> Result<(), UserValidationError> {
    normalize_roles(roles).map(|_| ())
}

fn normalize_roles(roles: &[String]) -> Result<Vec<String>, UserValidationError> {
    crate::roles::normalize_roles(roles).map_err(|err| UserValidationError::new(err.to_string()))
}

fn normalize_role(role: &str) -> Result<String, UserValidationError> {
    crate::roles::normalize_role(role).map_err(|err| UserValidationError::new(err.to_string()))
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
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        (
            "name",
            FieldLimit::Range {
                min: MIN_NAME_CHARS,
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
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        (
            "name",
            FieldLimit::Range {
                min: MIN_NAME_CHARS,
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
    error = "Unsupported request for password set codec",
);

define_request_codec!(
    UserPasswordSaltCodec,
    domain = Users,
    command = UserCommand,
    variant = PasswordSalt,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_SALT,
    request = UserPasswordSaltRequest,
    limits = FieldLimits::new(vec![("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS))]),
    values = |request| user_password_salt_field_values(request),
    error = "Unsupported request for password salt codec",
);

define_request_codec!(
    UserPasswordValidateCodec,
    domain = Users,
    command = UserCommand,
    variant = PasswordValidate,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_VALIDATE,
    request = UserPasswordValidateRequest,
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        (
            "front_end_hash",
            FieldLimit::MaxChars(PASSWORD_FRONT_END_HASH_CHARS),
        ),
    ]),
    values = |request| user_password_validate_field_values(request),
    error = "Unsupported request for password validate codec",
);

define_request_codec!(
    UserPasswordUpdateCodec,
    domain = Users,
    command = UserCommand,
    variant = PasswordUpdate,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_UPDATE,
    request = UserPasswordUpdateRequest,
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
            FieldLimit::MaxChars(PASSWORD_SALT_CHARS),
        ),
        ("change_token", FieldLimit::MaxChars(MAX_CHANGE_TOKEN_CHARS)),
    ]),
    values = |request| user_password_update_field_values(request),
    error = "Unsupported request for password update codec",
);

define_request_codec!(
    UserListCodec,
    domain = Users,
    command = UserCommand,
    variant = List,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_LIST,
    request = UserListRequest,
    limits = FieldLimits::new(vec![]),
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
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |request| user_role_field_values(&request.email, &request.role),
    error = "Unsupported request for role add codec",
);

define_request_codec!(
    UserRoleRemoveCodec,
    domain = Users,
    command = UserCommand,
    variant = RoleRemove,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_ROLE_REMOVE,
    request = UserRoleRemoveRequest,
    limits = FieldLimits::new(vec![
        ("email", FieldLimit::MaxChars(MAX_EMAIL_CHARS)),
        ("role", FieldLimit::MaxChars(MAX_ROLE_CHARS)),
    ]),
    values = |request| user_role_field_values(&request.email, &request.role),
    error = "Unsupported request for role remove codec",
);

define_request_codec!(
    UserRolesListCodec,
    domain = Users,
    command = UserCommand,
    variant = RolesList,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_ROLES_LIST,
    request = UserRolesListRequest,
    limits = FieldLimits::new(vec![]),
    values = |_request| FieldValues::new(),
    error = "Unsupported request for roles list codec",
);

define_message_response_codec!(
    MessageResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    error = "Unsupported response payload for message codec",
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
    error = "Unsupported response payload for list codec",
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
    error = "Unsupported response payload for show codec",
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
            FieldLimit::MaxChars(PASSWORD_SALT_CHARS),
        ),
        (
            "next_front_end_salt",
            FieldLimit::MaxChars(PASSWORD_SALT_CHARS)
        ),
    ]),
    values = |payload| {
        let mut values = FieldValues::new();
        values.insert_len("change_token", payload.change_token.chars().count());
        values.insert_len(
            "current_front_end_salt",
            payload.current_front_end_salt.chars().count(),
        );
        values.insert_len(
            "next_front_end_salt",
            payload.next_front_end_salt.chars().count(),
        );
        values
    },
    error = "Unsupported response payload for password salt codec",
);

define_response_codec!(
    PasswordValidateResponseCodec,
    domain_id = USERS_DOMAIN_ID,
    action_id = USER_ACTION_PASSWORD_VALIDATE_OK,
    payload = UserPasswordValidate,
    response = PasswordValidateResponse,
    limits = FieldLimits::new(vec![]),
    values = |_payload| FieldValues::new(),
    error = "Unsupported response payload for password validate codec",
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PasswordHashingParams;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig,
        UploadConfig, ValidatedConfig, test_local_users_config, test_server_list,
    };
    use crate::iam::{MemoryUserStore, User, UserServices};
    use crate::management::MessageResponse;
    use crate::management::codec::ResponseCodec;
    use crate::management::core::ResponsePayload;
    use crate::util::test_fixtures::TestFixtureRoot;

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
        }
    }

    fn build_context(
        fixture: &TestFixtureRoot,
        users: Vec<User>,
    ) -> (ManagementContext, Arc<UserServices>) {
        let config = build_test_config();
        let store = Arc::new(MemoryUserStore::from_users(users));
        let user_services = UserServices::new_with_store(&config, store).expect("user services");
        let user_services = Arc::new(user_services);
        let runtime_paths = fixture.runtime_paths().expect("runtime paths");
        std::fs::write(
            runtime_paths.state_sys_dir.join("roles.yaml"),
            "- admin\n- editor\n",
        )
        .expect("write roles");
        let context = ManagementContext::from_components_with_user_services(
            runtime_paths.root.clone(),
            Arc::new(config),
            runtime_paths,
            Some(user_services.clone()),
        )
        .expect("context");
        (context, user_services)
    }

    fn password_payload_sample() -> PasswordPayload {
        PasswordPayload::Plaintext {
            plaintext: "password".to_string(),
        }
    }

    fn dummy_password_block() -> PasswordProviderBlock {
        PasswordProviderBlock {
            front_end_salt: "00aa00bb00cc00dd".to_string(),
            back_end_salt: "1122334455667788".to_string(),
            stored_hash: "dummy-hash".to_string(),
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
        assert!(request.validate().is_err());
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
        assert!(request.validate().is_err());
    }

    #[test]
    fn change_request_requires_field() {
        let request = UserChangeRequest {
            email: "user@example.com".to_string(),
            name: None,
            roles: None,
        };
        assert!(request.validate().is_err());
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
        assert!(request.validate().is_err());
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
        assert!(request.validate().is_err());
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
        assert!(request.validate().is_err());
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

    #[tokio::test]
    async fn list_returns_user_summaries() {
        let fixture = TestFixtureRoot::new_unique("users-list").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User One".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: 1,
        };
        let (context, _user_services) = build_context(&fixture, vec![user]);
        let connection_id = crate::management::next_connection_id();

        let request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::List(UserListRequest {})),
        };
        let response = handle_users_request(request, Arc::new(context))
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        match response.payload {
            ResponsePayload::UserList(payload) => {
                assert_eq!(payload.users.len(), 1);
                assert_eq!(payload.users[0].email, "user@example.com");
                assert_eq!(payload.users[0].name, "User One");
            }
            _ => panic!("Expected user list response"),
        }
    }

    #[tokio::test]
    async fn show_returns_user_details() {
        let fixture = TestFixtureRoot::new_unique("users-show").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User Two".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["editor".to_string()],
            password_version: 1,
        };
        let (context, _user_services) = build_context(&fixture, vec![user]);
        let connection_id = crate::management::next_connection_id();

        let request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::Show(UserShowRequest {
                email: "USER@example.com".to_string(),
            })),
        };
        let response = handle_users_request(request, Arc::new(context))
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        match response.payload {
            ResponsePayload::UserShow(payload) => {
                assert_eq!(payload.email, "user@example.com");
                assert_eq!(payload.name, "User Two");
                assert_eq!(payload.roles, vec!["editor"]);
            }
            _ => panic!("Expected user show response"),
        }
    }

    #[tokio::test]
    async fn roles_list_returns_roles() {
        let fixture = TestFixtureRoot::new_unique("users-roles-list").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User Three".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["editor".to_string()],
            password_version: 1,
        };
        let (context, _user_services) = build_context(&fixture, vec![user]);
        let connection_id = crate::management::next_connection_id();

        let request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::RolesList(UserRolesListRequest {})),
        };
        let response = handle_users_request(request, Arc::new(context))
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        match response.payload {
            ResponsePayload::UserRolesList(payload) => {
                assert!(payload.roles.contains(&"admin".to_string()));
                assert!(payload.roles.contains(&"editor".to_string()));
            }
            _ => panic!("Expected roles list response"),
        }
    }

    #[tokio::test]
    async fn role_add_and_remove_update_user() {
        let fixture = TestFixtureRoot::new_unique("users-role-update").unwrap();
        fixture.init_runtime_layout().unwrap();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User Four".to_string(),
            password: Some(dummy_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: 1,
        };
        let (context, user_services) = build_context(&fixture, vec![user]);
        let context = Arc::new(context);
        let connection_id = crate::management::next_connection_id();

        let add_request = ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Users(UserCommand::RoleAdd(UserRoleAddRequest {
                email: "user@example.com".to_string(),
                role: "editor".to_string(),
            })),
        };
        handle_users_request(add_request, context.clone())
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        let users = user_services.list_users().expect("users");
        let updated = users
            .iter()
            .find(|user| user.email == "user@example.com")
            .expect("user");
        assert!(updated.roles.contains(&"editor".to_string()));

        let remove_request = ManagementRequest {
            workflow_id: 2,
            connection_id,
            command: ManagementCommand::Users(UserCommand::RoleRemove(UserRoleRemoveRequest {
                email: "user@example.com".to_string(),
                role: "editor".to_string(),
            })),
        };
        handle_users_request(remove_request, context)
            .await
            .unwrap_or_else(|err| panic!("{}", err));

        let users = user_services.list_users().expect("users");
        let updated = users
            .iter()
            .find(|user| user.email == "user@example.com")
            .expect("user");
        assert!(!updated.roles.contains(&"editor".to_string()));
    }
}
