// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::wire::{OptionMap, WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use serde::{Deserialize, Serialize};

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
                writer.write_string(plaintext)?;
            }
            PasswordPayload::FrontEndHash {
                front_end_hash,
                front_end_salt,
            } => {
                writer.write_u8(1);
                writer.write_string(front_end_hash)?;
                writer.write_string(front_end_salt)?;
            }
        }
        Ok(())
    }
}

impl WireDecode for PasswordPayload {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        match reader.read_u8()? {
            0 => Ok(Self::Plaintext {
                plaintext: reader.read_string()?,
            }),
            1 => Ok(Self::FrontEndHash {
                front_end_hash: reader.read_string()?,
                front_end_salt: reader.read_string()?,
            }),
            value => Err(crate::wire::WireError::new(format!(
                "Unknown password payload kind {}",
                value
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
        writer.write_vec(&self.users, |writer, item| item.encode(writer))
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
