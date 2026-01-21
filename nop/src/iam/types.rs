// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DEFAULT_PASSWORD_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User {
    pub email: String,
    pub name: String,
    pub password: Option<PasswordProviderBlock>,
    pub legacy_password_hash: Option<String>,
    pub roles: Vec<String>,
    pub password_version: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasswordProviderBlock {
    pub front_end_salt: String,
    pub back_end_salt: String,
    pub stored_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PasswordRecord {
    LegacyHash(String),
    Provider(PasswordProviderBlock),
}

// Structure matching the YAML file format
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct YamlUser {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<PasswordRecord>,
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_version: Option<u32>,
}

impl YamlUser {
    pub fn into_user(self, email: String) -> User {
        let (password, legacy_password_hash) = match self.password {
            Some(PasswordRecord::Provider(block)) => (Some(block), None),
            Some(PasswordRecord::LegacyHash(hash)) => (None, Some(hash)),
            None => (None, None),
        };
        User {
            email,
            name: self.name,
            password,
            legacy_password_hash,
            roles: self.roles,
            password_version: self.password_version.unwrap_or(DEFAULT_PASSWORD_VERSION),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IamError {
    UserNotFound(String),
    ServiceNotInitialized,
    ConfigurationError(String),
    FileError(String),
    ParseError(String),
}

impl std::fmt::Display for IamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IamError::UserNotFound(email) => write!(f, "User not found: {}", email),
            IamError::ServiceNotInitialized => write!(f, "IAM service not initialized"),
            IamError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            IamError::FileError(msg) => write!(f, "File error: {}", msg),
            IamError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for IamError {}

// Mutation commands for the background thread
#[derive(Debug)]
pub enum UserMutation {
    Update {
        email: String,
        name: Option<String>,
        password: Option<PasswordProviderBlock>,
        roles: Option<Vec<String>>,
    },
    Add {
        email: String,
        name: String,
        password: PasswordProviderBlock,
        roles: Vec<String>,
    },
    Delete {
        email: String,
    },
}

#[derive(Debug)]
pub enum UserMutationResult {
    Updated,
    Added,
    Deleted,
}

// The users.yaml file structure: email -> yaml user data
pub type YamlUsersData = HashMap<String, YamlUser>;
pub type UsersData = HashMap<String, User>;
