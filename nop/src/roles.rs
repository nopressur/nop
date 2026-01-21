// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::error::Error;
use std::fmt;

pub const ADMIN_ROLE: &str = "admin";
pub const MAX_ROLE_COUNT: usize = 64;
pub const MAX_ROLE_CHARS: usize = 64;

#[derive(Debug)]
pub struct RoleValidationError {
    message: String,
}

impl RoleValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RoleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for RoleValidationError {}

pub fn normalize_role(role: &str) -> Result<String, RoleValidationError> {
    let trimmed = role.trim();
    if trimmed.is_empty() {
        return Err(RoleValidationError::new("Role is required"));
    }
    if trimmed.chars().count() > MAX_ROLE_CHARS {
        return Err(RoleValidationError::new(format!(
            "Role must be at most {} characters",
            MAX_ROLE_CHARS
        )));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(RoleValidationError::new(format!(
            "Role '{}' contains invalid characters",
            trimmed
        )));
    }
    Ok(trimmed.to_string())
}

pub fn normalize_roles(roles: &[String]) -> Result<Vec<String>, RoleValidationError> {
    if roles.len() > MAX_ROLE_COUNT {
        return Err(RoleValidationError::new(format!(
            "Roles must be at most {} entries",
            MAX_ROLE_COUNT
        )));
    }
    let mut normalized = Vec::with_capacity(roles.len());
    for role in roles {
        normalized.push(normalize_role(role)?);
    }
    Ok(normalized)
}
