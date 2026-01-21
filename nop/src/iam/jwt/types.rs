// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use serde::{Deserialize, Serialize};

use crate::iam::types::DEFAULT_PASSWORD_VERSION;

fn default_password_version() -> u32 {
    DEFAULT_PASSWORD_VERSION
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,         // Subject (user email)
    pub name: String,        // User's full name
    pub groups: Vec<String>, // User groups/roles
    pub iat: i64,            // Issued at
    pub exp: i64,            // Expiration
    pub iss: String,         // Issuer
    pub aud: String,         // Audience
    pub jti: String,         // JWT ID
    #[serde(default = "default_password_version")]
    pub password_version: u32, // Bumped on password change to revoke old tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn claims_defaults_password_version() {
        let claims: Claims = serde_json::from_value(json!({
            "sub": "user@example.com",
            "name": "Example User",
            "groups": [],
            "iat": 1700000000,
            "exp": 1700003600,
            "iss": "nopressure",
            "aud": "nopressure",
            "jti": "jwt-id"
        }))
        .expect("claims should deserialize");

        assert_eq!(claims.password_version, DEFAULT_PASSWORD_VERSION);
    }
}

#[derive(Debug, Clone)]
// Remove once variants are renamed to drop the shared Error suffix.
#[allow(clippy::enum_variant_names)]
pub enum JwtError {
    TokenCreationError(String),
    TokenVerificationError(String),
    ConfigurationError(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::TokenCreationError(msg) => write!(f, "Token creation error: {}", msg),
            JwtError::TokenVerificationError(msg) => write!(f, "Token verification error: {}", msg),
            JwtError::ConfigurationError(msg) => write!(f, "JWT configuration error: {}", msg),
        }
    }
}

impl std::error::Error for JwtError {}
