// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::IamService;
use super::jwt::JwtService;
use super::password::{PasswordError, build_password_provider_block, verify_front_end_hash};
use super::password_tokens::PasswordChangeStore;
use super::store::{FileUserStore, UserStore};
use super::types::{PasswordProviderBlock, User};
use crate::config::{AuthMethod, PasswordHashingParams, ValidatedConfig, ValidatedUsersConfig};
use crate::public::page_meta_cache::PageMetaCache;
use crate::security::validate_email_field;
use std::fmt;
use std::sync::Arc;

/// High-level user services that abstract over authentication methods
pub struct UserServices {
    auth_method: AuthMethod,
    iam_service: Option<IamService>,
    jwt_service: Option<JwtService>,
    page_cache: Option<std::sync::Arc<PageMetaCache>>,
    password_params: PasswordHashingParams,
    password_change_store: PasswordChangeStore,
    dummy_stored_hash: String,
}

pub type UserServiceResult<T> = Result<T, UserServiceError>;

#[derive(Debug)]
pub enum UserServiceError {
    Validation(String),
    Config(String),
    Iam(String),
    Jwt(String),
    Password(PasswordError),
    UnsupportedAuth(AuthMethod),
}

impl fmt::Display for UserServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserServiceError::Validation(message) => write!(f, "{}", message),
            UserServiceError::Config(message) => write!(f, "{}", message),
            UserServiceError::Iam(message) => write!(f, "{}", message),
            UserServiceError::Jwt(message) => write!(f, "{}", message),
            UserServiceError::Password(err) => write!(f, "{}", err),
            UserServiceError::UnsupportedAuth(method) => {
                write!(f, "Unsupported auth method: {:?}", method)
            }
        }
    }
}

impl std::error::Error for UserServiceError {}

impl From<PasswordError> for UserServiceError {
    fn from(err: PasswordError) -> Self {
        UserServiceError::Password(err)
    }
}

fn build_dummy_stored_hash(params: &PasswordHashingParams) -> Result<String, PasswordError> {
    let block = build_password_provider_block("dummy-password", params)?;
    Ok(block.stored_hash)
}

impl UserServices {
    /// Initialize UserServices based on the configured authentication method
    pub fn new(
        config: &ValidatedConfig,
        users_file: std::path::PathBuf,
    ) -> UserServiceResult<Self> {
        match &config.users {
            ValidatedUsersConfig::Local(_) => {
                let store = Arc::new(
                    FileUserStore::new(users_file)
                        .map_err(|err| UserServiceError::Iam(err.to_string()))?,
                );
                Self::new_with_store(config, store)
            }
            ValidatedUsersConfig::Oidc(_) => {
                // TODO: Implement OIDC authentication
                // For now, return an error since OIDC is not implemented
                Err(UserServiceError::UnsupportedAuth(AuthMethod::Oidc))
            }
        }
    }

    pub fn new_with_store(
        config: &ValidatedConfig,
        store: Arc<dyn UserStore>,
    ) -> UserServiceResult<Self> {
        match &config.users {
            ValidatedUsersConfig::Local(_) => {
                let iam_service =
                    IamService::new(store).map_err(|err| UserServiceError::Iam(err.to_string()))?;
                let jwt_service = JwtService::new(config)
                    .map_err(|err| UserServiceError::Jwt(err.to_string()))?;
                let password_params = config
                    .users
                    .local()
                    .map(|local| local.password.clone())
                    .ok_or_else(|| {
                        UserServiceError::Config("Local auth config missing password params".into())
                    })?;
                let dummy_stored_hash = build_dummy_stored_hash(&password_params)?;

                Ok(UserServices {
                    auth_method: AuthMethod::Local,
                    iam_service: Some(iam_service),
                    jwt_service: Some(jwt_service),
                    page_cache: None,
                    password_params,
                    password_change_store: PasswordChangeStore::new(),
                    dummy_stored_hash,
                })
            }
            ValidatedUsersConfig::Oidc(_) => {
                Err(UserServiceError::UnsupportedAuth(AuthMethod::Oidc))
            }
        }
    }

    /// Public accessor for JwtService (if available)
    pub fn jwt_service(&self) -> Option<&JwtService> {
        self.jwt_service.as_ref()
    }

    pub fn password_params(&self) -> &PasswordHashingParams {
        &self.password_params
    }

    pub fn password_change_store(&self) -> &PasswordChangeStore {
        &self.password_change_store
    }

    pub fn get_user(&self, email: &str) -> UserServiceResult<Option<User>> {
        if self.auth_method == AuthMethod::Local {
            let iam_service = self.iam_service.as_ref().ok_or_else(|| {
                UserServiceError::Iam("IAM service not available for local authentication".into())
            })?;
            return iam_service
                .get_user(email)
                .map_err(|err| UserServiceError::Iam(err.to_string()));
        }
        Ok(None)
    }

    pub fn password_validate(
        &self,
        email: &str,
        front_end_hash: &str,
    ) -> Result<bool, PasswordError> {
        if self.auth_method != AuthMethod::Local {
            return Ok(false);
        }
        let iam_service = self
            .iam_service
            .as_ref()
            .ok_or_else(|| PasswordError::HashError("IAM service unavailable".to_string()))?;
        let user = iam_service
            .get_user(email)
            .map_err(|err| PasswordError::HashError(err.to_string()))?;
        let mut has_password = false;
        let stored_hash = match user.as_ref() {
            Some(user) => match user.password.as_ref() {
                Some(block) => {
                    has_password = true;
                    block.stored_hash.as_str()
                }
                None => {
                    if user.legacy_password_hash.is_some() {
                        log::warn!(
                            "Legacy password hash ignored for user {} (reset required)",
                            email
                        );
                    } else {
                        log::warn!("User {} has no password provider block", email);
                    }
                    self.dummy_stored_hash.as_str()
                }
            },
            None => self.dummy_stored_hash.as_str(),
        };

        let valid = verify_front_end_hash(front_end_hash, stored_hash)?;
        Ok(valid && has_password)
    }

    /// Validate a JWT token and return user roles if valid
    /// Returns Some(roles) if the token is valid and user exists, None otherwise
    pub async fn validate_jwt(&self, token: &str) -> Option<User> {
        match self.auth_method {
            AuthMethod::Local => {
                // For local authentication, use JWT service to verify token
                if let (Some(jwt_service), Some(iam_service)) =
                    (&self.jwt_service, &self.iam_service)
                {
                    // First verify the JWT token itself
                    match jwt_service.verify_token(token) {
                        Ok(claims) => {
                            // Token is valid, now check if user still exists and has roles
                            let user: Option<User> =
                                iam_service.get_user(&claims.sub).unwrap_or_default();
                            if let Some(user) = user {
                                if user.password_version != claims.password_version {
                                    log::warn!(
                                        "JWT password version mismatch for user {}",
                                        claims.sub
                                    );
                                    return None;
                                }
                                return Some(user);
                            }
                            None
                        }
                        Err(_) => None, // Invalid token
                    }
                } else {
                    None // Service not properly initialized
                }
            }
            AuthMethod::Oidc => {
                // TODO: Implement OIDC token validation
                None
            }
        }
    }

    /// List all users (only for local auth)
    pub fn list_users(&self) -> UserServiceResult<Vec<User>> {
        match self.auth_method {
            AuthMethod::Local => {
                if let Some(iam_service) = &self.iam_service {
                    Ok(iam_service
                        .list_users()
                        .map_err(|err| UserServiceError::Iam(err.to_string()))?)
                } else {
                    Err(UserServiceError::Iam(
                        "IAM service not available for local authentication".into(),
                    ))
                }
            }
            AuthMethod::Oidc => Err(UserServiceError::UnsupportedAuth(AuthMethod::Oidc)),
        }
    }

    /// Set the page cache (called after initialization)
    pub fn set_page_cache(&mut self, cache: std::sync::Arc<PageMetaCache>) {
        self.page_cache = Some(cache);
    }

    /// Add a new user (only for local auth)
    pub async fn add_user(
        &self,
        email: &str,
        name: &str,
        password: PasswordProviderBlock,
        roles: Vec<String>,
    ) -> UserServiceResult<()> {
        validate_email_field(email).map_err(UserServiceError::Validation)?;
        match self.auth_method {
            AuthMethod::Local => {
                if let Some(iam_service) = &self.iam_service {
                    Ok(iam_service
                        .add_user(email, name, password, roles)
                        .await
                        .map_err(|err| UserServiceError::Iam(err.to_string()))?)
                } else {
                    Err(UserServiceError::Iam(
                        "IAM service not available for local authentication".into(),
                    ))
                }
            }
            AuthMethod::Oidc => Err(UserServiceError::UnsupportedAuth(AuthMethod::Oidc)),
        }
    }

    /// Delete a user (only for local auth)
    pub async fn delete_user(&self, email: &str) -> UserServiceResult<()> {
        match self.auth_method {
            AuthMethod::Local => {
                if let Some(iam_service) = &self.iam_service {
                    Ok(iam_service
                        .delete_user(email)
                        .await
                        .map_err(|err| UserServiceError::Iam(err.to_string()))?)
                } else {
                    Err(UserServiceError::Iam(
                        "IAM service not available for local authentication".into(),
                    ))
                }
            }
            AuthMethod::Oidc => Err(UserServiceError::UnsupportedAuth(AuthMethod::Oidc)),
        }
    }

    /// Update a user with full parameters (only for local auth)
    pub async fn update_user_complete(
        &self,
        email: &str,
        name: Option<&str>,
        password: Option<PasswordProviderBlock>,
        roles: Option<Vec<String>>,
    ) -> UserServiceResult<()> {
        validate_email_field(email).map_err(UserServiceError::Validation)?;
        match self.auth_method {
            AuthMethod::Local => {
                if let Some(iam_service) = &self.iam_service {
                    Ok(iam_service
                        .update_user_complete(email, name, password, roles)
                        .await
                        .map_err(|err| UserServiceError::Iam(err.to_string()))?)
                } else {
                    Err(UserServiceError::Iam(
                        "IAM service not available for local authentication".into(),
                    ))
                }
            }
            AuthMethod::Oidc => Err(UserServiceError::UnsupportedAuth(AuthMethod::Oidc)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Argon2Params, PasswordHashingParams, ServerConfig, ServerListenerConfig, ServerProtocol,
        ServerRole, ValidatedLocalAuthConfig, ValidatedUsersConfig,
    };
    use crate::iam::password::{build_password_provider_block, derive_front_end_hash};
    use crate::iam::store::MemoryUserStore;
    use crate::iam::types::DEFAULT_PASSWORD_VERSION;
    use crate::iam::types::{PasswordProviderBlock, User};
    use crate::util::test_config::TestConfigBuilder;
    use std::sync::Arc;

    const VALID_PASSWORD: &str = "correct-password";

    fn test_password_params() -> PasswordHashingParams {
        PasswordHashingParams {
            front_end: Argon2Params {
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
                output_len: 16,
                salt_len: 8,
            },
            back_end: Argon2Params {
                memory_kib: 8192,
                iterations: 1,
                parallelism: 1,
                output_len: 16,
                salt_len: 8,
            },
        }
    }

    fn build_test_config() -> ValidatedConfig {
        let mut config = TestConfigBuilder::new().with_streaming(false).build();
        config.servers = vec![ServerListenerConfig {
            name: Some("main".to_string()),
            role: ServerRole::Main,
            host: "127.0.0.1".to_string(),
            port: 8080,
            protocol: ServerProtocol::Http,
        }];
        config.server = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            http_port: None,
            workers: 1,
        };
        config.users = ValidatedUsersConfig::Local(ValidatedLocalAuthConfig {
            jwt: crate::config::JwtConfig {
                secret: "test-secret".to_string(),
                issuer: "nopressure".to_string(),
                audience: "nopressure-users".to_string(),
                expiration_hours: 12,
                cookie_name: "nop_auth".to_string(),
                disable_refresh: false,
                refresh_threshold_percentage: 10,
                refresh_threshold_hours: 24,
            },
            password: test_password_params(),
        });
        config.security.max_violations = 10;
        config.security.cooldown_seconds = 60;
        config.upload.allowed_extensions = vec!["md".to_string(), "txt".to_string()];
        config
    }

    fn build_user_services(users: Vec<User>) -> UserServices {
        let config = build_test_config();
        let store = Arc::new(MemoryUserStore::from_users(users));
        UserServices::new_with_store(&config, store).expect("user services")
    }

    fn build_password_block() -> PasswordProviderBlock {
        build_password_provider_block(VALID_PASSWORD, &test_password_params())
            .expect("password block")
    }

    #[tokio::test]
    async fn password_validate_accepts_valid_front_end_hash() {
        let block = build_password_block();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User".to_string(),
            password: Some(block.clone()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: DEFAULT_PASSWORD_VERSION,
        };
        let services = build_user_services(vec![user.clone()]);
        let front_end_hash = derive_front_end_hash(
            VALID_PASSWORD,
            &block.front_end_salt,
            &test_password_params().front_end,
        )
        .expect("front_end_hash");

        let result = services.password_validate(&user.email, &front_end_hash);

        assert!(result.expect("password_validate"));
    }

    #[tokio::test]
    async fn password_validate_rejects_invalid_front_end_hash() {
        let block = build_password_block();
        let user = User {
            email: "user@example.com".to_string(),
            name: "User".to_string(),
            password: Some(block.clone()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: DEFAULT_PASSWORD_VERSION,
        };
        let services = build_user_services(vec![user]);
        let front_end_hash = derive_front_end_hash(
            "wrong-password",
            &block.front_end_salt,
            &test_password_params().front_end,
        )
        .expect("front_end_hash");

        let result = services.password_validate("user@example.com", &front_end_hash);

        assert!(!result.expect("password_validate"));
    }

    #[tokio::test]
    async fn password_validate_returns_false_for_missing_user() {
        let services = build_user_services(Vec::new());
        let front_end_hash = derive_front_end_hash(
            VALID_PASSWORD,
            "00aa00bb00cc00dd",
            &test_password_params().front_end,
        )
        .expect("front_end_hash");

        let result = services.password_validate("missing@example.com", &front_end_hash);

        assert!(!result.expect("password_validate"));
    }

    #[tokio::test]
    async fn password_validate_returns_false_for_legacy_password() {
        let user = User {
            email: "user@example.com".to_string(),
            name: "User".to_string(),
            password: None,
            legacy_password_hash: Some("legacy-hash".to_string()),
            roles: vec!["admin".to_string()],
            password_version: DEFAULT_PASSWORD_VERSION,
        };
        let services = build_user_services(vec![user]);
        let front_end_hash = derive_front_end_hash(
            VALID_PASSWORD,
            "00aa00bb00cc00dd",
            &test_password_params().front_end,
        )
        .expect("front_end_hash");

        let result = services.password_validate("user@example.com", &front_end_hash);

        assert!(!result.expect("password_validate"));
    }

    #[tokio::test]
    async fn validate_jwt_accepts_matching_password_version() {
        let user = User {
            email: "user@example.com".to_string(),
            name: "User".to_string(),
            password: Some(build_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: DEFAULT_PASSWORD_VERSION,
        };
        let services = build_user_services(vec![user.clone()]);
        let jwt_service = services.jwt_service().expect("jwt service");
        let token = jwt_service
            .create_token(&user.email, &user)
            .expect("create token");

        let validated = services.validate_jwt(&token).await;
        assert_eq!(validated.map(|user| user.email), Some(user.email));
    }

    #[tokio::test]
    async fn validate_jwt_rejects_password_version_mismatch() {
        let user = User {
            email: "user@example.com".to_string(),
            name: "User".to_string(),
            password: Some(build_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: DEFAULT_PASSWORD_VERSION,
        };
        let services = build_user_services(vec![user.clone()]);
        let jwt_service = services.jwt_service().expect("jwt service");
        let token = jwt_service
            .create_token(&user.email, &user)
            .expect("create token");

        services
            .update_user_complete(&user.email, None, Some(build_password_block()), None)
            .await
            .expect("update user");

        let validated = services.validate_jwt(&token).await;
        assert!(validated.is_none());
    }

    #[tokio::test]
    async fn add_user_rejects_invalid_email_format() {
        let services = build_user_services(Vec::new());
        let result = services
            .add_user("not-an-email", "User", build_password_block(), vec![])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn update_user_rejects_invalid_email_format() {
        let user = User {
            email: "user@example.com".to_string(),
            name: "User".to_string(),
            password: Some(build_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: DEFAULT_PASSWORD_VERSION,
        };
        let services = build_user_services(vec![user]);
        let result = services
            .update_user_complete("not-an-email", Some("Updated"), None, None)
            .await;
        assert!(result.is_err());
    }
}
