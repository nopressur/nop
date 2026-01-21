// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::store::UserStore;
use super::types::{
    DEFAULT_PASSWORD_VERSION, IamError, PasswordProviderBlock, User, UserMutation,
    UserMutationResult, UsersData,
};
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};

// Type aliases for complex channel types
type MutationRequest = (
    UserMutation,
    oneshot::Sender<Result<UserMutationResult, IamError>>,
);
type MutationSender = mpsc::UnboundedSender<MutationRequest>;
type MutationReceiver = mpsc::UnboundedReceiver<MutationRequest>;

/// Main IAM service that manages user data
#[derive(Clone)]
pub struct IamService {
    users_data: Arc<RwLock<UsersData>>,
    mutation_sender: MutationSender,
    store: Arc<dyn UserStore>,
}

impl IamService {
    /// Initialize the IAM service with a user store
    /// This loads users from the store and starts the background service for mutations
    pub fn new(store: Arc<dyn UserStore>) -> Result<Self, IamError> {
        // Load users from the store
        let users = store.load()?;

        // Store users in thread-safe storage
        let users_data = Arc::new(RwLock::new(users));

        // Create a channel for handling user mutations
        let (mutation_sender, mut mutation_receiver): (MutationSender, MutationReceiver) =
            mpsc::unbounded_channel();

        let users_data_clone = users_data.clone();
        let store_clone = store.clone();

        // Spawn background task to handle mutations
        tokio::spawn(async move {
            while let Some((mutation, response_sender)) = mutation_receiver.recv().await {
                let result = Self::handle_mutation(&mutation, &users_data_clone, &store_clone);
                let _ = response_sender.send(result);
            }
        });

        Ok(IamService {
            users_data,
            mutation_sender,
            store,
        })
    }

    /// Load users from the users.yaml file
    fn reload_users_from_store(
        users_data: &Arc<RwLock<UsersData>>,
        store: &Arc<dyn UserStore>,
    ) -> Result<(), IamError> {
        let users = store.load()?;
        match users_data.write() {
            Ok(mut guard) => {
                *guard = users;
                users_data.clear_poison();
                Ok(())
            }
            Err(poisoned) => {
                log::error!("Users lock poisoned during reload; recovering");
                let mut guard = poisoned.into_inner();
                *guard = users;
                users_data.clear_poison();
                Ok(())
            }
        }
    }

    fn with_users_read<T>(
        &self,
        f: impl FnOnce(&UsersData) -> Result<T, IamError>,
    ) -> Result<T, IamError> {
        match self.users_data.read() {
            Ok(guard) => f(&guard),
            Err(_) => {
                log::error!("Users lock poisoned on read; reloading from disk");
                Self::reload_users_from_store(&self.users_data, &self.store)?;
                let guard = self.users_data.read().map_err(|_| {
                    IamError::ConfigurationError(
                        "Users lock poisoned after recovery attempt".to_string(),
                    )
                })?;
                f(&guard)
            }
        }
    }

    fn with_users_write<T>(
        users_data: &Arc<RwLock<UsersData>>,
        store: &Arc<dyn UserStore>,
        f: impl FnOnce(&mut UsersData) -> Result<T, IamError>,
    ) -> Result<T, IamError> {
        let mut guard = match users_data.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("Users lock poisoned on write; reloading from disk");
                let mut guard = poisoned.into_inner();
                let users = store.load()?;
                *guard = users;
                users_data.clear_poison();
                guard
            }
        };

        f(&mut guard)
    }

    /// Handle a user mutation (runs in background thread)
    fn handle_mutation(
        mutation: &UserMutation,
        users_data: &Arc<RwLock<UsersData>>,
        store: &Arc<dyn UserStore>,
    ) -> Result<UserMutationResult, IamError> {
        match mutation {
            UserMutation::Update {
                email,
                name,
                password,
                roles,
            } => Self::with_users_write(users_data, store, |users| {
                let mut updated = users.clone();
                let user = match updated.get_mut(email) {
                    Some(user) => user,
                    None => return Err(IamError::UserNotFound(email.clone())),
                };
                if let Some(name) = name {
                    user.name = name.clone();
                }
                if let Some(password) = password {
                    user.password = Some(password.clone());
                    user.legacy_password_hash = None;
                    user.password_version = user.password_version.saturating_add(1);
                }
                if let Some(roles) = roles {
                    user.roles = roles.clone();
                }

                store.save(&updated)?;
                *users = updated;
                Ok(UserMutationResult::Updated)
            }),
            UserMutation::Add {
                email,
                name,
                password,
                roles,
            } => Self::with_users_write(users_data, store, |users| {
                if users.contains_key(email) {
                    return Err(IamError::ConfigurationError(format!(
                        "User {} already exists",
                        email
                    )));
                }

                let mut updated = users.clone();
                let user = User {
                    email: email.clone(),
                    name: name.clone(),
                    password: Some(password.clone()),
                    legacy_password_hash: None,
                    roles: roles.clone(),
                    password_version: DEFAULT_PASSWORD_VERSION,
                };

                updated.insert(email.clone(), user);

                store.save(&updated)?;
                *users = updated;
                Ok(UserMutationResult::Added)
            }),
            UserMutation::Delete { email } => Self::with_users_write(users_data, store, |users| {
                let mut updated = users.clone();
                if updated.remove(email).is_some() {
                    store.save(&updated)?;
                    *users = updated;
                    Ok(UserMutationResult::Deleted)
                } else {
                    Err(IamError::UserNotFound(email.clone()))
                }
            }),
        }
    }

    /// Get a user by email (synchronous read operation)
    pub fn get_user(&self, email: &str) -> Result<Option<User>, IamError> {
        log::debug!("Looking up user in IAM service: {}", email);
        self.with_users_read(|users| {
            if let Some(user) = users.get(email) {
                // If user has no roles, they are considered disabled
                if user.roles.is_empty() {
                    log::debug!("User found but has no roles (disabled): {}", email);
                    Ok(None) // Disabled user
                } else {
                    log::debug!("User found with roles: {}", email);
                    Ok(Some(user.clone()))
                }
            } else {
                log::debug!("User not found in IAM service: {}", email);
                Ok(None) // User not found
            }
        })
    }

    /// List all users (synchronous read operation)
    pub fn list_users(&self) -> Result<Vec<User>, IamError> {
        self.with_users_read(|users| Ok(users.values().cloned().collect()))
    }

    /// Add a new user (async mutation operation)
    pub async fn add_user(
        &self,
        email: &str,
        name: &str,
        password: PasswordProviderBlock,
        roles: Vec<String>,
    ) -> Result<(), IamError> {
        let (response_sender, response_receiver) = oneshot::channel();

        let mutation = UserMutation::Add {
            email: email.to_string(),
            name: name.to_string(),
            password,
            roles,
        };

        self.mutation_sender
            .send((mutation, response_sender))
            .map_err(|_| IamError::ServiceNotInitialized)?;

        let result = response_receiver
            .await
            .map_err(|_| IamError::ServiceNotInitialized)?;

        match result? {
            UserMutationResult::Added => Ok(()),
            _ => Err(IamError::ConfigurationError(
                "Unexpected result".to_string(),
            )),
        }
    }

    /// Delete a user (async mutation operation)
    pub async fn delete_user(&self, email: &str) -> Result<(), IamError> {
        let (response_sender, response_receiver) = oneshot::channel();

        let mutation = UserMutation::Delete {
            email: email.to_string(),
        };

        self.mutation_sender
            .send((mutation, response_sender))
            .map_err(|_| IamError::ServiceNotInitialized)?;

        let result = response_receiver
            .await
            .map_err(|_| IamError::ServiceNotInitialized)?;

        match result? {
            UserMutationResult::Deleted => Ok(()),
            _ => Err(IamError::ConfigurationError(
                "Unexpected result".to_string(),
            )),
        }
    }

    /// Update a user with more complete parameters (async mutation operation)
    pub async fn update_user_complete(
        &self,
        email: &str,
        name: Option<&str>,
        password: Option<PasswordProviderBlock>,
        roles: Option<Vec<String>>,
    ) -> Result<(), IamError> {
        let (response_sender, response_receiver) = oneshot::channel();

        let mutation = UserMutation::Update {
            email: email.to_string(),
            name: name.map(|s| s.to_string()),
            password,
            roles,
        };

        self.mutation_sender
            .send((mutation, response_sender))
            .map_err(|_| IamError::ServiceNotInitialized)?;

        let result = response_receiver
            .await
            .map_err(|_| IamError::ServiceNotInitialized)?;

        match result? {
            UserMutationResult::Updated => Ok(()),
            _ => Err(IamError::ConfigurationError(
                "Unexpected result".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::store::MemoryUserStore;
    use crate::iam::types::DEFAULT_PASSWORD_VERSION;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct FailingUserStore {
        users: UsersData,
    }

    impl FailingUserStore {
        fn new(users: UsersData) -> Self {
            Self { users }
        }
    }

    impl UserStore for FailingUserStore {
        fn load(&self) -> Result<UsersData, IamError> {
            Ok(self.users.clone())
        }

        fn save(&self, _users: &UsersData) -> Result<(), IamError> {
            Err(IamError::FileError(
                "Simulated users save failure".to_string(),
            ))
        }
    }

    fn sample_password_block() -> PasswordProviderBlock {
        PasswordProviderBlock {
            front_end_salt: "front".to_string(),
            back_end_salt: "back".to_string(),
            stored_hash: "hash".to_string(),
        }
    }

    fn sample_user() -> User {
        User {
            email: "user@example.com".to_string(),
            name: "User One".to_string(),
            password: Some(sample_password_block()),
            legacy_password_hash: None,
            roles: vec!["admin".to_string()],
            password_version: DEFAULT_PASSWORD_VERSION,
        }
    }

    #[tokio::test]
    async fn add_does_not_mutate_in_memory_on_save_error() {
        let store = Arc::new(FailingUserStore::new(HashMap::new()));
        let service = IamService::new(store).expect("service");

        let result = service
            .add_user(
                "user@example.com",
                "User One",
                sample_password_block(),
                vec!["admin".to_string()],
            )
            .await;
        assert!(result.is_err());

        let users = service.list_users().expect("list users");
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn update_does_not_mutate_in_memory_on_save_error() {
        let mut users = HashMap::new();
        let user = sample_user();
        users.insert(user.email.clone(), user);
        let store = Arc::new(FailingUserStore::new(users));
        let service = IamService::new(store).expect("service");

        let result = service
            .update_user_complete("user@example.com", Some("Updated Name"), None, None)
            .await;
        assert!(result.is_err());

        let users = service.list_users().expect("list users");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "User One");
    }

    #[tokio::test]
    async fn delete_does_not_mutate_in_memory_on_save_error() {
        let mut users = HashMap::new();
        let user = sample_user();
        users.insert(user.email.clone(), user);
        let store = Arc::new(FailingUserStore::new(users));
        let service = IamService::new(store).expect("service");

        let result = service.delete_user("user@example.com").await;
        assert!(result.is_err());

        let users = service.list_users().expect("list users");
        assert_eq!(users.len(), 1);
    }

    #[tokio::test]
    async fn password_update_bumps_password_version() {
        let mut users = HashMap::new();
        let user = sample_user();
        users.insert(user.email.clone(), user);
        let store = Arc::new(MemoryUserStore::new(users));
        let service = IamService::new(store).expect("service");

        service
            .update_user_complete(
                "user@example.com",
                None,
                Some(sample_password_block()),
                None,
            )
            .await
            .expect("update user");

        let updated = service
            .get_user("user@example.com")
            .expect("get user")
            .expect("user");
        assert_eq!(
            updated.password_version,
            DEFAULT_PASSWORD_VERSION.saturating_add(1)
        );
    }

    #[tokio::test]
    async fn name_update_does_not_bump_password_version() {
        let mut users = HashMap::new();
        let user = sample_user();
        users.insert(user.email.clone(), user);
        let store = Arc::new(MemoryUserStore::new(users));
        let service = IamService::new(store).expect("service");

        service
            .update_user_complete("user@example.com", Some("New Name"), None, None)
            .await
            .expect("update user");

        let updated = service
            .get_user("user@example.com")
            .expect("get user")
            .expect("user");
        assert_eq!(updated.password_version, DEFAULT_PASSWORD_VERSION);
    }
}
