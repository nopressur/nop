// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::store::UserStore;
use super::types::{
    DEFAULT_PASSWORD_VERSION, IamError, User, UserMutation, UserMutationResult, UsersData,
};
use nop_iam_passwords::PasswordProviderBlock;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};

const MUTATION_QUEUE_DEPTH: usize = 128;
const MUTATION_BATCH_SIZE: usize = 64;
const MUTATION_QUEUE_FULL_MESSAGE: &str = "User mutation queue is full; retry.";

// Type aliases for complex channel types
type MutationRequest = (
    UserMutation,
    oneshot::Sender<Result<UserMutationResult, IamError>>,
);
type MutationSender = mpsc::Sender<MutationRequest>;
type MutationReceiver = mpsc::Receiver<MutationRequest>;

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

        // Create a bounded channel for handling user mutations
        let (mutation_sender, mut mutation_receiver): (MutationSender, MutationReceiver) =
            mpsc::channel(MUTATION_QUEUE_DEPTH);

        let users_data_clone = users_data.clone();
        let store_clone = store.clone();

        // Spawn background task to handle mutations
        tokio::spawn(async move {
            while let Some(request) = mutation_receiver.recv().await {
                let mut batch = Vec::with_capacity(MUTATION_BATCH_SIZE);
                batch.push(request);
                while batch.len() < MUTATION_BATCH_SIZE {
                    match mutation_receiver.try_recv() {
                        Ok(request) => batch.push(request),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }

                if let Err(err) =
                    Self::handle_mutation_batch(batch, &users_data_clone, &store_clone).await
                {
                    log::error!("User mutation batch failed: {}", err);
                }
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

    fn snapshot_users(
        users_data: &Arc<RwLock<UsersData>>,
        store: &Arc<dyn UserStore>,
    ) -> Result<UsersData, IamError> {
        match users_data.read() {
            Ok(guard) => Ok(guard.clone()),
            Err(_) => {
                log::error!("Users lock poisoned on read; reloading from disk");
                Self::reload_users_from_store(users_data, store)?;
                let guard = users_data.read().map_err(|_| {
                    IamError::ConfigurationError(
                        "Users lock poisoned after recovery attempt".to_string(),
                    )
                })?;
                Ok(guard.clone())
            }
        }
    }

    fn commit_users_snapshot(
        users_data: &Arc<RwLock<UsersData>>,
        snapshot: UsersData,
    ) -> Result<(), IamError> {
        match users_data.write() {
            Ok(mut guard) => {
                *guard = snapshot;
                users_data.clear_poison();
                Ok(())
            }
            Err(poisoned) => {
                log::error!("Users lock poisoned on write; recovering");
                let mut guard = poisoned.into_inner();
                *guard = snapshot;
                users_data.clear_poison();
                Ok(())
            }
        }
    }

    fn apply_mutation(
        mutation: &UserMutation,
        users: &mut UsersData,
    ) -> Result<UserMutationResult, IamError> {
        match mutation {
            UserMutation::Update {
                email,
                name,
                password,
                roles,
            } => {
                let user = match users.get_mut(email) {
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
                Ok(UserMutationResult::Updated)
            }
            UserMutation::Add {
                email,
                name,
                password,
                roles,
            } => {
                if users.contains_key(email) {
                    return Err(IamError::ConfigurationError(format!(
                        "User {} already exists",
                        email
                    )));
                }
                let user = User {
                    email: email.clone(),
                    name: name.clone(),
                    password: Some(password.clone()),
                    legacy_password_hash: None,
                    roles: roles.clone(),
                    password_version: DEFAULT_PASSWORD_VERSION,
                };
                users.insert(email.clone(), user);
                Ok(UserMutationResult::Added)
            }
            UserMutation::Delete { email } => {
                if users.remove(email).is_some() {
                    Ok(UserMutationResult::Deleted)
                } else {
                    Err(IamError::UserNotFound(email.clone()))
                }
            }
        }
    }

    async fn handle_mutation_batch(
        batch: Vec<MutationRequest>,
        users_data: &Arc<RwLock<UsersData>>,
        store: &Arc<dyn UserStore>,
    ) -> Result<(), IamError> {
        let mut snapshot = Self::snapshot_users(users_data, store)?;
        let mut results = Vec::with_capacity(batch.len());
        let mut changed = false;

        for (mutation, responder) in batch {
            let result = Self::apply_mutation(&mutation, &mut snapshot);
            if result.is_ok() {
                changed = true;
            }
            results.push((responder, result));
        }

        if changed {
            if let Err(err) = store.save_async(&snapshot).await {
                for (responder, _) in results {
                    let _ = responder.send(Err(err.clone()));
                }
                return Err(err);
            }

            Self::commit_users_snapshot(users_data, snapshot)?;
        }

        for (responder, result) in results {
            let _ = responder.send(result);
        }

        Ok(())
    }

    /// Get a user by email (synchronous read operation)
    pub fn get_user(&self, email: &str) -> Result<Option<User>, IamError> {
        log::debug!("Looking up user in IAM service: {}", email);
        self.with_users_read(|users| {
            if let Some(user) = users.get(email) {
                log::debug!("User found with roles: {}", email);
                Ok(Some(user.clone()))
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

    fn send_mutation(
        &self,
        mutation: UserMutation,
        response_sender: oneshot::Sender<Result<UserMutationResult, IamError>>,
    ) -> Result<(), IamError> {
        match self.mutation_sender.try_send((mutation, response_sender)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(IamError::Busy(MUTATION_QUEUE_FULL_MESSAGE.to_string()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(IamError::ServiceNotInitialized),
        }
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

        self.send_mutation(mutation, response_sender)?;

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

        self.send_mutation(mutation, response_sender)?;

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

        self.send_mutation(mutation, response_sender)?;

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
    use crate::store::MemoryUserStore;
    use crate::types::DEFAULT_PASSWORD_VERSION;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use tokio::sync::Notify;

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

    #[derive(Clone)]
    struct BlockingUserStore {
        users: Arc<RwLock<UsersData>>,
        started: Arc<Notify>,
        gate: Arc<Notify>,
    }

    impl BlockingUserStore {
        fn new(users: UsersData, started: Arc<Notify>, gate: Arc<Notify>) -> Self {
            Self {
                users: Arc::new(RwLock::new(users)),
                started,
                gate,
            }
        }
    }

    impl UserStore for BlockingUserStore {
        fn load(&self) -> Result<UsersData, IamError> {
            match self.users.read() {
                Ok(guard) => Ok(guard.clone()),
                Err(poisoned) => Ok(poisoned.into_inner().clone()),
            }
        }

        fn save(&self, _users: &UsersData) -> Result<(), IamError> {
            Ok(())
        }

        fn save_async<'a>(
            &'a self,
            _users: &'a UsersData,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), IamError>> + Send + 'a>>
        {
            let started = self.started.clone();
            let gate = self.gate.clone();
            Box::pin(async move {
                started.notify_one();
                gate.notified().await;
                Ok(())
            })
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
        let store: Arc<dyn UserStore> = Arc::new(MemoryUserStore::new(users));
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
        let store: Arc<dyn UserStore> = Arc::new(MemoryUserStore::new(users));
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

    #[tokio::test]
    async fn get_user_allows_empty_roles() {
        let mut users = HashMap::new();
        let mut user = sample_user();
        user.roles = vec![];
        users.insert(user.email.clone(), user.clone());
        let store: Arc<dyn UserStore> = Arc::new(MemoryUserStore::new(users));
        let service = IamService::new(store).expect("service");

        let fetched = service
            .get_user("user@example.com")
            .expect("get user")
            .expect("user");

        assert!(fetched.roles.is_empty());
    }

    #[tokio::test]
    async fn mutation_queue_returns_busy_when_full() {
        let started = Arc::new(Notify::new());
        let gate = Arc::new(Notify::new());
        let store = Arc::new(BlockingUserStore::new(
            UsersData::new(),
            started.clone(),
            gate.clone(),
        ));
        let service = IamService::new(store).expect("service");

        let (response_sender, _response_receiver) = oneshot::channel();
        service
            .send_mutation(
                UserMutation::Add {
                    email: "user0@example.com".to_string(),
                    name: "User".to_string(),
                    password: sample_password_block(),
                    roles: vec![],
                },
                response_sender,
            )
            .expect("enqueue");

        started.notified().await;

        let mut busy_seen = false;
        for idx in 1..(MUTATION_QUEUE_DEPTH + 4) {
            let (response_sender, _response_receiver) = oneshot::channel();
            let result = service.send_mutation(
                UserMutation::Add {
                    email: format!("user{}@example.com", idx),
                    name: "User".to_string(),
                    password: sample_password_block(),
                    roles: vec![],
                },
                response_sender,
            );
            if matches!(result, Err(IamError::Busy(_))) {
                busy_seen = true;
                break;
            }
        }

        assert!(busy_seen, "expected busy error when queue is full");

        gate.notify_one();
    }

    #[tokio::test]
    async fn mutation_batch_applies_in_order() {
        let users = UsersData::new();
        let users_data = Arc::new(RwLock::new(users.clone()));
        let store: Arc<dyn UserStore> = Arc::new(MemoryUserStore::new(users));

        let (add_tx, add_rx) = oneshot::channel();
        let (update_tx, update_rx) = oneshot::channel();

        let batch = vec![
            (
                UserMutation::Add {
                    email: "user@example.com".to_string(),
                    name: "First".to_string(),
                    password: sample_password_block(),
                    roles: vec!["editor".to_string()],
                },
                add_tx,
            ),
            (
                UserMutation::Update {
                    email: "user@example.com".to_string(),
                    name: Some("Second".to_string()),
                    password: None,
                    roles: Some(vec!["admin".to_string()]),
                },
                update_tx,
            ),
        ];

        IamService::handle_mutation_batch(batch, &users_data, &store)
            .await
            .expect("batch handled");

        let add_result = add_rx.await.expect("add response");
        assert!(matches!(add_result, Ok(UserMutationResult::Added)));
        let update_result = update_rx.await.expect("update response");
        assert!(matches!(update_result, Ok(UserMutationResult::Updated)));

        let stored = users_data
            .read()
            .expect("read users")
            .get("user@example.com")
            .cloned()
            .expect("user exists");
        assert_eq!(stored.name, "Second");
        assert_eq!(stored.roles, vec!["admin".to_string()]);
    }

    #[tokio::test]
    async fn mutation_batch_failure_does_not_commit_snapshot() {
        let mut users = UsersData::new();
        let original = sample_user();
        users.insert(original.email.clone(), original.clone());
        let users_data = Arc::new(RwLock::new(users.clone()));
        let store: Arc<dyn UserStore> = Arc::new(FailingUserStore::new(users));

        let (update_tx, _update_rx) = oneshot::channel();
        let (add_tx, _add_rx) = oneshot::channel();

        let batch = vec![
            (
                UserMutation::Update {
                    email: original.email.clone(),
                    name: Some("Updated".to_string()),
                    password: None,
                    roles: None,
                },
                update_tx,
            ),
            (
                UserMutation::Add {
                    email: "new@example.com".to_string(),
                    name: "New".to_string(),
                    password: sample_password_block(),
                    roles: vec!["admin".to_string()],
                },
                add_tx,
            ),
        ];

        let result = IamService::handle_mutation_batch(batch, &users_data, &store).await;
        assert!(result.is_err());

        let stored = users_data
            .read()
            .expect("read users")
            .get(&original.email)
            .cloned()
            .expect("original user");
        assert_eq!(stored.name, original.name);
        assert!(
            users_data
                .read()
                .expect("read users")
                .get("new@example.com")
                .is_none()
        );
    }
}
