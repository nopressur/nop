// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::sync::{mpsc, oneshot};

const PASSWORD_CHANGE_CHANNEL_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub struct PasswordChangeToken {
    pub email: String,
    pub next_front_end_salt: String,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub enum PasswordChangeStoreError {
    Unavailable,
}

impl PasswordChangeStoreError {
    pub fn message(&self) -> &'static str {
        match self {
            PasswordChangeStoreError::Unavailable => "Password change token store unavailable",
        }
    }
}

#[derive(Clone)]
pub struct PasswordChangeStore {
    sender: mpsc::Sender<PasswordChangeCommand>,
}

impl PasswordChangeStore {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(PASSWORD_CHANGE_CHANNEL_DEPTH);
        tokio::spawn(async move {
            let mut state = PasswordChangeState::new();
            state.run(receiver).await;
        });
        Self { sender }
    }

    pub async fn issue(
        &self,
        email: &str,
        next_front_end_salt: String,
        ttl: Duration,
    ) -> Result<(String, PasswordChangeToken), PasswordChangeStoreError> {
        let (reply, receive) = oneshot::channel();
        let command = PasswordChangeCommand::Issue {
            email: email.to_string(),
            next_front_end_salt,
            ttl,
            reply,
        };
        if self.sender.send(command).await.is_err() {
            return Err(PasswordChangeStoreError::Unavailable);
        }
        receive
            .await
            .unwrap_or(Err(PasswordChangeStoreError::Unavailable))
    }

    pub async fn get(
        &self,
        change_token: &str,
    ) -> Result<Option<PasswordChangeToken>, PasswordChangeStoreError> {
        let (reply, receive) = oneshot::channel();
        let command = PasswordChangeCommand::Get {
            change_token: change_token.to_string(),
            reply,
        };
        if self.sender.send(command).await.is_err() {
            return Err(PasswordChangeStoreError::Unavailable);
        }
        receive
            .await
            .unwrap_or(Err(PasswordChangeStoreError::Unavailable))
    }

    pub async fn invalidate(&self, change_token: &str) -> Result<(), PasswordChangeStoreError> {
        let command = PasswordChangeCommand::Invalidate {
            change_token: change_token.to_string(),
        };
        if self.sender.send(command).await.is_err() {
            return Err(PasswordChangeStoreError::Unavailable);
        }
        Ok(())
    }
}

impl Default for PasswordChangeStore {
    fn default() -> Self {
        Self::new()
    }
}

enum PasswordChangeCommand {
    Issue {
        email: String,
        next_front_end_salt: String,
        ttl: Duration,
        reply: oneshot::Sender<Result<(String, PasswordChangeToken), PasswordChangeStoreError>>,
    },
    Get {
        change_token: String,
        reply: oneshot::Sender<Result<Option<PasswordChangeToken>, PasswordChangeStoreError>>,
    },
    Invalidate {
        change_token: String,
    },
}

struct PasswordChangeState {
    tokens: HashMap<String, PasswordChangeToken>,
}

impl PasswordChangeState {
    fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    async fn run(&mut self, mut receiver: mpsc::Receiver<PasswordChangeCommand>) {
        while let Some(command) = receiver.recv().await {
            self.cleanup_expired();
            match command {
                PasswordChangeCommand::Issue {
                    email,
                    next_front_end_salt,
                    ttl,
                    reply,
                } => {
                    let change_token = generate_change_token();
                    let token = PasswordChangeToken {
                        email,
                        next_front_end_salt,
                        expires_at: Instant::now() + ttl,
                    };
                    self.tokens.insert(change_token.clone(), token.clone());
                    let _ = reply.send(Ok((change_token, token)));
                }
                PasswordChangeCommand::Get {
                    change_token,
                    reply,
                } => {
                    let token = self.tokens.get(&change_token).cloned();
                    let _ = reply.send(Ok(token));
                }
                PasswordChangeCommand::Invalidate { change_token } => {
                    self.tokens.remove(&change_token);
                }
            }
        }
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.tokens.retain(|_, token| token.expires_at > now);
    }
}

fn generate_change_token() -> String {
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn password_change_store_issue_get_invalidate() {
        let store = PasswordChangeStore::new();
        let (token, issued) = store
            .issue(
                "user@example.com",
                "salt".to_string(),
                Duration::from_secs(30),
            )
            .await
            .expect("issue");
        assert_eq!(issued.email, "user@example.com");

        let fetched = store.get(&token).await.expect("get");
        assert!(fetched.is_some());

        store.invalidate(&token).await.expect("invalidate");
        let missing = store.get(&token).await.expect("get after invalidate");
        assert!(missing.is_none());
    }

    #[actix_web::test]
    async fn password_change_store_expires_tokens() {
        let store = PasswordChangeStore::new();
        let (token, _issued) = store
            .issue(
                "user@example.com",
                "salt".to_string(),
                Duration::from_secs(0),
            )
            .await
            .expect("issue");

        let missing = store.get(&token).await.expect("get expired");
        assert!(missing.is_none());
    }
}
