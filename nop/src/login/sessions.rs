// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::LoginSessionConfig;
use crate::management::{WorkflowCounter, next_connection_id};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

pub(crate) const LOGIN_SESSION_TTL_SECONDS: u64 = 600;
const LOGIN_SESSION_CHANNEL_DEPTH: usize = 64;
const MAX_LOGIN_SESSIONS: usize = 10000;

#[derive(Debug, Clone)]
pub struct LoginSessionIssue {
    pub login_session_id: String,
    pub return_path: Option<String>,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct LoginSessionUse {
    pub return_path: Option<String>,
    pub connection_id: u32,
    pub workflow_id: u32,
}

#[derive(Debug)]
pub enum LoginSessionError {
    RateLimited,
    InvalidSession,
}

impl LoginSessionError {
    pub fn code(&self) -> &'static str {
        match self {
            LoginSessionError::RateLimited => "login_rate_limited",
            LoginSessionError::InvalidSession => "login_session_expired",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            LoginSessionError::RateLimited => {
                "Login is temporarily unavailable. Please try again later."
            }
            LoginSessionError::InvalidSession => "Login session expired. Please start again.",
        }
    }
}

#[derive(Clone)]
pub struct LoginSessionStore {
    sender: mpsc::Sender<LoginSessionCommand>,
}

impl LoginSessionStore {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(LOGIN_SESSION_CHANNEL_DEPTH);
        tokio::spawn(async move {
            let mut state = LoginSessionState::new();
            state.run(receiver).await;
        });
        Self { sender }
    }

    pub async fn issue(
        &self,
        ip: IpAddr,
        return_path: Option<String>,
        limits: &LoginSessionConfig,
    ) -> Result<LoginSessionIssue, LoginSessionError> {
        let (reply, receive) = oneshot::channel();
        let command = LoginSessionCommand::Issue {
            ip,
            return_path,
            limits: limits.clone(),
            reply,
        };
        if self.sender.send(command).await.is_err() {
            return Err(LoginSessionError::RateLimited);
        }
        receive.await.unwrap_or(Err(LoginSessionError::RateLimited))
    }

    pub async fn use_session(
        &self,
        ip: IpAddr,
        session_id: &str,
        limits: &LoginSessionConfig,
    ) -> Result<LoginSessionUse, LoginSessionError> {
        let (reply, receive) = oneshot::channel();
        let command = LoginSessionCommand::Use {
            ip,
            session_id: session_id.to_string(),
            limits: limits.clone(),
            reply,
        };
        if self.sender.send(command).await.is_err() {
            return Err(LoginSessionError::RateLimited);
        }
        receive.await.unwrap_or(Err(LoginSessionError::RateLimited))
    }

    pub fn invalidate(&self, session_id: &str) {
        let _ = self.sender.try_send(LoginSessionCommand::Invalidate {
            session_id: session_id.to_string(),
        });
    }
}

impl Default for LoginSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

enum LoginSessionCommand {
    Issue {
        ip: IpAddr,
        return_path: Option<String>,
        limits: LoginSessionConfig,
        reply: oneshot::Sender<Result<LoginSessionIssue, LoginSessionError>>,
    },
    Use {
        ip: IpAddr,
        session_id: String,
        limits: LoginSessionConfig,
        reply: oneshot::Sender<Result<LoginSessionUse, LoginSessionError>>,
    },
    Invalidate {
        session_id: String,
    },
}

struct LoginSessionRecord {
    ip: IpAddr,
    return_path: Option<String>,
    expires_at: Instant,
    connection_id: u32,
    workflow_counter: WorkflowCounter,
}

struct IpRateState {
    window_start: Instant,
    issued_count: u32,
    used_count: u32,
    blocked_until: Option<Instant>,
}

impl IpRateState {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            issued_count: 0,
            used_count: 0,
            blocked_until: None,
        }
    }

    fn refresh_window(&mut self, now: Instant, period: Duration) {
        if now.duration_since(self.window_start) >= period {
            self.window_start = now;
            self.issued_count = 0;
            self.used_count = 0;
        }
    }

    fn is_blocked(&mut self, now: Instant) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            if now < blocked_until {
                return true;
            }
            self.blocked_until = None;
            self.issued_count = 0;
            self.used_count = 0;
        }
        false
    }
}

struct LoginSessionState {
    sessions: HashMap<String, LoginSessionRecord>,
    session_order: VecDeque<String>,
    rate_limits: HashMap<IpAddr, IpRateState>,
}

impl LoginSessionState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_order: VecDeque::new(),
            rate_limits: HashMap::new(),
        }
    }

    async fn run(&mut self, mut receiver: mpsc::Receiver<LoginSessionCommand>) {
        while let Some(command) = receiver.recv().await {
            match command {
                LoginSessionCommand::Issue {
                    ip,
                    return_path,
                    limits,
                    reply,
                } => {
                    let _ = reply.send(self.issue_session(ip, return_path, limits));
                }
                LoginSessionCommand::Use {
                    ip,
                    session_id,
                    limits,
                    reply,
                } => {
                    let _ = reply.send(self.use_session(ip, &session_id, limits));
                }
                LoginSessionCommand::Invalidate { session_id } => {
                    self.invalidate_session(&session_id);
                }
            }
        }
    }

    fn invalidate_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
        self.session_order.retain(|id| id != session_id);
    }

    fn issue_session(
        &mut self,
        ip: IpAddr,
        return_path: Option<String>,
        limits: LoginSessionConfig,
    ) -> Result<LoginSessionIssue, LoginSessionError> {
        let now = Instant::now();
        self.cleanup_expired(now);

        let period = Duration::from_secs(limits.period_seconds);
        let lockout = Duration::from_secs(limits.lockout_seconds);
        let state = self
            .rate_limits
            .entry(ip)
            .or_insert_with(|| IpRateState::new(now));
        state.refresh_window(now, period);
        if state.is_blocked(now) {
            return Err(LoginSessionError::RateLimited);
        }
        state.issued_count = state.issued_count.saturating_add(1);
        if state.issued_count > limits.id_requests {
            state.blocked_until = Some(now + lockout);
            return Err(LoginSessionError::RateLimited);
        }

        let session_id = generate_session_id();
        let expires_at = now + Duration::from_secs(LOGIN_SESSION_TTL_SECONDS);
        self.sessions.insert(
            session_id.clone(),
            LoginSessionRecord {
                ip,
                return_path: return_path.clone(),
                expires_at,
                connection_id: next_connection_id(),
                workflow_counter: WorkflowCounter::new(),
            },
        );
        self.session_order.push_back(session_id.clone());
        self.prune_overflow();

        Ok(LoginSessionIssue {
            login_session_id: session_id,
            return_path,
            expires_in_seconds: LOGIN_SESSION_TTL_SECONDS,
        })
    }

    fn use_session(
        &mut self,
        ip: IpAddr,
        session_id: &str,
        limits: LoginSessionConfig,
    ) -> Result<LoginSessionUse, LoginSessionError> {
        let now = Instant::now();
        self.cleanup_expired(now);

        let record = match self.sessions.get(session_id) {
            Some(record) => record,
            None => return Err(LoginSessionError::InvalidSession),
        };
        if record.ip != ip {
            return Err(LoginSessionError::InvalidSession);
        }
        if record.expires_at <= now {
            self.sessions.remove(session_id);
            return Err(LoginSessionError::InvalidSession);
        }
        let period = Duration::from_secs(limits.period_seconds);
        let lockout = Duration::from_secs(limits.lockout_seconds);
        let state = self
            .rate_limits
            .entry(ip)
            .or_insert_with(|| IpRateState::new(now));
        state.refresh_window(now, period);
        if state.is_blocked(now) {
            return Err(LoginSessionError::RateLimited);
        }
        state.used_count = state.used_count.saturating_add(1);
        if state.used_count > limits.id_requests {
            state.blocked_until = Some(now + lockout);
            return Err(LoginSessionError::RateLimited);
        }

        let record = match self.sessions.get_mut(session_id) {
            Some(record) => record,
            None => return Err(LoginSessionError::InvalidSession),
        };
        let workflow_id = record
            .workflow_counter
            .next_id()
            .map_err(|_| LoginSessionError::InvalidSession)?;

        Ok(LoginSessionUse {
            return_path: record.return_path.clone(),
            connection_id: record.connection_id,
            workflow_id,
        })
    }

    fn cleanup_expired(&mut self, now: Instant) {
        self.sessions.retain(|_, record| record.expires_at > now);
        self.session_order
            .retain(|id| self.sessions.contains_key(id));
    }

    fn prune_overflow(&mut self) {
        while self.sessions.len() > MAX_LOGIN_SESSIONS {
            if let Some(oldest) = self.session_order.pop_front() {
                self.sessions.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

fn generate_session_id() -> String {
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    format!("lsn_{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn invalidate_removes_session_order_entry() {
        let mut state = LoginSessionState::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let session_id = "lsn_test";
        state.sessions.insert(
            session_id.to_string(),
            LoginSessionRecord {
                ip,
                return_path: None,
                expires_at: Instant::now() + Duration::from_secs(60),
                connection_id: next_connection_id(),
                workflow_counter: WorkflowCounter::new(),
            },
        );
        state.session_order.push_back(session_id.to_string());

        state.invalidate_session(session_id);

        assert!(!state.sessions.contains_key(session_id));
        assert!(state.session_order.is_empty());
    }

    #[test]
    fn use_session_increments_workflow_id() {
        let mut state = LoginSessionState::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");
        let limits = LoginSessionConfig {
            period_seconds: 60,
            id_requests: 10,
            lockout_seconds: 60,
        };

        let issue = state
            .issue_session(ip, None, limits.clone())
            .expect("issue");
        let first = state
            .use_session(ip, &issue.login_session_id, limits.clone())
            .expect("first");
        let second = state
            .use_session(ip, &issue.login_session_id, limits)
            .expect("second");

        assert_eq!(first.connection_id, second.connection_id);
        assert!(second.workflow_id > first.workflow_id);
    }
}
