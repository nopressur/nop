// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::LoginSessionConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

const ACTION_LIMIT_CHANNEL_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthAction {
    LoginCsrfToken,
    ProfilePasswordSalt,
    ProfilePasswordChange,
}

impl AuthAction {}

#[derive(Debug)]
pub enum AuthActionError {
    RateLimited,
}

impl AuthActionError {
    pub fn code(&self) -> &'static str {
        match self {
            AuthActionError::RateLimited => "auth_rate_limited",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            AuthActionError::RateLimited => "Too many requests. Please try again later.",
        }
    }
}

#[derive(Clone)]
pub struct AuthActionLimiter {
    sender: mpsc::Sender<AuthActionCommand>,
}

impl AuthActionLimiter {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(ACTION_LIMIT_CHANNEL_DEPTH);
        tokio::spawn(async move {
            let mut state = AuthActionState::new();
            state.run(receiver).await;
        });
        Self { sender }
    }

    pub async fn check(
        &self,
        action: AuthAction,
        ip: IpAddr,
        user_key: Option<String>,
        limits: &LoginSessionConfig,
    ) -> Result<(), AuthActionError> {
        let (reply, receive) = oneshot::channel();
        let command = AuthActionCommand::Check {
            action,
            ip,
            user_key,
            limits: limits.clone(),
            reply,
        };
        if self.sender.send(command).await.is_err() {
            return Err(AuthActionError::RateLimited);
        }
        receive.await.unwrap_or(Err(AuthActionError::RateLimited))
    }
}

impl Default for AuthActionLimiter {
    fn default() -> Self {
        Self::new()
    }
}

enum AuthActionCommand {
    Check {
        action: AuthAction,
        ip: IpAddr,
        user_key: Option<String>,
        limits: LoginSessionConfig,
        reply: oneshot::Sender<Result<(), AuthActionError>>,
    },
}

#[derive(Hash, PartialEq, Eq)]
struct AuthActionKey {
    action: AuthAction,
    ip: IpAddr,
    user_key: Option<String>,
}

struct RateState {
    window_start: Instant,
    count: u32,
    blocked_until: Option<Instant>,
}

impl RateState {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            count: 0,
            blocked_until: None,
        }
    }

    fn refresh_window(&mut self, now: Instant, period: Duration) {
        if now.duration_since(self.window_start) >= period {
            self.window_start = now;
            self.count = 0;
        }
    }

    fn is_blocked(&mut self, now: Instant) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            if now < blocked_until {
                return true;
            }
            self.blocked_until = None;
            self.count = 0;
        }
        false
    }
}

struct AuthActionState {
    rate_limits: HashMap<AuthActionKey, RateState>,
}

impl AuthActionState {
    fn new() -> Self {
        Self {
            rate_limits: HashMap::new(),
        }
    }

    async fn run(&mut self, mut receiver: mpsc::Receiver<AuthActionCommand>) {
        while let Some(command) = receiver.recv().await {
            match command {
                AuthActionCommand::Check {
                    action,
                    ip,
                    user_key,
                    limits,
                    reply,
                } => {
                    let _ = reply.send(self.check_request(action, ip, user_key.as_deref(), limits));
                }
            }
        }
    }

    fn check_request(
        &mut self,
        action: AuthAction,
        ip: IpAddr,
        user_key: Option<&str>,
        limits: LoginSessionConfig,
    ) -> Result<(), AuthActionError> {
        let now = Instant::now();
        let period = Duration::from_secs(limits.period_seconds);
        let lockout = Duration::from_secs(limits.lockout_seconds);

        if !self.apply_limit(
            AuthActionKey {
                action,
                ip,
                user_key: None,
            },
            now,
            period,
            lockout,
            limits.id_requests,
        ) {
            return Err(AuthActionError::RateLimited);
        }

        if let Some(user_key) = user_key
            && !self.apply_limit(
                AuthActionKey {
                    action,
                    ip,
                    user_key: Some(user_key.to_string()),
                },
                now,
                period,
                lockout,
                limits.id_requests,
            )
        {
            return Err(AuthActionError::RateLimited);
        }

        Ok(())
    }

    fn apply_limit(
        &mut self,
        key: AuthActionKey,
        now: Instant,
        period: Duration,
        lockout: Duration,
        limit: u32,
    ) -> bool {
        let state = self
            .rate_limits
            .entry(key)
            .or_insert_with(|| RateState::new(now));
        state.refresh_window(now, period);
        if state.is_blocked(now) {
            return false;
        }
        state.count = state.count.saturating_add(1);
        if state.count > limit {
            state.blocked_until = Some(now + lockout);
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[actix_web::test]
    async fn auth_action_limiter_rate_limits() {
        let limiter = AuthActionLimiter::new();
        let limits = LoginSessionConfig {
            period_seconds: 300,
            id_requests: 1,
            lockout_seconds: 60,
        };
        let ip: IpAddr = "127.0.0.1".parse().expect("ip");

        assert!(
            limiter
                .check(AuthAction::LoginCsrfToken, ip, None, &limits)
                .await
                .is_ok()
        );
        assert!(matches!(
            limiter
                .check(AuthAction::LoginCsrfToken, ip, None, &limits)
                .await,
            Err(AuthActionError::RateLimited)
        ));
    }
}
