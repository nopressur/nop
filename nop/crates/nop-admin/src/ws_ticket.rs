// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const WS_TICKET_EXPIRY_SECONDS: u64 = 20;

#[derive(Clone, Debug)]
struct TicketData {
    created_at: Instant,
    jwt_id: String,
}

#[derive(Clone)]
pub struct WsTicketStore {
    sender: mpsc::Sender<WsTicketCommand>,
    expiry: Duration,
}

enum WsTicketCommand {
    Issue {
        jwt_id: String,
        reply: mpsc::Sender<String>,
    },
    Validate {
        ticket: String,
        jwt_id: String,
        reply: mpsc::Sender<bool>,
    },
}

impl WsTicketStore {
    pub fn new() -> Self {
        Self::new_with_expiry_inner(Duration::from_secs(WS_TICKET_EXPIRY_SECONDS))
    }

    #[cfg(test)]
    pub fn new_with_expiry(expiry: Duration) -> Self {
        Self::new_with_expiry_inner(expiry)
    }

    fn new_with_expiry_inner(expiry: Duration) -> Self {
        let sender = start_ws_ticket_worker(expiry);
        Self { sender, expiry }
    }

    pub fn issue(&self, jwt_id: &str) -> String {
        self.request(
            |reply| WsTicketCommand::Issue {
                jwt_id: jwt_id.to_string(),
                reply,
            },
            String::new(),
        )
    }

    pub fn expiry_seconds(&self) -> u64 {
        self.expiry.as_secs()
    }

    pub fn validate_and_consume(&self, ticket: &str, jwt_id: &str) -> bool {
        self.request(
            |reply| WsTicketCommand::Validate {
                ticket: ticket.to_string(),
                jwt_id: jwt_id.to_string(),
                reply,
            },
            false,
        )
    }

    fn request<T>(&self, build: impl FnOnce(mpsc::Sender<T>) -> WsTicketCommand, fallback: T) -> T {
        let (reply, receive) = mpsc::channel();
        if self.sender.send(build(reply)).is_err() {
            log::error!("🚨 CRITICAL: WsTicketStore channel closed");
            return fallback;
        }
        receive.recv().unwrap_or(fallback)
    }
}

fn start_ws_ticket_worker(expiry: Duration) -> mpsc::Sender<WsTicketCommand> {
    let (sender, receiver) = mpsc::channel();
    let thread = thread::Builder::new().name("ws-ticket-store".to_string());
    if let Err(err) = thread.spawn(move || run_ws_ticket_worker(receiver, expiry)) {
        log::error!("WsTicketStore worker failed to start: {}", err);
    }
    sender
}

fn run_ws_ticket_worker(receiver: mpsc::Receiver<WsTicketCommand>, expiry: Duration) {
    let mut tickets: HashMap<String, TicketData> = HashMap::new();
    while let Ok(command) = receiver.recv() {
        let now = Instant::now();
        cleanup_expired(&mut tickets, now, expiry);
        match command {
            WsTicketCommand::Issue { jwt_id, reply } => {
                let ticket = Uuid::new_v4().to_string();
                tickets.insert(
                    ticket.clone(),
                    TicketData {
                        created_at: now,
                        jwt_id: jwt_id.clone(),
                    },
                );
                let _ = reply.send(ticket);
            }
            WsTicketCommand::Validate {
                ticket,
                jwt_id,
                reply,
            } => {
                let is_valid = match tickets.get(&ticket) {
                    Some(data) => {
                        if data.jwt_id != jwt_id {
                            tickets.remove(&ticket);
                            false
                        } else {
                            let valid = data.created_at.elapsed() < expiry;
                            tickets.remove(&ticket);
                            valid
                        }
                    }
                    None => false,
                };
                let _ = reply.send(is_valid);
            }
        }
    }
}

fn cleanup_expired(tickets: &mut HashMap<String, TicketData>, now: Instant, expiry: Duration) {
    tickets.retain(|_, data| now.duration_since(data.created_at) < expiry);
}

impl Default for WsTicketStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn ticket_consumes_once() {
        let store = WsTicketStore::new_with_expiry(Duration::from_secs(5));
        let ticket = store.issue("user-1");
        assert!(store.validate_and_consume(&ticket, "user-1"));
        assert!(!store.validate_and_consume(&ticket, "user-1"));
    }

    #[test]
    fn ticket_expires() {
        let store = WsTicketStore::new_with_expiry(Duration::from_millis(50));
        let ticket = store.issue("user-1");
        thread::sleep(Duration::from_millis(60));
        assert!(!store.validate_and_consume(&ticket, "user-1"));
    }

    #[test]
    fn ticket_rejects_wrong_jwt() {
        let store = WsTicketStore::new_with_expiry(Duration::from_secs(5));
        let ticket = store.issue("user-1");
        assert!(!store.validate_and_consume(&ticket, "user-2"));
    }
}
