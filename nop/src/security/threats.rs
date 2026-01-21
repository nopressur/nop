// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{DevMode, ValidatedConfig};
use crate::public::error::{self, ErrorRenderer};
use crate::templates::TemplateEngine;
use actix_web::{HttpRequest, HttpResponse, Result};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone)]
struct ViolationRecord {
    count: u32,
    last_violation: SystemTime,
    blocked_until: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy)]
enum ViolationKind {
    PathTraversal,
    LoginFailure,
}

enum ThreatCommand {
    Check {
        ip: IpAddr,
        reply: oneshot::Sender<Option<SystemTime>>,
    },
    Record {
        ip: IpAddr,
        kind: ViolationKind,
        detail: String,
        max_violations: u32,
        cooldown_seconds: u64,
    },
}

pub struct ThreatTracker {
    sender: mpsc::UnboundedSender<ThreatCommand>,
}

impl ThreatTracker {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        actix_web::rt::spawn(async move {
            let mut state = ThreatTrackerState::new();
            state.run(receiver).await;
        });
        Self { sender }
    }

    async fn check_blocked(&self, ip: IpAddr) -> Option<SystemTime> {
        let (reply, receive) = oneshot::channel();
        if self
            .sender
            .send(ThreatCommand::Check { ip, reply })
            .is_err()
        {
            warn!("ThreatTracker channel closed while checking IP");
            return None;
        }
        match receive.await {
            Ok(result) => result,
            Err(_) => {
                warn!("ThreatTracker check response dropped");
                None
            }
        }
    }

    fn record_violation(
        &self,
        ip: IpAddr,
        kind: ViolationKind,
        detail: String,
        max_violations: u32,
        cooldown_seconds: u64,
    ) {
        if self
            .sender
            .send(ThreatCommand::Record {
                ip,
                kind,
                detail,
                max_violations,
                cooldown_seconds,
            })
            .is_err()
        {
            warn!("ThreatTracker channel closed while recording violation");
        }
    }
}

impl Default for ThreatTracker {
    fn default() -> Self {
        Self::new()
    }
}

struct ThreatTrackerState {
    records: HashMap<IpAddr, ViolationRecord>,
}

impl ThreatTrackerState {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    async fn run(&mut self, mut receiver: mpsc::UnboundedReceiver<ThreatCommand>) {
        while let Some(command) = receiver.recv().await {
            match command {
                ThreatCommand::Check { ip, reply } => {
                    let now = SystemTime::now();
                    let mut blocked_until = None;

                    if let Some(record) = self.records.get_mut(&ip)
                        && let Some(blocked) = record.blocked_until
                    {
                        if now < blocked {
                            blocked_until = Some(blocked);
                        } else {
                            record.count = 0;
                            record.blocked_until = None;
                            info!("🔓 IP {} cooldown expired, violations reset", ip);
                        }
                    }

                    let _ = reply.send(blocked_until);
                }
                ThreatCommand::Record {
                    ip,
                    kind,
                    detail,
                    max_violations,
                    cooldown_seconds,
                } => {
                    let now = SystemTime::now();
                    let record = self.records.entry(ip).or_insert(ViolationRecord {
                        count: 0,
                        last_violation: now,
                        blocked_until: None,
                    });

                    record.count += 1;
                    record.last_violation = now;

                    match kind {
                        ViolationKind::PathTraversal => {
                            warn!(
                                "🚨 SECURITY THREAT: Path traversal violation #{} from IP {} - path: {}",
                                record.count, ip, detail
                            );
                        }
                        ViolationKind::LoginFailure => {
                            warn!(
                                "🚨 SECURITY THREAT: Login failure #{} from IP {} - reason: {}",
                                record.count, ip, detail
                            );
                        }
                    }

                    if record.count >= max_violations {
                        let cooldown_duration = Duration::from_secs(cooldown_seconds);
                        record.blocked_until = Some(now + cooldown_duration);

                        warn!(
                            "🚫 SECURITY ALERT: IP {} BLOCKED for {} seconds after {} violations",
                            ip, cooldown_seconds, record.count
                        );

                        info!(
                            "SECURITY_EVENT_BLOCK: IP={} violations={} cooldown_seconds={} last_event={}",
                            ip, record.count, cooldown_seconds, detail
                        );
                    }
                }
            }
        }
    }
}

/// Extracts the real client IP address from the request, considering X-Forwarded-For headers if configured
pub fn extract_client_ip(req: &HttpRequest, config: &ValidatedConfig) -> Option<IpAddr> {
    if config.security.use_forwarded_for {
        // Check X-Forwarded-For header first
        if let Some(forwarded_for) = req.headers().get("x-forwarded-for")
            && let Ok(header_value) = forwarded_for.to_str()
            && let Some(first_ip) = header_value.split(',').next()
            && let Ok(ip) = first_ip.trim().parse::<IpAddr>()
        {
            // Take the first IP from the comma-separated list (leftmost is the original client)
            return Some(ip);
        }

        // Check X-Real-IP header as fallback
        if let Some(real_ip) = req.headers().get("x-real-ip")
            && let Ok(header_value) = real_ip.to_str()
            && let Ok(ip) = header_value.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
    }

    // Fall back to connection info
    if let Some(peer_addr) = req.connection_info().peer_addr()
        && let Some(ip_str) = peer_addr.split(':').next()
        && let Ok(ip) = ip_str.parse::<IpAddr>()
    {
        // Handle both IPv4 and IPv6 addresses with ports
        return Some(ip);
    }

    if let Some(peer_addr) = req.connection_info().peer_addr()
        && let Ok(ip) = peer_addr.parse::<IpAddr>()
    {
        // Try parsing the full address as IP (in case there's no port)
        return Some(ip);
    }

    warn!("Could not extract client IP from request");
    None
}

/// Checks if an IP is currently blocked due to violations
pub async fn is_ip_blocked(
    tracker: &ThreatTracker,
    req: &HttpRequest,
    config: &ValidatedConfig,
    error_renderer: &ErrorRenderer,
    template_engine: Option<&dyn TemplateEngine>,
) -> Option<Result<HttpResponse>> {
    let client_ip = extract_client_ip(req, config)?;

    if let Some(blocked_until) = tracker.check_blocked(client_ip).await {
        warn!(
            "🚫 SECURITY THREAT: Blocked IP {} attempted access (blocked until {:?})",
            client_ip, blocked_until
        );
        return Some(error::serve_404(error_renderer, template_engine));
    }

    None
}

/// Records a path traversal violation for an IP address
pub fn record_violation(
    tracker: &ThreatTracker,
    req: &HttpRequest,
    config: &ValidatedConfig,
    path: &str,
) {
    let client_ip = match extract_client_ip(req, config) {
        Some(ip) => ip,
        None => {
            warn!(
                "🚨 SECURITY THREAT: Path traversal attempt from unknown IP - path: {}",
                path
            );
            return;
        }
    };

    tracker.record_violation(
        client_ip,
        ViolationKind::PathTraversal,
        path.to_string(),
        config.security.max_violations,
        config.security.cooldown_seconds,
    );
}

/// Records a login failure for an IP address.
pub fn record_login_failure(
    tracker: &ThreatTracker,
    req: &HttpRequest,
    config: &ValidatedConfig,
    reason: &str,
) {
    let client_ip = match extract_client_ip(req, config) {
        Some(ip) => ip,
        None => {
            warn!(
                "🚨 SECURITY THREAT: Login failure from unknown IP - reason: {}",
                reason
            );
            return;
        }
    };

    tracker.record_violation(
        client_ip,
        ViolationKind::LoginFailure,
        reason.to_string(),
        config.security.max_violations,
        config.security.cooldown_seconds,
    );
}

/// Check if development mode allows bypassing access controls
pub fn is_dev_mode_bypass_allowed(req: &HttpRequest, config: &ValidatedConfig) -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }

    match &config.dev_mode {
        Some(DevMode::Dangerous) => {
            // Log warning about dangerous mode usage
            warn!("🚨 DEV MODE: Dangerous mode active - bypassing ALL access controls");
            true
        }
        Some(DevMode::Localhost) => {
            if let Some(client_ip) = extract_client_ip(req, config) {
                let is_localhost = client_ip.is_loopback();
                if is_localhost {
                    debug!(
                        "🔧 DEV MODE: Localhost mode active - bypassing access controls for {}",
                        client_ip
                    );
                }
                is_localhost
            } else {
                false
            }
        }
        None => false, // Normal access controls
    }
}
