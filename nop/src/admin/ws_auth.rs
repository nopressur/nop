// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::ValidatedConfig;
use crate::iam::middleware::AuthRequest;
use crate::util::{CSRF_HEADER_NAME, CsrfTokenStore, ValidatedCsrfToken, WsTicketStore};
use actix_web::{HttpMessage, HttpRequest, HttpResponse};
use serde_json::json;

pub enum WsAuthError {
    InvalidCsrf,
    InvalidTicket,
}

impl WsAuthError {
    pub fn log_message(&self) -> &'static str {
        match self {
            WsAuthError::InvalidCsrf => "Admin WS CSRF validation failed",
            WsAuthError::InvalidTicket => "Admin WS ticket validation failed",
        }
    }

    pub fn client_message(&self) -> &'static str {
        match self {
            WsAuthError::InvalidCsrf => "CSRF token validation failed",
            WsAuthError::InvalidTicket => "Ticket validation failed",
        }
    }
}

pub fn require_validated_csrf(req: &HttpRequest) -> Result<(), HttpResponse> {
    if req.extensions().get::<ValidatedCsrfToken>().is_none() {
        log::warn!("Admin WS ticket request missing CSRF token");
        return Err(HttpResponse::BadRequest().json(json!({
            "error": format!("{} header required", CSRF_HEADER_NAME)
        })));
    }
    Ok(())
}

pub fn resolve_jwt_id(req: &HttpRequest, config: &ValidatedConfig) -> Option<String> {
    if let Some(jwt_id) = req.jwt_id() {
        return Some(jwt_id);
    }
    if crate::security::is_dev_mode_bypass_allowed(req, config) {
        return Some("localhost".to_string());
    }
    None
}

pub fn validate_auth_frame(
    csrf_store: &CsrfTokenStore,
    ticket_store: &WsTicketStore,
    jwt_id: &str,
    csrf_token: &str,
    ticket: &str,
) -> Result<(), WsAuthError> {
    if !csrf_store.validate_and_renew_token(csrf_token, jwt_id) {
        return Err(WsAuthError::InvalidCsrf);
    }
    if !ticket_store.validate_and_consume(ticket, jwt_id) {
        return Err(WsAuthError::InvalidTicket);
    }
    Ok(())
}
