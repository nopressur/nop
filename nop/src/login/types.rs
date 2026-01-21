// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginBootstrapRequest {
    pub return_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginBootstrapResponse {
    pub login_session_id: String,
    pub expires_in_seconds: u64,
    pub return_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordEmailRequest {
    pub login_session_id: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordEmailResponse {
    pub front_end_salt: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordLoginRequest {
    pub login_session_id: String,
    pub email: String,
    pub front_end_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginSuccessResponse {
    pub return_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileUpdateRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordSaltPayload {
    pub front_end_salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfilePasswordSaltResponse {
    pub change_token: String,
    pub current: PasswordSaltPayload,
    pub next: PasswordSaltPayload,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfilePasswordChangeRequest {
    pub change_token: String,
    pub current_front_end_hash: String,
    pub new_front_end_hash: String,
    pub new_front_end_salt: String,
}
