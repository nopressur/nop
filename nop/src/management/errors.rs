// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementErrorKind {
    NotFound,
    Validation,
    Internal,
    Busy,
    Codec,
    VersionMismatch,
}

#[derive(Debug, Clone)]
pub struct ManagementError {
    kind: ManagementErrorKind,
    domain_id: Option<u32>,
    action_id: Option<u32>,
    message: String,
}

impl ManagementError {
    pub fn new(
        kind: ManagementErrorKind,
        domain_id: Option<u32>,
        action_id: Option<u32>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            domain_id,
            action_id,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> ManagementErrorKind {
        self.kind
    }

    pub fn domain_id(&self) -> Option<u32> {
        self.domain_id
    }

    pub fn action_id(&self) -> Option<u32> {
        self.action_id
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn with_request(mut self, domain_id: u32, action_id: u32) -> Self {
        self.domain_id = Some(domain_id);
        self.action_id = Some(action_id);
        self
    }
}

impl fmt::Display for ManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.domain_id, self.action_id) {
            (Some(domain_id), Some(action_id)) => write!(
                f,
                "{:?} error for domain {} action {}: {}",
                self.kind, domain_id, action_id, self.message
            ),
            _ => write!(f, "{:?} error: {}", self.kind, self.message),
        }
    }
}

impl Error for ManagementError {}

pub trait DomainError: fmt::Display + Send + Sync + 'static {
    fn kind(&self) -> ManagementErrorKind;
}

pub type DomainResult<T> = Result<T, Box<dyn DomainError>>;
