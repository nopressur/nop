// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::codec::{CodecRegistry, RequestCodec, ResponseCodec};
use crate::management::core::{ManagementContext, ManagementRequest, ManagementResponse};
use crate::management::errors::DomainResult;
use futures_util::future::BoxFuture;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainActionKey {
    pub domain_id: u32,
    pub action_id: u32,
}

impl DomainActionKey {
    pub fn new(domain_id: u32, action_id: u32) -> Self {
        Self {
            domain_id,
            action_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActionDescriptor {
    pub name: &'static str,
    pub id: u32,
}

#[derive(Debug, Clone)]
pub struct DomainDescriptor {
    pub name: &'static str,
    pub id: u32,
    pub actions: Vec<ActionDescriptor>,
}

#[derive(Debug)]
pub struct RegistryError {
    message: String,
}

impl RegistryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "registry error: {}", self.message)
    }
}

impl Error for RegistryError {}

pub type ManagementHandler = Arc<
    dyn Fn(
            ManagementRequest,
            Arc<ManagementContext>,
        ) -> BoxFuture<'static, DomainResult<ManagementResponse>>
        + Send
        + Sync,
>;

pub struct ManagementRegistry {
    handlers: BTreeMap<DomainActionKey, ManagementHandler>,
    codecs: CodecRegistry,
    domains: BTreeMap<u32, DomainDescriptor>,
}

impl Default for ManagementRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagementRegistry {
    pub fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
            codecs: CodecRegistry::new(),
            domains: BTreeMap::new(),
        }
    }

    pub fn register_domain(&mut self, domain: DomainDescriptor) -> Result<(), RegistryError> {
        if self.domains.contains_key(&domain.id) {
            return Err(RegistryError::new(format!(
                "Domain ID {} already registered",
                domain.id
            )));
        }
        self.domains.insert(domain.id, domain);
        Ok(())
    }

    pub fn domains(&self) -> Vec<DomainDescriptor> {
        self.domains.values().cloned().collect()
    }

    pub fn register_handler(
        &mut self,
        key: DomainActionKey,
        handler: ManagementHandler,
    ) -> Result<(), RegistryError> {
        if self.handlers.contains_key(&key) {
            return Err(RegistryError::new(format!(
                "Handler already registered for domain {} action {}",
                key.domain_id, key.action_id
            )));
        }
        self.handlers.insert(key, handler);
        Ok(())
    }

    pub fn handler(&self, key: &DomainActionKey) -> Option<&ManagementHandler> {
        self.handlers.get(key)
    }

    pub fn register_request_codec(
        &mut self,
        codec: Arc<dyn RequestCodec>,
    ) -> Result<(), RegistryError> {
        self.codecs.register_request_codec(codec)
    }

    pub fn register_response_codec(
        &mut self,
        codec: Arc<dyn ResponseCodec>,
    ) -> Result<(), RegistryError> {
        self.codecs.register_response_codec(codec)
    }

    pub fn codec_registry(&self) -> &CodecRegistry {
        &self.codecs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::system::{SYSTEM_ACTION_PING, SYSTEM_DOMAIN_ID};

    #[test]
    fn register_domain_rejects_duplicates() {
        let mut registry = ManagementRegistry::new();
        registry
            .register_domain(DomainDescriptor {
                name: "system",
                id: SYSTEM_DOMAIN_ID,
                actions: vec![ActionDescriptor {
                    name: "ping",
                    id: SYSTEM_ACTION_PING,
                }],
            })
            .expect("first registration ok");

        let err = registry
            .register_domain(DomainDescriptor {
                name: "system",
                id: SYSTEM_DOMAIN_ID,
                actions: vec![],
            })
            .expect_err("duplicate domain rejected");

        assert!(err.to_string().contains("already registered"));
    }
}
