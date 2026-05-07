// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop_management_contract::codec::{RequestCodec, ResponseCodec};
use nop_management_contract::registry::DomainActionKey;
use std::collections::BTreeMap;

#[cfg(test)]
use nop_management_contract::codec::{FieldLimit, FieldLimits, FieldValues, validate_field_limits};

#[derive(Default)]
pub struct CodecRegistry {
    request_codecs: BTreeMap<DomainActionKey, std::sync::Arc<dyn RequestCodec>>,
    response_codecs: BTreeMap<DomainActionKey, std::sync::Arc<dyn ResponseCodec>>,
}

impl CodecRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_request_codec(
        &mut self,
        codec: std::sync::Arc<dyn RequestCodec>,
    ) -> Result<(), crate::RegistryError> {
        let key = codec.key();
        if self.request_codecs.contains_key(&key) {
            return Err(crate::RegistryError::new(format!(
                "Request codec already registered for domain {} action {}",
                key.domain_id, key.action_id
            )));
        }
        self.request_codecs.insert(key, codec);
        Ok(())
    }

    pub fn register_response_codec(
        &mut self,
        codec: std::sync::Arc<dyn ResponseCodec>,
    ) -> Result<(), crate::RegistryError> {
        let key = codec.key();
        if self.response_codecs.contains_key(&key) {
            return Err(crate::RegistryError::new(format!(
                "Response codec already registered for domain {} action {}",
                key.domain_id, key.action_id
            )));
        }
        self.response_codecs.insert(key, codec);
        Ok(())
    }

    pub fn request_codec(
        &self,
        key: &DomainActionKey,
    ) -> Option<&std::sync::Arc<dyn RequestCodec>> {
        self.request_codecs.get(key)
    }

    pub fn response_codec(
        &self,
        key: &DomainActionKey,
    ) -> Option<&std::sync::Arc<dyn ResponseCodec>> {
        self.response_codecs.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nop_management_contract::system::{SYSTEM_ACTION_PING, SYSTEM_DOMAIN_ID};

    #[test]
    fn field_limits_enforce_bounds() {
        let limits = FieldLimits::new(vec![
            ("name", FieldLimit::Range { min: 2, max: 4 }),
            ("roles", FieldLimit::MaxEntries(2)),
            ("role", FieldLimit::MaxChars(3)),
        ]);

        let mut values = FieldValues::new();
        values.insert_len("name", 1);
        let err = validate_field_limits(&limits, &values).unwrap_err();
        assert!(err.to_string().contains("between 2 and 4"));

        let mut values = FieldValues::new();
        values.insert_len("name", 5);
        let err = validate_field_limits(&limits, &values).unwrap_err();
        assert!(err.to_string().contains("between 2 and 4"));

        let mut values = FieldValues::new();
        values.insert_len("name", 3);
        values.insert_count("roles", 3);
        let err = validate_field_limits(&limits, &values).unwrap_err();
        assert!(err.to_string().contains("at most 2 entries"));

        let mut values = FieldValues::new();
        values.insert_len("name", 3);
        values.insert_count("roles", 1);
        values.insert_lens("role", vec![4]);
        let err = validate_field_limits(&limits, &values).unwrap_err();
        assert!(err.to_string().contains("at most 3 characters"));
    }

    #[test]
    fn domain_action_key_is_stable() {
        let key = DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PING);
        assert_eq!(key.domain_id, SYSTEM_DOMAIN_ID);
        assert_eq!(key.action_id, SYSTEM_ACTION_PING);
    }
}
