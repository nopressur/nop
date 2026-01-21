// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::management::errors::ManagementErrorKind;
use crate::management::registry::DomainActionKey;
use crate::management::wire::{WireDecode, WireEncode, WireReader, WireWriter};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct CodecError {
    kind: ManagementErrorKind,
    message: String,
}

impl CodecError {
    pub fn new(kind: ManagementErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> ManagementErrorKind {
        self.kind
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "codec error: {}", self.message)
    }
}

impl Error for CodecError {}

#[derive(Debug, Clone)]
pub enum FieldLimit {
    MaxChars(usize),
    MaxEntries(usize),
    Range { min: usize, max: usize },
}

#[derive(Debug, Clone)]
pub struct FieldLimits {
    fields: BTreeMap<&'static str, FieldLimit>,
}

impl FieldLimits {
    pub fn new(entries: Vec<(&'static str, FieldLimit)>) -> Self {
        let mut fields = BTreeMap::new();
        for (name, limit) in entries {
            fields.insert(name, limit);
        }
        Self { fields }
    }

    pub fn fields(&self) -> &BTreeMap<&'static str, FieldLimit> {
        &self.fields
    }
}

#[derive(Debug, Clone)]
pub enum FieldValue {
    Len(usize),
    Count(usize),
    Lens(Vec<usize>),
}

#[derive(Debug, Default, Clone)]
pub struct FieldValues {
    values: BTreeMap<&'static str, FieldValue>,
}

impl FieldValues {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_len(&mut self, name: &'static str, len: usize) {
        self.values.insert(name, FieldValue::Len(len));
    }

    pub fn insert_count(&mut self, name: &'static str, count: usize) {
        self.values.insert(name, FieldValue::Count(count));
    }

    pub fn insert_lens(&mut self, name: &'static str, lens: Vec<usize>) {
        self.values.insert(name, FieldValue::Lens(lens));
    }

    pub fn get(&self, name: &'static str) -> Option<&FieldValue> {
        self.values.get(name)
    }
}

pub fn validate_field_limits(limits: &FieldLimits, values: &FieldValues) -> Result<(), CodecError> {
    for (name, limit) in limits.fields() {
        let value = match values.get(name) {
            Some(value) => value,
            None => continue,
        };
        match (limit, value) {
            (FieldLimit::MaxChars(max), FieldValue::Len(len)) => {
                if len > max {
                    return Err(CodecError::new(
                        ManagementErrorKind::Validation,
                        format!(
                            "{} must be at most {} characters (got {})",
                            display_field_name(name),
                            max,
                            len
                        ),
                    ));
                }
            }
            (FieldLimit::MaxChars(max), FieldValue::Lens(lens)) => {
                if let Some(len) = lens.iter().find(|len| *len > max) {
                    return Err(CodecError::new(
                        ManagementErrorKind::Validation,
                        format!(
                            "{} must be at most {} characters (got {})",
                            display_field_name(name),
                            max,
                            len
                        ),
                    ));
                }
            }
            (FieldLimit::Range { min, max }, FieldValue::Len(len)) => {
                if len < min || len > max {
                    return Err(CodecError::new(
                        ManagementErrorKind::Validation,
                        format!(
                            "{} must be between {} and {} characters (got {})",
                            display_field_name(name),
                            min,
                            max,
                            len
                        ),
                    ));
                }
            }
            (FieldLimit::MaxEntries(max), FieldValue::Count(count)) => {
                if count > max {
                    return Err(CodecError::new(
                        ManagementErrorKind::Validation,
                        format!(
                            "{} must be at most {} entries (got {})",
                            display_field_name(name),
                            max,
                            count
                        ),
                    ));
                }
            }
            (FieldLimit::MaxEntries(max), FieldValue::Lens(lens)) => {
                if lens.len() > *max {
                    return Err(CodecError::new(
                        ManagementErrorKind::Validation,
                        format!(
                            "{} must be at most {} entries (got {})",
                            display_field_name(name),
                            max,
                            lens.len()
                        ),
                    ));
                }
            }
            _ => {
                return Err(CodecError::new(
                    ManagementErrorKind::Internal,
                    format!("Field limit mismatch for '{}'", name),
                ));
            }
        }
    }
    Ok(())
}

fn display_field_name(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

pub trait RequestCodec: Send + Sync {
    fn key(&self) -> DomainActionKey;
    fn limits(&self) -> FieldLimits;
    fn decode(&self, payload: &[u8]) -> Result<crate::management::ManagementCommand, CodecError>;
    fn encode(&self, command: &crate::management::ManagementCommand)
    -> Result<Vec<u8>, CodecError>;
    fn validate(&self, _command: &crate::management::ManagementCommand) -> Result<(), CodecError> {
        Ok(())
    }
}

pub trait ResponseCodec: Send + Sync {
    fn key(&self) -> DomainActionKey;
    fn limits(&self) -> FieldLimits;
    fn encode(
        &self,
        response: &crate::management::ManagementResponse,
    ) -> Result<Vec<u8>, CodecError>;
    fn decode(&self, payload: &[u8]) -> Result<crate::management::ResponsePayload, CodecError>;
    fn validate(
        &self,
        _response: &crate::management::ManagementResponse,
    ) -> Result<(), CodecError> {
        Ok(())
    }
}

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
    ) -> Result<(), crate::management::RegistryError> {
        let key = codec.key();
        if self.request_codecs.contains_key(&key) {
            return Err(crate::management::RegistryError::new(format!(
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
    ) -> Result<(), crate::management::RegistryError> {
        let key = codec.key();
        if self.response_codecs.contains_key(&key) {
            return Err(crate::management::RegistryError::new(format!(
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

pub fn encode_payload<T: WireEncode>(payload: &T) -> Result<Vec<u8>, CodecError> {
    let mut writer = WireWriter::new();
    payload.encode(&mut writer).map_err(|err| {
        CodecError::new(
            ManagementErrorKind::Codec,
            format!("encode failed: {}", err),
        )
    })?;
    Ok(writer.into_bytes())
}

pub fn decode_payload<T: WireDecode>(payload: &[u8]) -> Result<T, CodecError> {
    let mut reader = WireReader::new(payload);
    let decoded = T::decode(&mut reader).map_err(|err| {
        CodecError::new(
            ManagementErrorKind::Codec,
            format!("decode failed: {}", err),
        )
    })?;
    reader.ensure_fully_consumed().map_err(|err| {
        CodecError::new(
            ManagementErrorKind::Codec,
            format!("decode failed: {}", err),
        )
    })?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::system::{PingRequest, SYSTEM_ACTION_PING, SYSTEM_DOMAIN_ID};

    #[test]
    fn encode_decode_payload_roundtrip() {
        let request = PingRequest {
            version_major: 1,
            version_minor: 2,
            version_patch: 3,
        };

        let encoded = encode_payload(&request).expect("encode ok");
        let decoded: PingRequest = decode_payload(&encoded).expect("decode ok");

        assert_eq!(decoded.version_major, 1);
        assert_eq!(decoded.version_minor, 2);
        assert_eq!(decoded.version_patch, 3);

        let key = DomainActionKey::new(SYSTEM_DOMAIN_ID, SYSTEM_ACTION_PING);
        assert_eq!(key.domain_id, SYSTEM_DOMAIN_ID);
        assert_eq!(key.action_id, SYSTEM_ACTION_PING);
    }

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
}
