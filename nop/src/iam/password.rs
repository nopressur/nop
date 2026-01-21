// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{Argon2Params, PasswordHashingParams};
use crate::iam::types::PasswordProviderBlock;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    rand_core::RngCore,
};
use argon2::{Algorithm, Argon2, Params, Version};

#[derive(Debug)]
pub enum PasswordError {
    InvalidHex(String),
    HashError(String),
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::InvalidHex(msg) => write!(f, "{}", msg),
            PasswordError::HashError(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for PasswordError {}

pub fn derive_front_end_hash(
    password: &str,
    front_end_salt: &str,
    params: &Argon2Params,
) -> Result<String, PasswordError> {
    let salt_bytes = decode_hex(front_end_salt)?;
    let mut output = vec![0u8; params.output_len as usize];
    let argon2 = build_argon2(params)?;
    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut output)
        .map_err(|err| PasswordError::HashError(err.to_string()))?;
    Ok(hex::encode(output))
}

pub fn derive_back_end_hash(
    front_end_hash: &str,
    back_end_salt: &str,
    params: &Argon2Params,
) -> Result<String, PasswordError> {
    let front_end_bytes = decode_hex(front_end_hash)?;
    let salt_bytes = decode_hex(back_end_salt)?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|err| PasswordError::HashError(err.to_string()))?;
    let argon2 = build_argon2(params)?;
    let hash = argon2
        .hash_password(&front_end_bytes, &salt)
        .map_err(|err| PasswordError::HashError(err.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_front_end_hash(
    front_end_hash: &str,
    stored_hash: &str,
) -> Result<bool, PasswordError> {
    let front_end_bytes = decode_hex(front_end_hash)?;
    let parsed =
        PasswordHash::new(stored_hash).map_err(|err| PasswordError::HashError(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    Ok(argon2.verify_password(&front_end_bytes, &parsed).is_ok())
}

pub fn build_password_provider_block(
    password: &str,
    params: &PasswordHashingParams,
) -> Result<PasswordProviderBlock, PasswordError> {
    let front_end_salt = generate_salt_hex(params.front_end.salt_len)?;
    let back_end_salt = generate_salt_hex(params.back_end.salt_len)?;
    let front_end_hash = derive_front_end_hash(password, &front_end_salt, &params.front_end)?;
    let stored_hash = derive_back_end_hash(&front_end_hash, &back_end_salt, &params.back_end)?;

    Ok(PasswordProviderBlock {
        front_end_salt,
        back_end_salt,
        stored_hash,
    })
}

fn build_argon2(params: &Argon2Params) -> Result<Argon2<'static>, PasswordError> {
    let output_len = params.output_len as usize;
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(output_len),
    )
    .map_err(|err| PasswordError::HashError(err.to_string()))?;
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_params,
    ))
}

pub fn generate_salt_hex(length: u32) -> Result<String, PasswordError> {
    let mut bytes = vec![0u8; length as usize];
    OsRng.fill_bytes(&mut bytes);
    Ok(hex::encode(bytes))
}

pub(crate) fn validate_hex_field(
    label: &str,
    value: &str,
    expected_len: usize,
) -> Result<(), PasswordError> {
    if value.is_empty() {
        return Err(PasswordError::InvalidHex(format!("{} is required", label)));
    }
    let len = value.chars().count();
    if len != expected_len {
        return Err(PasswordError::InvalidHex(format!(
            "{} must be {} hex characters",
            label, expected_len
        )));
    }
    if !len.is_multiple_of(2) {
        return Err(PasswordError::InvalidHex(format!(
            "{} must have an even number of hex characters",
            label
        )));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PasswordError::InvalidHex(format!(
            "{} must contain only hex characters",
            label
        )));
    }
    Ok(())
}

fn decode_hex(input: &str) -> Result<Vec<u8>, PasswordError> {
    hex::decode(input).map_err(|err| PasswordError::InvalidHex(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 32768,
            iterations: 2,
            parallelism: 1,
            output_len: 32,
            salt_len: 16,
        }
    }

    #[test]
    fn front_end_hash_round_trip() {
        let params = test_params();
        let salt = generate_salt_hex(params.salt_len).expect("salt");
        let hash = derive_front_end_hash("password", &salt, &params).expect("hash");
        assert_eq!(hash.len(), (params.output_len as usize) * 2);
    }

    #[test]
    fn back_end_hash_verifies() {
        let params = test_params();
        let salt = generate_salt_hex(params.salt_len).expect("salt");
        let front_end = derive_front_end_hash("password", &salt, &params).expect("front");
        let back_end_salt = generate_salt_hex(params.salt_len).expect("salt");
        let stored = derive_back_end_hash(&front_end, &back_end_salt, &params).expect("stored");
        let valid = verify_front_end_hash(&front_end, &stored).expect("verify");
        assert!(valid);
    }

    #[test]
    fn validate_hex_field_accepts_valid_input() {
        assert!(validate_hex_field("salt", "0a0b", 4).is_ok());
    }

    #[test]
    fn validate_hex_field_rejects_invalid_length() {
        let err = validate_hex_field("salt", "0a", 4).expect_err("length");
        assert_eq!(err.to_string(), "salt must be 4 hex characters");
    }

    #[test]
    fn validate_hex_field_rejects_odd_length() {
        let err = validate_hex_field("hash", "abc", 3).expect_err("odd");
        assert_eq!(
            err.to_string(),
            "hash must have an even number of hex characters"
        );
    }

    #[test]
    fn validate_hex_field_rejects_non_hex() {
        let err = validate_hex_field("hash", "0g0h", 4).expect_err("hex");
        assert_eq!(err.to_string(), "hash must contain only hex characters");
    }
}
