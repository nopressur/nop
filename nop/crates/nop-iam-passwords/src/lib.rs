// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use nop_config::{Argon2Params, PasswordHashingParams};
use password_hash::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasswordProviderBlock {
    pub front_end_salt: String,
    pub back_end_salt: String,
    pub stored_hash: String,
}

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

pub fn validate_hex_field(
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

const MIN_PASSWORD_CHARS: usize = 8;

pub const PASSWORD_COMPLEXITY_MESSAGE_UNCASED: &str =
    "Password needs to be at least 8 long with letters and numbers.";
pub const PASSWORD_COMPLEXITY_MESSAGE_CASED: &str =
    "Password needs to be at least 8 long with lowercase and uppercase letters and numbers.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordComplexityCase {
    Uncased,
    Cased,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordComplexityReport {
    pub valid: bool,
    pub case_kind: PasswordComplexityCase,
}

pub fn evaluate_password_complexity(password: &str) -> PasswordComplexityReport {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_letter = false;
    let mut has_uncased = false;
    let mut has_number = false;
    let mut length = 0usize;

    for ch in password.chars() {
        length += 1;
        let is_lower = ch.is_lowercase();
        let is_upper = ch.is_uppercase();
        if is_lower {
            has_lower = true;
            has_letter = true;
        } else if is_upper {
            has_upper = true;
            has_letter = true;
        } else if ch.is_alphabetic() {
            has_letter = true;
            has_uncased = true;
        }
        if ch.is_ascii_digit() {
            has_number = true;
        }
    }

    let case_kind = if has_lower || has_upper {
        if has_uncased {
            PasswordComplexityCase::Mixed
        } else {
            PasswordComplexityCase::Cased
        }
    } else {
        PasswordComplexityCase::Uncased
    };

    let length_ok = length >= MIN_PASSWORD_CHARS;
    let number_ok = has_number;
    let letter_ok = has_letter;
    let case_ok = match case_kind {
        PasswordComplexityCase::Cased => has_lower && has_upper,
        PasswordComplexityCase::Mixed | PasswordComplexityCase::Uncased => true,
    };

    PasswordComplexityReport {
        valid: length_ok && number_ok && letter_ok && case_ok,
        case_kind,
    }
}

pub fn password_complexity_message(case_kind: PasswordComplexityCase) -> &'static str {
    match case_kind {
        PasswordComplexityCase::Cased => PASSWORD_COMPLEXITY_MESSAGE_CASED,
        PasswordComplexityCase::Mixed | PasswordComplexityCase::Uncased => {
            PASSWORD_COMPLEXITY_MESSAGE_UNCASED
        }
    }
}

pub fn validate_password_complexity(password: &str) -> Result<(), String> {
    let report = evaluate_password_complexity(password);
    if report.valid {
        Ok(())
    } else {
        Err(password_complexity_message(report.case_kind).to_string())
    }
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

    #[test]
    fn accepts_cased_password_with_number() {
        let report = evaluate_password_complexity("Abcdefg1");
        assert!(report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Cased);
    }

    #[test]
    fn rejects_cased_password_missing_lowercase() {
        let report = evaluate_password_complexity("ABCDEFG1");
        assert!(!report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Cased);
    }

    #[test]
    fn accepts_uncased_password_with_number() {
        let report = evaluate_password_complexity("漢字漢字漢字12");
        assert!(report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Uncased);
    }

    #[test]
    fn accepts_mixed_password_without_both_cases() {
        let report = evaluate_password_complexity("A漢字1234B");
        assert!(report.valid);
        assert_eq!(report.case_kind, PasswordComplexityCase::Mixed);
    }
}
