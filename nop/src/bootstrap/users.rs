// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::{BootstrapError, log_action, log_warning};
use crate::config::ValidatedConfig;
use crate::iam::build_password_provider_block;
use openssl::rand::rand_bytes;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const ADMIN_EMAIL: &str = "admin@example.com";
const ADMIN_NAME: &str = "Administrator";
const ADMIN_ROLE: &str = "admin";
const ADMIN_PASSWORD_LENGTH: usize = 16;
const PASSWORD_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub fn ensure_users(root: &Path, config: &ValidatedConfig) -> Result<bool, BootstrapError> {
    if config.users.local().is_none() {
        return Ok(false);
    }

    let users_path = users_path(root)?;
    if users_path.exists() {
        return Ok(false);
    }

    let password = generate_password()?;
    let password_params = config
        .users
        .local()
        .ok_or_else(|| BootstrapError::Io(io::Error::other("Missing local auth config")))?;
    let password_block = build_password_provider_block(&password, &password_params.password)
        .map_err(|err| BootstrapError::Io(io::Error::other(err.to_string())))?;

    let yaml = format!(
        "\"{email}\":\n  name: \"{name}\"\n  password:\n    front_end_salt: \"{front_end_salt}\"\n    back_end_salt: \"{back_end_salt}\"\n    stored_hash: \"{stored_hash}\"\n  password_version: 1\n  roles:\n    - \"{role}\"\n",
        email = ADMIN_EMAIL,
        name = ADMIN_NAME,
        front_end_salt = password_block.front_end_salt,
        back_end_salt = password_block.back_end_salt,
        stored_hash = password_block.stored_hash,
        role = ADMIN_ROLE
    );

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&users_path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(BootstrapError::Io(err)),
    };

    file.write_all(yaml.as_bytes())?;
    file.sync_all()?;

    log_action(format!("created users.yaml with {}", ADMIN_EMAIL));
    log_warning(format!(
        "{} password: {} (change this immediately)",
        ADMIN_EMAIL, password
    ));

    Ok(true)
}

fn users_path(root: &Path) -> Result<PathBuf, BootstrapError> {
    let root_path = if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root.to_path_buf()
    };

    Ok(root_path.join("users.yaml"))
}

fn generate_password() -> Result<String, BootstrapError> {
    let mut bytes = [0u8; ADMIN_PASSWORD_LENGTH];
    rand_bytes(&mut bytes).map_err(|err| {
        BootstrapError::Io(io::Error::other(format!(
            "Failed to generate admin password: {}",
            err
        )))
    })?;

    let mut password = String::with_capacity(ADMIN_PASSWORD_LENGTH);
    for byte in bytes {
        let idx = (byte as usize) % PASSWORD_CHARS.len();
        password.push(PASSWORD_CHARS[idx] as char);
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_is_alphanumeric_and_length_16() {
        let password = generate_password().expect("password generation should succeed");
        assert_eq!(password.len(), ADMIN_PASSWORD_LENGTH);
        assert!(password.chars().all(|ch| ch.is_ascii_alphanumeric()));
    }
}
