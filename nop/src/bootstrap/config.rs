// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::{BootstrapError, log_action};
use openssl::rand::rand_bytes;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const DEFAULT_HTTP_PORT: u16 = 7080;
const DEFAULT_HTTPS_PORT: u16 = 7443;
const DEFAULT_WORKERS: u16 = 4;

pub fn ensure_config(root: &Path) -> Result<bool, BootstrapError> {
    let root_path = normalize_root(root)?;
    let config_path = root_path.join("config.yaml");

    if config_path.exists() {
        return Ok(false);
    }

    let jwt_secret = generate_jwt_secret()?;
    let contents = default_config_yaml(&jwt_secret);

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config_path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(BootstrapError::Io(err)),
    };

    file.write_all(contents.as_bytes())?;
    file.sync_all()?;

    log_action(format!(
        "created config.yaml with self-signed TLS (https {}, well-known http {})",
        DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT
    ));

    Ok(true)
}

fn normalize_root(root: &Path) -> Result<PathBuf, BootstrapError> {
    let root_path = if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root.to_path_buf()
    };

    if root_path.exists() {
        if !root_path.is_dir() {
            return Err(BootstrapError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Runtime root is not a directory: {}", root_path.display()),
            )));
        }
        return Ok(root_path);
    }

    fs::create_dir_all(&root_path)?;
    log_action(format!(
        "created runtime root directory {}",
        root_path.display()
    ));
    Ok(root_path)
}

fn generate_jwt_secret() -> Result<String, BootstrapError> {
    let mut bytes = [0u8; 32];
    rand_bytes(&mut bytes).map_err(|err| {
        BootstrapError::Io(io::Error::other(format!(
            "Failed to generate JWT secret: {}",
            err
        )))
    })?;

    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }

    Ok(hex)
}

fn default_config_yaml(jwt_secret: &str) -> String {
    format!(
        "server:\n  host: \"0.0.0.0\"\n  port: {https_port}\n  http_port: {http_port}\n  workers: {workers}\n\nadmin:\n  path: \"/admin\"\n\ntls:\n  mode: \"self-signed\"\n  domains:\n    - \"localhost\"\n\nusers:\n  auth_method: \"local\"\n  local:\n    jwt:\n      secret: \"{jwt_secret}\"\n\nnavigation:\n  max_dropdown_items: 7\n\nrendering:\n  short_paragraph_length: 256\n\nlogging:\n  level: \"info\"\n  rotation:\n    max_size_mb: 16\n    max_files: 10\n\nsecurity:\n  max_violations: 2\n  cooldown_seconds: 30\n  use_forwarded_for: false\n  hsts_enabled: false\n  hsts_max_age: 31536000\n  hsts_include_subdomains: true\n  hsts_preload: false\n\napp:\n  name: \"NoPressure\"\n  description: \"A lightweight web content management system\"\n\nupload:\n  max_file_size_mb: 100\n",
        http_port = DEFAULT_HTTP_PORT,
        https_port = DEFAULT_HTTPS_PORT,
        workers = DEFAULT_WORKERS,
        jwt_secret = jwt_secret,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_contains_expected_ports() {
        let yaml = default_config_yaml("secret");
        assert!(yaml.contains("http_port: 7080"));
        assert!(yaml.contains("port: 7443"));
    }
}
