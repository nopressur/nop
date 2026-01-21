// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{ConfigError, ValidatedConfig, ValidatedUsersConfig};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RuntimePaths {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub users_file: PathBuf,
    pub content_dir: PathBuf,
    pub themes_dir: PathBuf,
    pub state_dir: PathBuf,
    pub state_sys_dir: PathBuf,
    pub state_sc_dir: PathBuf,
    pub logs_dir: PathBuf,
}

impl RuntimePaths {
    pub fn from_root(root: &Path, config: &ValidatedConfig) -> Result<Self, ConfigError> {
        let root_path = if root.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            root.to_path_buf()
        };

        if !root_path.exists() {
            fs::create_dir_all(&root_path).map_err(|e| {
                ConfigError::ValidationError(format!(
                    "Failed to create runtime root '{}': {}",
                    root_path.display(),
                    e
                ))
            })?;
        }

        let root_canonical = root_path.canonicalize().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Failed to canonicalize runtime root '{}': {}",
                root_path.display(),
                e
            ))
        })?;

        let config_file = root_canonical.join("config.yaml");
        ensure_file_writable(&config_file, "Config file must be writable")?;

        let users_file = root_canonical.join("users.yaml");
        if matches!(config.users, ValidatedUsersConfig::Local(_)) {
            ensure_file_writable(&users_file, "Users file must be writable")?;
        }

        let content_dir = root_canonical.join("content");
        let themes_dir = root_canonical.join("themes");
        let state_dir = root_canonical.join("state");
        let state_sys_dir = state_dir.join("sys");
        let state_sc_dir = state_dir.join("sc");
        let logs_dir = root_canonical.join("logs");

        ensure_dir_exists(&content_dir)?;
        ensure_dir_exists(&themes_dir)?;
        ensure_dir_exists(&state_dir)?;
        ensure_dir_exists(&state_sys_dir)?;
        ensure_dir_exists(&state_sc_dir)?;

        if config.is_tls_enabled() {
            let tls_dir = state_sys_dir.join("tls");
            ensure_dir_exists(&tls_dir)?;
        }

        let content_dir = content_dir.canonicalize().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Failed to canonicalize content directory '{}': {}",
                content_dir.display(),
                e
            ))
        })?;
        let themes_dir = themes_dir.canonicalize().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Failed to canonicalize themes directory '{}': {}",
                themes_dir.display(),
                e
            ))
        })?;
        let state_dir = state_dir.canonicalize().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Failed to canonicalize state directory '{}': {}",
                state_dir.display(),
                e
            ))
        })?;
        let state_sys_dir = state_sys_dir.canonicalize().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Failed to canonicalize state/sys directory '{}': {}",
                state_sys_dir.display(),
                e
            ))
        })?;
        let state_sc_dir = state_sc_dir.canonicalize().map_err(|e| {
            ConfigError::ValidationError(format!(
                "Failed to canonicalize state/sc directory '{}': {}",
                state_sc_dir.display(),
                e
            ))
        })?;

        Ok(Self {
            root: root_canonical,
            config_file,
            users_file,
            content_dir,
            themes_dir,
            state_dir,
            state_sys_dir,
            state_sc_dir,
            logs_dir,
        })
    }

    pub fn shortcode_dir(&self, name: &str) -> PathBuf {
        self.state_sc_dir.join(name)
    }

    pub fn ensure_shortcode_dirs(&self, names: &[String]) -> Result<(), ConfigError> {
        for name in names {
            let dir = self.shortcode_dir(name);
            ensure_dir_exists(&dir)?;
        }
        Ok(())
    }
}

fn ensure_dir_exists(path: &Path) -> Result<(), ConfigError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| {
            ConfigError::ValidationError(format!(
                "Failed to create directory '{}': {}",
                path.display(),
                e
            ))
        })?;
    }

    ensure_dir_writable(path, "Directory must be writable")?;
    Ok(())
}

fn ensure_dir_writable(path: &Path, context: &str) -> Result<(), ConfigError> {
    if !path.is_dir() {
        return Err(ConfigError::ValidationError(format!(
            "{} (not a directory): {}",
            context,
            path.display()
        )));
    }

    let probe_name = format!(".nop-write-check-{}", Uuid::new_v4());
    let probe_path = path.join(probe_name);

    let probe_result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path);

    match probe_result {
        Ok(_) => {
            if let Err(err) = fs::remove_file(&probe_path) {
                return Err(ConfigError::ValidationError(format!(
                    "{} (unable to clean probe file {}): {}",
                    context,
                    probe_path.display(),
                    err
                )));
            }
            Ok(())
        }
        Err(err) => Err(ConfigError::ValidationError(format!(
            "{} ({}): {}",
            context,
            path.display(),
            err
        ))),
    }
}

fn ensure_file_writable(path: &Path, context: &str) -> Result<(), ConfigError> {
    if !path.is_file() {
        return Err(ConfigError::ValidationError(format!(
            "{} (not a file): {}",
            context,
            path.display()
        )));
    }

    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map(|_| ())
        .map_err(|err| {
            ConfigError::ValidationError(format!("{} ({}): {}", context, path.display(), err))
        })
}
