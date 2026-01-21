// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::{BootstrapError, log_action, log_warning};
use crate::roles::{ADMIN_ROLE, normalize_role};
use crate::runtime_paths::RuntimePaths;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const ROLES_FILE_NAME: &str = "roles.yaml";

#[derive(Deserialize)]
struct TagRecord {
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct UserRecord {
    roles: Vec<String>,
}

pub fn ensure_roles(runtime_paths: &RuntimePaths) -> Result<(), BootstrapError> {
    let roles_path = roles_path(&runtime_paths.state_sys_dir)?;
    if roles_path.exists() {
        return Ok(());
    }

    let mut roles = BTreeSet::new();
    roles.insert(ADMIN_ROLE.to_string());

    collect_roles_from_tags(&runtime_paths.state_sys_dir, &mut roles)?;
    collect_roles_from_users(&runtime_paths.users_file, &mut roles)?;

    let yaml =
        serde_yaml::to_string(&roles).map_err(|err| BootstrapError::Io(io::Error::other(err)))?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&roles_path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(err) => return Err(BootstrapError::Io(err)),
    };

    file.write_all(yaml.as_bytes())?;
    file.sync_all()?;
    log_action(format!("created {}", roles_path.display()));
    Ok(())
}

fn roles_path(state_sys_dir: &Path) -> Result<PathBuf, BootstrapError> {
    Ok(state_sys_dir.join(ROLES_FILE_NAME))
}

fn collect_roles_from_tags(
    state_sys_dir: &Path,
    roles: &mut BTreeSet<String>,
) -> Result<(), BootstrapError> {
    let tags_path = state_sys_dir.join("tags.yaml");
    if !tags_path.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&tags_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }
    let tags: BTreeMap<String, TagRecord> =
        serde_yaml::from_str(&content).map_err(|err| BootstrapError::Io(io::Error::other(err)))?;
    for record in tags.values() {
        for role in &record.roles {
            match normalize_role(role) {
                Ok(normalized) => {
                    roles.insert(normalized);
                }
                Err(err) => {
                    log_warning(format!("Skipping invalid tag role '{}': {}", role, err));
                }
            }
        }
    }
    Ok(())
}

fn collect_roles_from_users(
    users_path: &Path,
    roles: &mut BTreeSet<String>,
) -> Result<(), BootstrapError> {
    if !users_path.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(users_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }
    let users: HashMap<String, UserRecord> =
        serde_yaml::from_str(&content).map_err(|err| BootstrapError::Io(io::Error::other(err)))?;
    for user in users.values() {
        for role in &user.roles {
            match normalize_role(role) {
                Ok(normalized) => {
                    roles.insert(normalized);
                }
                Err(err) => {
                    log_warning(format!("Skipping invalid user role '{}': {}", role, err));
                }
            }
        }
    }
    Ok(())
}
