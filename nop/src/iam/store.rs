// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::types::{
    DEFAULT_PASSWORD_VERSION, IamError, PasswordRecord, UsersData, YamlUser, YamlUsersData,
};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(test)]
use super::types::User;
#[cfg(test)]
use std::sync::{Arc, RwLock};

pub trait UserStore: Send + Sync {
    fn load(&self) -> Result<UsersData, IamError>;
    fn save(&self, users: &UsersData) -> Result<(), IamError>;
}

pub struct FileUserStore {
    users_file: PathBuf,
}

impl FileUserStore {
    pub fn new(users_file: PathBuf) -> Result<Self, IamError> {
        if users_file.as_os_str().is_empty() {
            return Err(IamError::ConfigurationError(
                "Users file path is empty".to_string(),
            ));
        }

        Ok(Self { users_file })
    }

    fn parse_users(content: &str) -> Result<(UsersData, usize), IamError> {
        let yaml_users: YamlUsersData = serde_yaml::from_str(content)
            .map_err(|e| IamError::ParseError(format!("Failed to parse users file: {}", e)))?;

        let mut missing_password_versions = 0;
        let mut users_data = UsersData::new();
        for (email, yaml_user) in yaml_users {
            if yaml_user.password_version.is_none() {
                missing_password_versions += 1;
            }
            users_data.insert(email.clone(), yaml_user.into_user(email));
        }

        Ok((users_data, missing_password_versions))
    }

    fn serialize_users(users_data: &UsersData) -> Result<String, IamError> {
        let yaml_users: YamlUsersData = users_data
            .iter()
            .map(|(email, user)| {
                let password = if let Some(block) = &user.password {
                    Some(PasswordRecord::Provider(block.clone()))
                } else {
                    user.legacy_password_hash
                        .as_ref()
                        .map(|hash| PasswordRecord::LegacyHash(hash.clone()))
                };
                (
                    email.clone(),
                    YamlUser {
                        name: user.name.clone(),
                        password,
                        roles: user.roles.clone(),
                        password_version: Some(user.password_version),
                    },
                )
            })
            .collect();

        serde_yaml::to_string(&yaml_users)
            .map_err(|e| IamError::ParseError(format!("Failed to serialize users: {}", e)))
    }

    fn read_users_file(&self) -> Result<String, IamError> {
        std::fs::read_to_string(&self.users_file)
            .map_err(|e| IamError::FileError(format!("Failed to read users file: {}", e)))
    }

    fn write_users_file(&self, content: &str) -> Result<(), IamError> {
        let parent = self.users_file.parent().ok_or_else(|| {
            IamError::FileError("Users file path has no parent directory".to_string())
        })?;
        let file_name = self
            .users_file
            .file_name()
            .ok_or_else(|| IamError::FileError("Users file path has no file name".to_string()))?;
        let (mut file, temp_path) = create_temp_file(parent, file_name)?;

        if let Ok(metadata) = std::fs::metadata(&self.users_file) {
            #[cfg(unix)]
            {
                if let Err(err) = std::fs::set_permissions(&temp_path, metadata.permissions()) {
                    let _ = std::fs::remove_file(&temp_path);
                    return Err(IamError::FileError(format!(
                        "Failed to set temp users file permissions: {}",
                        err
                    )));
                }
            }
        }

        if let Err(err) = file.write_all(content.as_bytes()) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(IamError::FileError(format!(
                "Failed to write users temp file: {}",
                err
            )));
        }
        if let Err(err) = file.sync_all() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(IamError::FileError(format!(
                "Failed to sync users temp file: {}",
                err
            )));
        }

        if let Err(err) = std::fs::rename(&temp_path, &self.users_file) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(IamError::FileError(format!(
                "Failed to replace users file: {}",
                err
            )));
        }

        #[cfg(unix)]
        {
            if let Err(err) = sync_parent_dir(parent) {
                log::warn!("Users directory sync failed: {}", err);
            }
        }

        Ok(())
    }
}

fn create_temp_file(
    dir: &Path,
    file_name: &std::ffi::OsStr,
) -> Result<(std::fs::File, PathBuf), IamError> {
    use std::fs::OpenOptions;
    const MAX_ATTEMPTS: u32 = 100;
    let base = file_name.to_string_lossy();
    for attempt in 0..MAX_ATTEMPTS {
        let candidate = dir.join(format!(".{}.tmp.{}.{}", base, std::process::id(), attempt));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((file, candidate)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(IamError::FileError(format!(
                    "Failed to create temp users file: {}",
                    err
                )));
            }
        }
    }
    Err(IamError::FileError(
        "Failed to create temp users file after repeated attempts".to_string(),
    ))
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> Result<(), IamError> {
    let dir = std::fs::File::open(parent).map_err(|err| {
        IamError::FileError(format!("Failed to open users directory for sync: {}", err))
    })?;
    dir.sync_all()
        .map_err(|err| IamError::FileError(format!("Failed to sync users directory: {}", err)))
}

impl UserStore for FileUserStore {
    fn load(&self) -> Result<UsersData, IamError> {
        let content = self.read_users_file()?;
        let (users_data, missing_password_versions) = Self::parse_users(&content)?;

        if missing_password_versions > 0 {
            log::warn!(
                "users.yaml missing password_version for {} user(s); defaulting to {} and persisting",
                missing_password_versions,
                DEFAULT_PASSWORD_VERSION
            );
            self.save(&users_data)?;
        }

        Ok(users_data)
    }

    fn save(&self, users: &UsersData) -> Result<(), IamError> {
        let content = Self::serialize_users(users)?;
        self.write_users_file(&content)
    }
}

#[cfg(test)]
pub struct MemoryUserStore {
    users: Arc<RwLock<UsersData>>,
}

#[cfg(test)]
impl MemoryUserStore {
    pub fn new(initial: UsersData) -> Self {
        Self {
            users: Arc::new(RwLock::new(initial)),
        }
    }

    pub fn from_users(users: Vec<User>) -> Self {
        let data = users
            .into_iter()
            .map(|user| (user.email.clone(), user))
            .collect();
        Self::new(data)
    }
}

#[cfg(test)]
impl UserStore for MemoryUserStore {
    fn load(&self) -> Result<UsersData, IamError> {
        match self.users.read() {
            Ok(guard) => Ok(guard.clone()),
            Err(poisoned) => {
                log::error!("MemoryUserStore lock poisoned on read; recovering");
                Ok(poisoned.into_inner().clone())
            }
        }
    }

    fn save(&self, users: &UsersData) -> Result<(), IamError> {
        match self.users.write() {
            Ok(mut guard) => {
                *guard = users.clone();
                Ok(())
            }
            Err(poisoned) => {
                log::error!("MemoryUserStore lock poisoned on write; recovering");
                let mut guard = poisoned.into_inner();
                *guard = users.clone();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::types::{PasswordProviderBlock, User};
    use std::collections::HashMap;

    #[cfg(unix)]
    #[test]
    fn save_does_not_modify_existing_file_on_dir_permission_error() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let users_path = temp.path().join("users.yaml");
        std::fs::write(&users_path, "original\n").expect("write users");

        let store = FileUserStore::new(users_path.clone()).expect("store");
        let mut users = HashMap::new();
        users.insert(
            "user@example.com".to_string(),
            User {
                email: "user@example.com".to_string(),
                name: "User One".to_string(),
                password: Some(PasswordProviderBlock {
                    front_end_salt: "front".to_string(),
                    back_end_salt: "back".to_string(),
                    stored_hash: "hash".to_string(),
                }),
                legacy_password_hash: None,
                roles: vec!["admin".to_string()],
                password_version: DEFAULT_PASSWORD_VERSION,
            },
        );

        let dir = temp.path();
        let original_permissions = std::fs::metadata(dir)
            .expect("metadata")
            .permissions()
            .mode();
        let read_only = std::fs::Permissions::from_mode(original_permissions & 0o555);
        std::fs::set_permissions(dir, read_only).expect("set read-only");

        let result = store.save(&users);
        assert!(result.is_err());

        let content = std::fs::read_to_string(&users_path).expect("read users");
        assert_eq!(content, "original\n");

        let restore = std::fs::Permissions::from_mode(original_permissions);
        std::fs::set_permissions(dir, restore).expect("restore permissions");
    }

    #[test]
    fn load_migrates_missing_password_versions() {
        let temp = tempfile::tempdir().expect("tempdir");
        let users_path = temp.path().join("users.yaml");
        let yaml = "user@example.com:\n  name: \"User\"\n  password: \"hash\"\n  roles:\n    - \"admin\"\n";
        std::fs::write(&users_path, yaml).expect("write users");

        let store = FileUserStore::new(users_path.clone()).expect("store");
        let users = store.load().expect("load users");
        let user = users.get("user@example.com").expect("user");
        assert_eq!(user.password_version, DEFAULT_PASSWORD_VERSION);

        let migrated = std::fs::read_to_string(&users_path).expect("read users");
        let parsed: YamlUsersData = serde_yaml::from_str(&migrated).expect("parse users");
        let yaml_user = parsed.get("user@example.com").expect("yaml user");
        assert_eq!(yaml_user.password_version, Some(DEFAULT_PASSWORD_VERSION));
        let password = yaml_user.password.as_ref().expect("password");
        match password {
            PasswordRecord::LegacyHash(hash) => assert_eq!(hash, "hash"),
            PasswordRecord::Provider(_) => panic!("expected legacy password hash"),
        }
    }
}
