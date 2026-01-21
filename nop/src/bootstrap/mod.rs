// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{Config, ConfigError, ValidatedConfig};
use crate::runtime_paths::RuntimePaths;
use std::error::Error;
use std::fmt;
use std::path::Path;

pub mod config;
pub mod paths;
pub mod roles;
pub mod root_guard;
pub mod users;

#[derive(Debug)]
pub struct BootstrapResult {
    pub validated_config: ValidatedConfig,
    pub runtime_paths: RuntimePaths,
    pub created_config: bool,
    pub created_users: bool,
}

#[derive(Debug)]
pub enum BootstrapError {
    Config(ConfigError),
    Io(std::io::Error),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootstrapError::Config(err) => write!(f, "{}", err),
            BootstrapError::Io(err) => write!(f, "Bootstrap I/O error: {}", err),
        }
    }
}

impl Error for BootstrapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            BootstrapError::Config(err) => Some(err),
            BootstrapError::Io(err) => Some(err),
        }
    }
}

impl From<ConfigError> for BootstrapError {
    fn from(err: ConfigError) -> Self {
        BootstrapError::Config(err)
    }
}

impl From<std::io::Error> for BootstrapError {
    fn from(err: std::io::Error) -> Self {
        BootstrapError::Io(err)
    }
}

pub fn bootstrap_runtime(root: &Path) -> Result<BootstrapResult, BootstrapError> {
    let root_path = root_guard::ensure_root_is_clean(root)?;

    let created_config = config::ensure_config(&root_path)?;

    let validated_config = Config::load_and_validate(&root_path).map_err(BootstrapError::Config)?;

    let created_users = users::ensure_users(&root_path, &validated_config)?;

    let runtime_paths = paths::ensure_paths(&root_path, &validated_config)?;

    Ok(BootstrapResult {
        validated_config,
        runtime_paths,
        created_config,
        created_users,
    })
}

pub(crate) fn log_action(message: impl AsRef<str>) {
    eprintln!("[bootstrap] {}", message.as_ref());
}

pub(crate) fn log_warning(message: impl AsRef<str>) {
    eprintln!("[bootstrap] WARNING: {}", message.as_ref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerProtocol, ServerRole};
    use crate::iam::types::{PasswordRecord, YamlUser};
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn bootstrap_creates_defaults_when_missing() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-default").unwrap();
        let result = bootstrap_runtime(fixture.path()).expect("bootstrap should succeed");

        assert!(result.created_config);
        assert!(result.created_users);

        assert!(result.validated_config.is_tls_enabled());
        assert_eq!(result.validated_config.server.port, 7443);
        assert_eq!(result.validated_config.server.http_port, Some(7080));

        let main_https = result
            .validated_config
            .servers_for_role(ServerRole::Main, Some(ServerProtocol::Https));
        assert_eq!(main_https.len(), 1);
        assert_eq!(main_https[0].port, 7443);

        let well_known_http = result
            .validated_config
            .servers_for_role(ServerRole::WellKnown, Some(ServerProtocol::Http));
        assert_eq!(well_known_http.len(), 1);
        assert_eq!(well_known_http[0].port, 7080);

        let users_path = fixture.path().join("users.yaml");
        assert!(users_path.exists());
        let users_content = fs::read_to_string(users_path).unwrap();
        let users: HashMap<String, YamlUser> = serde_yaml::from_str(&users_content).unwrap();
        let admin = users.get("admin@example.com").expect("admin user missing");
        assert_eq!(admin.name, "Administrator");
        assert!(admin.roles.iter().any(|role| role == "admin"));
        let password = admin.password.as_ref().expect("password missing");
        match password {
            PasswordRecord::Provider(block) => {
                assert!(block.stored_hash.starts_with("$argon2id$"));
                assert!(!block.front_end_salt.is_empty());
                assert!(!block.back_end_salt.is_empty());
            }
            PasswordRecord::LegacyHash(_) => panic!("expected provider password record"),
        }
        assert_eq!(admin.password_version, Some(1));

        let roles_path = fixture.path().join("state").join("sys").join("roles.yaml");
        assert!(roles_path.exists());
        let roles_content = fs::read_to_string(roles_path).unwrap();
        let roles: Vec<String> = serde_yaml::from_str(&roles_content).unwrap();
        assert!(roles.iter().any(|role| role == "admin"));

        let (sidecar_path, blob_path) = find_default_content_paths(fixture.path().join("content"));
        assert!(sidecar_path.exists());
        assert!(blob_path.exists());
        let index_content = fs::read_to_string(blob_path).unwrap();
        assert_eq!(index_content, paths::DEFAULT_HOME_MD);

        let theme_path = fixture.path().join("themes").join("default.html");
        assert!(theme_path.exists());
        let theme_content = fs::read_to_string(theme_path).unwrap();
        assert_eq!(theme_content, paths::RED_THEME_HTML);

        let tls_dir = fixture.path().join("state").join("sys").join("tls");
        assert!(tls_dir.exists());
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-idempotent").unwrap();
        let first = bootstrap_runtime(fixture.path()).expect("bootstrap should succeed");
        assert!(first.created_config);
        assert!(first.created_users);

        let config_path = fixture.path().join("config.yaml");
        let users_path = fixture.path().join("users.yaml");
        let roles_path = fixture.path().join("state").join("sys").join("roles.yaml");
        let (sidecar_path, blob_path) = find_default_content_paths(fixture.path().join("content"));
        let theme_path = fixture.path().join("themes").join("default.html");

        let config_before = fs::read_to_string(&config_path).unwrap();
        let users_before = fs::read_to_string(&users_path).unwrap();
        let roles_before = fs::read_to_string(&roles_path).unwrap();
        let sidecar_before = fs::read_to_string(&sidecar_path).unwrap();
        let blob_before = fs::read_to_string(&blob_path).unwrap();
        let theme_before = fs::read_to_string(&theme_path).unwrap();

        let second = bootstrap_runtime(fixture.path()).expect("bootstrap should succeed");
        assert!(!second.created_config);
        assert!(!second.created_users);

        assert_eq!(config_before, fs::read_to_string(&config_path).unwrap());
        assert_eq!(users_before, fs::read_to_string(&users_path).unwrap());
        assert_eq!(roles_before, fs::read_to_string(&roles_path).unwrap());
        assert_eq!(sidecar_before, fs::read_to_string(&sidecar_path).unwrap());
        assert_eq!(blob_before, fs::read_to_string(&blob_path).unwrap());
        assert_eq!(theme_before, fs::read_to_string(&theme_path).unwrap());
    }

    #[test]
    fn bootstrap_skips_users_for_oidc() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-oidc").unwrap();
        let config_path = fixture.path().join("config.yaml");
        let config = r#"server:
  host: "127.0.0.1"
  port: 8080
  workers: 1

admin:
  path: "/admin"

users:
  auth_method: "oidc"
  oidc:
    server_url: "https://example.com"
    realm: "example"
    client_id: "nop"
    redirect_uri: "http://127.0.0.1:8080/login/callback"

navigation:
  max_dropdown_items: 7

logging:
  level: "info"

security:
  max_violations: 2
  cooldown_seconds: 30
  use_forwarded_for: false
  hsts_enabled: false
  hsts_max_age: 31536000
  hsts_include_subdomains: true
  hsts_preload: false

app:
  name: "NoPressure"
  description: "OIDC config"

upload:
  max_file_size_mb: 100
"#;
        fs::write(&config_path, config).unwrap();

        let result = bootstrap_runtime(fixture.path()).expect("bootstrap should succeed");
        assert!(!result.created_config);
        assert!(!result.created_users);

        assert!(!fixture.path().join("users.yaml").exists());
        assert!(
            fixture
                .path()
                .join("state")
                .join("sys")
                .join("roles.yaml")
                .exists()
        );
        let config_after = fs::read_to_string(&config_path).unwrap();
        assert_eq!(config, config_after);
    }

    #[test]
    fn bootstrap_rejects_unexpected_root_entries() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-unexpected").unwrap();
        fs::write(fixture.path().join("notes.txt"), "do not use").unwrap();

        let error = bootstrap_runtime(fixture.path()).expect_err("bootstrap should fail");
        let message = error.to_string();
        assert!(message.contains("unexpected entries"));
        assert!(message.contains("notes.txt"));
    }

    #[test]
    fn bootstrap_accepts_logs_directory() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-logs").unwrap();
        fs::create_dir_all(fixture.path().join("logs")).unwrap();

        bootstrap_runtime(fixture.path()).expect("bootstrap should succeed");
    }

    #[test]
    fn bootstrap_accepts_pid_file() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-pid").unwrap();
        fs::write(fixture.path().join("nop.pid"), "1234\n").unwrap();

        bootstrap_runtime(fixture.path()).expect("bootstrap should succeed");
    }

    #[test]
    fn bootstrap_skips_well_known_directory() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-well-known").unwrap();
        bootstrap_runtime(fixture.path()).expect("bootstrap should succeed");

        let well_known = fixture.path().join("state").join("sys").join("well-known");
        assert!(!well_known.exists());
    }

    fn find_default_content_paths(content_dir: PathBuf) -> (PathBuf, PathBuf) {
        let mut stack = vec![content_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(&dir).unwrap();
            for entry in entries.flatten() {
                let path = entry.path();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    if path.file_name().and_then(|name| name.to_str()) == Some("legacy") {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if file_type.is_file()
                    && path.extension().and_then(|ext| ext.to_str()) == Some("ron")
                {
                    let filename = path
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let blob_name = filename.trim_end_matches(".ron");
                    let mut blob_path = path.clone();
                    blob_path.set_file_name(blob_name);
                    return (path, blob_path);
                }
            }
        }
        panic!("default content sidecar not found");
    }
}
