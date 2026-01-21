// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::roles::ensure_roles;
use super::{BootstrapError, log_action};
use crate::config::ValidatedConfig;
use crate::content::flat_storage::{
    ContentSidecar, ContentVersion, blob_path, generate_content_id, sidecar_path,
    write_sidecar_atomic,
};
use crate::content::migration::migrate_legacy_content;
use crate::runtime_paths::RuntimePaths;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(super) const DEFAULT_HOME_MD: &str = "# Welcome to NoPressure!\n\nThis site was auto-generated to get you started.\n\n- Make sure you change the admin password.\n- Edit content in the admin UI.\n";
const DEFAULT_HOME_ALIAS: &str = "index";
const DEFAULT_HOME_TITLE: &str = "Welcome";

pub(crate) const RED_THEME_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bootstrap/themes/red.html"
));

pub fn ensure_paths(root: &Path, config: &ValidatedConfig) -> Result<RuntimePaths, BootstrapError> {
    let root_path = normalize_root(root)?;
    let content_dir = root_path.join("content");
    let themes_dir = root_path.join("themes");
    let state_dir = root_path.join("state");
    let state_sys_dir = state_dir.join("sys");
    let state_sc_dir = state_dir.join("sc");

    ensure_dir(&content_dir)?;
    ensure_dir(&themes_dir)?;
    ensure_dir(&state_dir)?;
    ensure_dir(&state_sys_dir)?;
    ensure_dir(&state_sc_dir)?;

    if config.is_tls_enabled() {
        let tls_dir = state_sys_dir.join("tls");
        ensure_dir(&tls_dir)?;
    }

    let runtime_paths =
        RuntimePaths::from_root(&root_path, config).map_err(BootstrapError::Config)?;

    ensure_roles(&runtime_paths)?;

    ensure_default_content(&runtime_paths)?;
    let report = migrate_legacy_content(&runtime_paths).map_err(|err| {
        BootstrapError::Io(io::Error::other(format!(
            "Content migration failed: {}",
            err
        )))
    })?;
    if report.migrated {
        log_action(format!(
            "migrated {} legacy files into flat storage",
            report.files_migrated
        ));
        if report.tags_created > 0 {
            log_action(format!("created {} legacy role tags", report.tags_created));
        }
        if report.index_placeholder_created {
            log_action("created placeholder index.md (no legacy root index.md found)");
        }
    }
    ensure_default_theme(&runtime_paths)?;

    Ok(runtime_paths)
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

fn ensure_dir(path: &Path) -> Result<(), BootstrapError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(BootstrapError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Path is not a directory: {}", path.display()),
            )));
        }
        return Ok(());
    }

    fs::create_dir_all(path)?;
    log_action(format!("created directory {}", path.display()));
    Ok(())
}

fn ensure_default_content(runtime_paths: &RuntimePaths) -> Result<(), BootstrapError> {
    if has_content(&runtime_paths.content_dir)? {
        return Ok(());
    }

    let content_id =
        generate_content_id().map_err(|err| BootstrapError::Io(io::Error::other(err)))?;
    let version = ContentVersion(0);
    let blob_path = blob_path(&runtime_paths.content_dir, content_id, version);
    if let Some(parent) = blob_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if write_new_file(&blob_path, DEFAULT_HOME_MD)? {
        log_action(format!("created {}", blob_path.display()));
    }

    let sidecar = ContentSidecar {
        alias: DEFAULT_HOME_ALIAS.to_string(),
        title: Some(DEFAULT_HOME_TITLE.to_string()),
        mime: "text/markdown".to_string(),
        tags: Vec::new(),
        nav_title: Some(DEFAULT_HOME_TITLE.to_string()),
        nav_parent_id: None,
        nav_order: None,
        original_filename: Some("index.md".to_string()),
        theme: None,
    };
    let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, version);
    write_sidecar_atomic(&sidecar_path, &sidecar)
        .map_err(|err| BootstrapError::Io(io::Error::other(err)))?;
    log_action(format!("created {}", sidecar_path.display()));

    Ok(())
}

fn ensure_default_theme(runtime_paths: &RuntimePaths) -> Result<(), BootstrapError> {
    let default_theme = runtime_paths.themes_dir.join("default.html");
    if write_new_file(&default_theme, RED_THEME_HTML)? {
        log_action(format!(
            "created {} from embedded red theme",
            default_theme.display()
        ));
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &str) -> Result<bool, BootstrapError> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(BootstrapError::Io(err)),
    };

    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(true)
}

fn has_content(root: &Path) -> Result<bool, BootstrapError> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => return Err(BootstrapError::Io(err)),
        };

        for entry in entries {
            let entry = entry.map_err(BootstrapError::Io)?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(BootstrapError::Io)?;

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                if should_skip_dir(root, &path) {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if file_type.is_file() {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn should_skip_dir(content_root: &Path, path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|value| value.to_str())
        && name.starts_with('.')
    {
        return true;
    }
    if let Ok(relative) = path.strip_prefix(content_root)
        && relative.components().count() == 1
        && relative == Path::new("legacy")
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ValidatedConfig;
    use crate::config::test_local_users_config;
    use crate::config::{
        AdminConfig, AppConfig, LoggingConfig, LoggingRotationConfig, NavigationConfig,
        RenderingConfig, SecurityConfig, ServerConfig, ServerListenerConfig, ServerProtocol,
        ServerRole, ShortcodeConfig, StreamingConfig, UploadConfig,
    };
    use crate::config::{TlsConfig, TlsMode};
    use crate::content::flat_storage::read_sidecar;
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::fs;
    use std::path::PathBuf;

    fn build_test_config() -> ValidatedConfig {
        ValidatedConfig {
            servers: vec![ServerListenerConfig {
                name: Some("main-https".to_string()),
                role: ServerRole::Main,
                host: "127.0.0.1".to_string(),
                port: 7443,
                protocol: ServerProtocol::Https,
            }],
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 7443,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: test_local_users_config(),
            navigation: NavigationConfig {
                max_dropdown_items: 7,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                rotation: LoggingRotationConfig::default(),
            },
            security: SecurityConfig {
                max_violations: 2,
                cooldown_seconds: 30,
                use_forwarded_for: false,
                login_sessions: crate::config::LoginSessionConfig::default(),
                hsts_enabled: false,
                hsts_max_age: 31536000,
                hsts_include_subdomains: true,
                hsts_preload: false,
            },
            tls: Some(TlsConfig {
                mode: TlsMode::SelfSigned,
                domains: vec!["localhost".to_string()],
                redirect_base_url: None,
                acme: None,
            }),
            app: AppConfig {
                name: "Test".to_string(),
                description: "Test".to_string(),
            },
            upload: UploadConfig {
                max_file_size_mb: 100,
                allowed_extensions: vec!["jpg".to_string()],
            },
            streaming: StreamingConfig { enabled: true },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            dev_mode: None,
        }
    }

    #[test]
    fn creates_default_index_when_no_content() {
        let fixture = TestFixtureRoot::new_unique("bootstrap-content").unwrap();
        fs::write(fixture.path().join("config.yaml"), "stub").unwrap();
        fs::write(fixture.path().join("users.yaml"), "").unwrap();
        let runtime_paths = ensure_paths(fixture.path(), &build_test_config()).unwrap();
        let sidecar_path = find_sidecar(&runtime_paths.content_dir).expect("sidecar missing");
        let sidecar = read_sidecar(&sidecar_path).expect("sidecar invalid");
        assert_eq!(sidecar.alias, DEFAULT_HOME_ALIAS);
        assert_eq!(sidecar.title.as_deref(), Some(DEFAULT_HOME_TITLE));
        assert_eq!(sidecar.mime, "text/markdown");
        let blob_path = blob_path_from_sidecar(&sidecar_path);
        assert!(blob_path.exists());
        let content = fs::read_to_string(blob_path).unwrap();
        assert_eq!(content, DEFAULT_HOME_MD);
    }

    fn find_sidecar(content_dir: &Path) -> Option<PathBuf> {
        let mut stack = vec![content_dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(&dir).ok()?;
            for entry in entries.flatten() {
                let path = entry.path();
                let file_type = entry.file_type().ok()?;
                if file_type.is_dir() {
                    if should_skip_dir(content_dir, &path) {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if file_type.is_file()
                    && path.extension().and_then(|ext| ext.to_str()) == Some("ron")
                {
                    return Some(path);
                }
            }
        }
        None
    }

    fn blob_path_from_sidecar(sidecar: &Path) -> PathBuf {
        let filename = sidecar
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        let blob_name = filename.trim_end_matches(".ron");
        let mut blob_path = sidecar.to_path_buf();
        blob_path.set_file_name(blob_name);
        blob_path
    }
}
