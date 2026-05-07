// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::UploadRegistry;
use crate::blocking::BlockingPool;
use nop_config::{ValidatedConfig, ValidatedUsersConfig};
use nop_management_errors::{ManagementError, ManagementErrorKind};
use nop_management_roles::RoleStore;
use nop_management_tags::TagStore;
use nop_rt_iam::UserServices;
use nop_rt_logging::{DEFAULT_LOG_FILE_NAME, LogController, LogRotationSettings, LogRunMode};
use nop_rt_page_cache::PageMetaCache;
use nop_rt_paths::RuntimePaths;
use nop_rt_release::ReleaseTracker;
use nop_rt_search_service::SearchService;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl VersionInfo {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn from_pkg_version() -> Result<Self, ManagementError> {
        let raw = env!("CARGO_PKG_VERSION");
        let mut parts = raw.split('.');
        let major = parts
            .next()
            .ok_or_else(|| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    "Missing major version",
                )
            })?
            .parse::<u16>()
            .map_err(|err| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    format!("Invalid major version: {}", err),
                )
            })?;
        let minor = parts
            .next()
            .ok_or_else(|| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    "Missing minor version",
                )
            })?
            .parse::<u16>()
            .map_err(|err| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    format!("Invalid minor version: {}", err),
                )
            })?;
        let patch_raw = parts.next().ok_or_else(|| {
            ManagementError::new(
                ManagementErrorKind::Internal,
                None,
                None,
                "Missing patch version",
            )
        })?;
        let patch = patch_raw
            .split('-')
            .next()
            .unwrap_or(patch_raw)
            .parse::<u16>()
            .map_err(|err| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    format!("Invalid patch version: {}", err),
                )
            })?;

        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

#[derive(Clone)]
pub struct ManagementContext {
    pub version: VersionInfo,
    pub blocking_pool: BlockingPool,
    pub runtime_root: PathBuf,
    pub config: Arc<ValidatedConfig>,
    pub runtime_paths: RuntimePaths,
    pub log_controller: LogController,
    pub user_services: Option<Arc<UserServices>>,
    pub page_cache: Option<Arc<PageMetaCache>>,
    pub upload_registry: Arc<UploadRegistry>,
    pub release_tracker: Option<Arc<ReleaseTracker>>,
    pub search_service: Option<Arc<SearchService>>,
    pub(crate) tag_store: Arc<TagStore>,
    pub(crate) role_store: Arc<RoleStore>,
}

impl ManagementContext {
    pub fn from_components(
        runtime_root: PathBuf,
        config: Arc<ValidatedConfig>,
        runtime_paths: RuntimePaths,
    ) -> Result<Self, ManagementError> {
        Self::from_components_with_user_services(runtime_root, config, runtime_paths, None)
    }

    pub fn from_components_with_user_services(
        runtime_root: PathBuf,
        config: Arc<ValidatedConfig>,
        runtime_paths: RuntimePaths,
        user_services: Option<Arc<UserServices>>,
    ) -> Result<Self, ManagementError> {
        Self::from_components_with_user_services_and_cache(
            runtime_root,
            config,
            runtime_paths,
            user_services,
            None,
        )
    }

    pub fn from_components_with_user_services_and_cache(
        runtime_root: PathBuf,
        config: Arc<ValidatedConfig>,
        runtime_paths: RuntimePaths,
        user_services: Option<Arc<UserServices>>,
        page_cache: Option<Arc<PageMetaCache>>,
    ) -> Result<Self, ManagementError> {
        let log_controller = default_log_controller(&runtime_paths, &config);
        Self::from_components_with_user_services_and_cache_and_logs(
            runtime_root,
            config,
            runtime_paths,
            user_services,
            page_cache,
            log_controller,
        )
    }

    pub fn from_components_with_user_services_and_cache_and_logs(
        runtime_root: PathBuf,
        config: Arc<ValidatedConfig>,
        runtime_paths: RuntimePaths,
        user_services: Option<Arc<UserServices>>,
        page_cache: Option<Arc<PageMetaCache>>,
        log_controller: LogController,
    ) -> Result<Self, ManagementError> {
        let tag_store = TagStore::new(runtime_paths.state_sys_dir.clone())
            .map(Arc::new)
            .map_err(|err| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    format!("Tag store error: {}", err),
                )
            })?;
        let role_store = RoleStore::new(runtime_paths.state_sys_dir.clone())
            .map(Arc::new)
            .map_err(|err| {
                ManagementError::new(
                    ManagementErrorKind::Internal,
                    None,
                    None,
                    format!("Role store error: {}", err),
                )
            })?;
        Ok(Self {
            version: VersionInfo::from_pkg_version()?,
            blocking_pool: BlockingPool::default_pool(),
            runtime_root,
            config,
            runtime_paths,
            log_controller,
            user_services,
            page_cache,
            upload_registry: Arc::new(UploadRegistry::new()),
            release_tracker: None,
            search_service: None,
            tag_store,
            role_store,
        })
    }

    pub fn from_runtime_root(root: &Path) -> Result<Self, ManagementError> {
        let bootstrap = nop_rt_bootstrap::bootstrap_runtime(root).map_err(|err| {
            ManagementError::new(
                ManagementErrorKind::Internal,
                None,
                None,
                format!("Bootstrap error: {}", err),
            )
        })?;
        let validated_config = bootstrap.validated_config;
        let runtime_paths = bootstrap.runtime_paths;
        let user_services = match &validated_config.users {
            ValidatedUsersConfig::Local(_) => Some(
                UserServices::new(&validated_config, runtime_paths.users_file.clone())
                    .map(Arc::new)
                    .map_err(|err| {
                        ManagementError::new(
                            ManagementErrorKind::Internal,
                            None,
                            None,
                            format!("User services error: {}", err),
                        )
                    })?,
            ),
            ValidatedUsersConfig::Oidc(_) => None,
        };
        Self::from_components_with_user_services(
            root.to_path_buf(),
            Arc::new(validated_config),
            runtime_paths,
            user_services,
        )
    }

    pub fn with_upload_registry(mut self, upload_registry: Arc<UploadRegistry>) -> Self {
        self.upload_registry = upload_registry;
        self
    }

    pub fn with_release_tracker(mut self, release_tracker: Arc<ReleaseTracker>) -> Self {
        self.release_tracker = Some(release_tracker);
        self
    }

    pub fn with_search_service(mut self, search_service: Arc<SearchService>) -> Self {
        self.search_service = Some(search_service);
        self
    }
}

fn default_log_controller(runtime_paths: &RuntimePaths, config: &ValidatedConfig) -> LogController {
    let rotation = LogRotationSettings {
        max_size_mb: config.logging.rotation.max_size_mb,
        max_files: config.logging.rotation.max_files,
    };
    LogController::new(
        LogRunMode::Foreground,
        runtime_paths.logs_dir.clone(),
        DEFAULT_LOG_FILE_NAME,
        rotation,
        None,
    )
}
