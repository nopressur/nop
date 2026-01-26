// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::config::{ValidatedConfig, ValidatedUsersConfig};
use crate::iam::UserServices;
use crate::management::UploadRegistry;
use crate::management::blocking::BlockingPool;
use crate::management::errors::{ManagementError, ManagementErrorKind};
use crate::management::roles::RoleStore;
use crate::management::system::{SYSTEM_DOMAIN_ID, SystemCommand};
use crate::management::tags::TagStore;
use crate::public::page_meta_cache::PageMetaCache;
use crate::runtime_paths::RuntimePaths;
use crate::util::ReleaseTracker;
use crate::util::log_rotation::{
    DEFAULT_LOG_FILE_NAME, LogController, LogRotationSettings, LogRunMode,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_MESSAGE_CHARS: usize = 1024;

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
            tag_store,
            role_store,
        })
    }

    pub fn from_runtime_root(root: &Path) -> Result<Self, ManagementError> {
        let bootstrap = crate::bootstrap::bootstrap_runtime(root).map_err(|err| {
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

#[derive(Debug, Clone)]
pub enum ManagementCommand {
    System(SystemCommand),
    Users(crate::management::users::UserCommand),
    Tags(crate::management::tags::TagCommand),
    Roles(crate::management::roles::RoleCommand),
    Content(crate::management::content::ContentCommand),
}

impl ManagementCommand {
    pub fn domain_id(&self) -> u32 {
        match self {
            ManagementCommand::System(_) => SYSTEM_DOMAIN_ID,
            ManagementCommand::Users(_) => crate::management::users::USERS_DOMAIN_ID,
            ManagementCommand::Tags(_) => crate::management::tags::TAGS_DOMAIN_ID,
            ManagementCommand::Roles(_) => crate::management::roles::ROLES_DOMAIN_ID,
            ManagementCommand::Content(_) => crate::management::content::CONTENT_DOMAIN_ID,
        }
    }

    pub fn action_id(&self) -> u32 {
        match self {
            ManagementCommand::System(command) => command.action_id(),
            ManagementCommand::Users(command) => command.action_id(),
            ManagementCommand::Tags(command) => command.action_id(),
            ManagementCommand::Roles(command) => command.action_id(),
            ManagementCommand::Content(command) => command.action_id(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagementRequest {
    pub workflow_id: u32,
    pub connection_id: u32,
    pub command: ManagementCommand,
    pub actor_email: Option<String>,
}

impl ManagementRequest {
    pub fn domain_id(&self) -> u32 {
        self.command.domain_id()
    }

    pub fn action_id(&self) -> u32 {
        self.command.action_id()
    }
}

#[derive(Debug, Clone)]
pub struct ManagementResponse {
    pub domain_id: u32,
    pub action_id: u32,
    pub workflow_id: u32,
    pub payload: ResponsePayload,
}

impl ManagementResponse {
    pub fn message(
        domain_id: u32,
        action_id: u32,
        workflow_id: u32,
        message: impl Into<String>,
    ) -> Result<Self, ManagementError> {
        let payload = ResponsePayload::Message(MessageResponse::new(message)?);
        Ok(Self {
            domain_id,
            action_id,
            workflow_id,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub enum ResponsePayload {
    Message(MessageResponse),
    SystemLoggingConfig(crate::management::system::LoggingConfigResponse),
    SystemLogCleanup(crate::management::system::ClearLogsResponse),
    UserList(crate::management::users::UserListResponse),
    UserShow(crate::management::users::UserShowResponse),
    UserRolesList(crate::management::users::UserRolesListResponse),
    UserPasswordSalt(crate::management::users::PasswordSaltResponse),
    UserPasswordValidate(crate::management::users::PasswordValidateResponse),
    RoleList(crate::management::roles::RoleListResponse),
    RoleShow(crate::management::roles::RoleShowResponse),
    TagList(crate::management::tags::TagListResponse),
    TagShow(crate::management::tags::TagShowResponse),
    ContentList(crate::management::content::ContentListResponse),
    ContentNavIndex(crate::management::content::ContentNavIndexResponse),
    ContentRead(crate::management::content::ContentReadResponse),
    ContentUpload(crate::management::content::ContentUploadResponse),
    ContentBinaryPrevalidate(crate::management::content::BinaryPrevalidateResponse),
    ContentUploadStreamInit(crate::management::content::UploadStreamInitResponse),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Result<Self, ManagementError> {
        let message = message.into();
        let message_len = message.chars().count();
        if message_len > MAX_MESSAGE_CHARS {
            return Err(ManagementError::new(
                ManagementErrorKind::Validation,
                None,
                None,
                format!(
                    "Message exceeds {} characters (got {})",
                    MAX_MESSAGE_CHARS, message_len
                ),
            ));
        }
        Ok(Self { message })
    }
}

impl crate::management::WireEncode for MessageResponse {
    fn encode(
        &self,
        writer: &mut crate::management::WireWriter,
    ) -> crate::management::WireResult<()> {
        writer.write_string(&self.message)
    }
}

impl crate::management::WireDecode for MessageResponse {
    fn decode(reader: &mut crate::management::WireReader) -> crate::management::WireResult<Self> {
        let message = reader.read_string()?;
        Ok(Self { message })
    }
}
