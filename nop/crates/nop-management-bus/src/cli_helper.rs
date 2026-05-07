// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::bus::ManagementBus;
use crate::cli::CliError;
use crate::socket::SocketError;
use crate::socket::client::{SocketClient, SocketConnect};
use crate::ws::{StreamAckFrame, WsFrame};
use crate::{ManagementContext, WorkflowCounter, build_default_registry, next_connection_id};
use nop_content_store::flat_storage::{blob_path, parse_content_id_hex};
use nop_content_store::reserved_paths::ReservedPaths;
use nop_management_contract::DomainActionKey;
use nop_management_contract::{ManagementCommand, ManagementResponse, ResponsePayload};
use nop_management_errors::ManagementError;
use nop_rt_page_cache::PageMetaCache;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone)]
pub enum ContentStreamTarget {
    Stdout,
    File(PathBuf),
}

#[derive(Debug)]
pub struct CliCommand {
    pub command: ManagementCommand,
    pub success_actions: Vec<DomainActionKey>,
    pub stream_target: Option<ContentStreamTarget>,
}

pub async fn execute(runtime_root: &Path, cli_command: CliCommand) -> Result<i32, CliError> {
    let CliCommand {
        command,
        success_actions,
        stream_target,
    } = cli_command;
    if let Some(stream_target) = stream_target {
        return execute_stream(runtime_root, command, &success_actions, stream_target).await;
    }

    let socket_path = socket_path(runtime_root);
    if socket_path.exists() {
        let registry =
            build_default_registry().map_err(|err| CliError::connector(err.to_string()))?;
        let registry = std::sync::Arc::new(registry);
        match SocketClient::connect(&socket_path, registry.clone()).await? {
            SocketConnect::Ready(mut client) => {
                let response = client.send(command).await?;
                return Ok(output_response(&response, &success_actions));
            }
            SocketConnect::Stale => {
                std::fs::remove_file(&socket_path).map_err(|err| {
                    CliError::connector(format!(
                        "Failed to remove stale socket {}: {}",
                        socket_path.display(),
                        err
                    ))
                })?;
            }
            SocketConnect::Incompatible(message) => {
                return Err(CliError::connector(message));
            }
        }
    }

    let response = send_via_bypass(runtime_root, command).await?;
    Ok(output_response(&response, &success_actions))
}

async fn execute_stream(
    runtime_root: &Path,
    command: ManagementCommand,
    success_actions: &[DomainActionKey],
    stream_target: ContentStreamTarget,
) -> Result<i32, CliError> {
    let socket_path = socket_path(runtime_root);
    if socket_path.exists() {
        let registry =
            build_default_registry().map_err(|err| CliError::connector(err.to_string()))?;
        let registry = std::sync::Arc::new(registry);
        match SocketClient::connect(&socket_path, registry.clone()).await? {
            SocketConnect::Ready(mut client) => {
                return stream_via_socket(&mut client, command, success_actions, stream_target)
                    .await;
            }
            SocketConnect::Stale => {
                std::fs::remove_file(&socket_path).map_err(|err| {
                    CliError::connector(format!(
                        "Failed to remove stale socket {}: {}",
                        socket_path.display(),
                        err
                    ))
                })?;
            }
            SocketConnect::Incompatible(message) => {
                return Err(CliError::connector(message));
            }
        }
    }

    stream_via_bypass(runtime_root, command, success_actions, stream_target).await
}

type StreamWriter = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

async fn open_stream_writer(target: &ContentStreamTarget) -> Result<StreamWriter, CliError> {
    match target {
        ContentStreamTarget::Stdout => Ok(Box::new(tokio::io::stdout())),
        ContentStreamTarget::File(path) => {
            let file = tokio::fs::File::create(path).await.map_err(|err| {
                CliError::connector(format!(
                    "Failed to create output file {}: {}",
                    path.display(),
                    err
                ))
            })?;
            Ok(Box::new(file))
        }
    }
}

async fn stream_via_socket(
    client: &mut SocketClient,
    command: ManagementCommand,
    success_actions: &[DomainActionKey],
    stream_target: ContentStreamTarget,
) -> Result<i32, CliError> {
    let response = client.send(command).await?;
    let key = DomainActionKey::new(response.domain_id, response.action_id);
    if !success_actions.contains(&key) {
        return Ok(output_response(&response, success_actions));
    }

    let payload = match response.payload {
        ResponsePayload::ContentRead(payload) => payload,
        other => {
            return Err(CliError::connector(format!(
                "Unexpected content stream response: {:?}",
                other
            )));
        }
    };

    let mut writer = open_stream_writer(&stream_target).await?;
    if let Some(content) = payload.content {
        writer
            .write_all(content.as_bytes())
            .await
            .map_err(|err| CliError::connector(format!("Failed to write content: {}", err)))?;
        writer
            .flush()
            .await
            .map_err(|err| CliError::connector(format!("Failed to flush output: {}", err)))?;
        return Ok(0);
    }

    let stream_id = payload.stream_id.ok_or_else(|| {
        CliError::connector("Missing stream_id in content stream response".to_string())
    })?;
    let chunk_bytes = payload.chunk_bytes.ok_or_else(|| {
        CliError::connector("Missing chunk_bytes in content stream response".to_string())
    })?;
    let expected_size = payload.size_bytes.ok_or_else(|| {
        CliError::connector("Missing size_bytes in content stream response".to_string())
    })?;

    let mut received = 0u64;
    let mut expected_seq = 0u32;
    loop {
        let frame = client.read_stream_frame().await?;
        match frame {
            WsFrame::StreamChunk(chunk) => {
                if chunk.stream_id != stream_id {
                    return Err(CliError::connector(format!(
                        "Unexpected stream id {} (expected {})",
                        chunk.stream_id, stream_id
                    )));
                }
                if chunk.seq != expected_seq {
                    return Err(CliError::connector(format!(
                        "Unexpected stream sequence {} (expected {})",
                        chunk.seq, expected_seq
                    )));
                }
                if chunk.payload.len() > chunk_bytes as usize {
                    return Err(CliError::connector(
                        "Stream chunk exceeds negotiated size".to_string(),
                    ));
                }
                writer.write_all(&chunk.payload).await.map_err(|err| {
                    CliError::connector(format!("Failed to write stream chunk: {}", err))
                })?;
                received = received.saturating_add(chunk.payload.len() as u64);
                client
                    .write_stream_frame(&WsFrame::Ack(StreamAckFrame {
                        stream_id,
                        seq: chunk.seq,
                    }))
                    .await?;
                if chunk.is_final() {
                    break;
                }
                expected_seq = expected_seq.saturating_add(1);
            }
            other => {
                return Err(CliError::connector(format!(
                    "Unexpected stream frame: {:?}",
                    other
                )));
            }
        }
    }

    writer
        .flush()
        .await
        .map_err(|err| CliError::connector(format!("Failed to flush output: {}", err)))?;
    if received != expected_size {
        return Err(CliError::connector(format!(
            "Stream size mismatch (expected {}, received {})",
            expected_size, received
        )));
    }
    Ok(0)
}

async fn stream_via_bypass(
    runtime_root: &Path,
    command: ManagementCommand,
    success_actions: &[DomainActionKey],
    stream_target: ContentStreamTarget,
) -> Result<i32, CliError> {
    let registry = build_default_registry().map_err(|err| CliError::connector(err.to_string()))?;
    let context = ManagementContext::from_runtime_root(runtime_root)
        .map_err(|err| CliError::connector(err.to_string()))?;
    validate_command(&registry, &command)?;
    let bus = ManagementBus::start(registry, context.clone());
    let connection_id = next_connection_id();
    let workflow_id = WorkflowCounter::new()
        .next_id()
        .map_err(|err| CliError::connector(err.to_string()))?;
    let response = bus
        .send(connection_id, workflow_id, command)
        .await
        .map_err(|err| CliError::connector(err.to_string()))?;

    let key = DomainActionKey::new(response.domain_id, response.action_id);
    if !success_actions.contains(&key) {
        return Ok(output_response(&response, success_actions));
    }

    let payload = match response.payload {
        ResponsePayload::ContentRead(payload) => payload,
        other => {
            return Err(CliError::connector(format!(
                "Unexpected content stream response: {:?}",
                other
            )));
        }
    };

    let mut writer = open_stream_writer(&stream_target).await?;
    if let Some(content) = payload.content {
        writer
            .write_all(content.as_bytes())
            .await
            .map_err(|err| CliError::connector(format!("Failed to write content: {}", err)))?;
        writer
            .flush()
            .await
            .map_err(|err| CliError::connector(format!("Failed to flush output: {}", err)))?;
        return Ok(0);
    }

    let content_id = parse_content_id_hex(&payload.id)
        .map_err(|err| CliError::connector(format!("Invalid content id for stream: {}", err)))?;
    let cache = get_cache_for_stream(&context).await?;
    let object = cache
        .get_by_id(content_id)
        .ok_or_else(|| CliError::connector("Content not found for stream".to_string()))?;
    let blob_path = blob_path(
        &context.runtime_paths.content_dir,
        object.key.id,
        object.key.version,
    );

    let mut file = tokio::fs::File::open(&blob_path).await.map_err(|err| {
        CliError::connector(format!(
            "Failed to open content blob {}: {}",
            blob_path.display(),
            err
        ))
    })?;
    let written = tokio::io::copy(&mut file, &mut *writer)
        .await
        .map_err(|err| CliError::connector(format!("Failed to stream content: {}", err)))?;
    writer
        .flush()
        .await
        .map_err(|err| CliError::connector(format!("Failed to flush output: {}", err)))?;
    if let Some(expected) = payload.size_bytes
        && written != expected
    {
        return Err(CliError::connector(format!(
            "Stream size mismatch (expected {}, received {})",
            expected, written
        )));
    }

    Ok(0)
}

async fn send_via_bypass(
    runtime_root: &Path,
    command: ManagementCommand,
) -> Result<ManagementResponse, CliError> {
    let registry = build_default_registry().map_err(|err| CliError::connector(err.to_string()))?;
    let mut context = ManagementContext::from_runtime_root(runtime_root)
        .map_err(|err| CliError::connector(err.to_string()))?;
    if matches!(command, ManagementCommand::Search(_)) {
        let startup = nop_rt_search_service::initialize(
            &context.runtime_paths,
            &context.config.search,
            nop_content_store::reserved_paths::ReservedPaths::from_config(&context.config),
            false,
        )
        .map_err(|err| CliError::connector(err.to_string()))?;
        context = context.with_search_service(startup.service);
    }
    validate_command(&registry, &command)?;
    let bus = ManagementBus::start(registry, context);
    let connection_id = next_connection_id();
    let workflow_id = WorkflowCounter::new()
        .next_id()
        .map_err(|err| CliError::connector(err.to_string()))?;
    bus.send(connection_id, workflow_id, command)
        .await
        .map_err(|err| CliError::connector(err.to_string()))
}

fn output_response(response: &ManagementResponse, success_actions: &[DomainActionKey]) -> i32 {
    let key = DomainActionKey::new(response.domain_id, response.action_id);
    let is_success = success_actions.contains(&key);

    match &response.payload {
        ResponsePayload::Message(payload) => {
            if is_success {
                println!("{}", payload.message);
                0
            } else {
                eprintln!("{}", payload.message);
                1
            }
        }
        ResponsePayload::SystemLoggingConfig(payload) => {
            if is_success {
                print_logging_config(payload);
                0
            } else {
                eprintln!("Logging configuration failed");
                1
            }
        }
        ResponsePayload::SystemLogCleanup(payload) => {
            if is_success {
                println!("{}", payload.message);
                0
            } else {
                eprintln!("{}", payload.message);
                1
            }
        }
        ResponsePayload::UserList(payload) => {
            if is_success {
                print_user_list(payload);
                0
            } else {
                eprintln!("User list failed");
                1
            }
        }
        ResponsePayload::UserShow(payload) => {
            if is_success {
                print_user_show(payload);
                0
            } else {
                eprintln!("User lookup failed");
                1
            }
        }
        ResponsePayload::UserRolesList(payload) => {
            if is_success {
                print_roles_list(payload);
                0
            } else {
                eprintln!("Roles list failed");
                1
            }
        }
        ResponsePayload::UserPasswordSalt(payload) => {
            if is_success {
                println!(
                    "current_front_end_salt={} next_front_end_salt={} change_token={} expires_in_seconds={}",
                    payload.current_front_end_salt,
                    payload.next_front_end_salt,
                    payload.change_token,
                    payload.expires_in_seconds
                );
                0
            } else {
                eprintln!("Password salt request failed");
                1
            }
        }
        ResponsePayload::UserPasswordValidate(payload) => {
            if is_success {
                println!("valid={}", payload.valid);
                0
            } else {
                eprintln!("Password validation failed");
                1
            }
        }
        ResponsePayload::RoleList(payload) => {
            if is_success {
                print_role_list(payload);
                0
            } else {
                eprintln!("Role list failed");
                1
            }
        }
        ResponsePayload::RoleShow(payload) => {
            if is_success {
                print_role_show(payload);
                0
            } else {
                eprintln!("Role lookup failed");
                1
            }
        }
        ResponsePayload::TagList(payload) => {
            if is_success {
                print_tag_list(payload);
                0
            } else {
                eprintln!("Tag list failed");
                1
            }
        }
        ResponsePayload::TagShow(payload) => {
            if is_success {
                print_tag_show(payload);
                0
            } else {
                eprintln!("Tag lookup failed");
                1
            }
        }
        ResponsePayload::ContentList(payload) => {
            if is_success {
                print_content_list(payload);
                0
            } else {
                eprintln!("Content list failed");
                1
            }
        }
        ResponsePayload::ContentNavIndex(payload) => {
            if is_success {
                print_content_nav_index(payload);
                0
            } else {
                eprintln!("Content nav index failed");
                1
            }
        }
        ResponsePayload::ContentRead(payload) => {
            if is_success {
                print_content_read(payload);
                0
            } else {
                eprintln!("Content lookup failed");
                1
            }
        }
        ResponsePayload::ContentUpload(payload) => {
            if is_success {
                print_content_upload(payload);
                0
            } else {
                eprintln!("Content upload failed");
                1
            }
        }
        ResponsePayload::ContentBinaryPrevalidate(payload) => {
            if is_success {
                if payload.accepted {
                    println!("Accepted: {}", payload.message);
                } else {
                    println!("Rejected: {}", payload.message);
                }
                0
            } else {
                eprintln!("{}", payload.message);
                1
            }
        }
        ResponsePayload::ContentUploadStreamInit(payload) => {
            if is_success {
                println!(
                    "upload_id={} stream_id={} max_bytes={} chunk_bytes={}",
                    payload.upload_id, payload.stream_id, payload.max_bytes, payload.chunk_bytes
                );
                0
            } else {
                eprintln!("Upload stream init failed");
                1
            }
        }
        ResponsePayload::SearchFind(payload) => {
            if is_success {
                print_search_results(payload);
                0
            } else {
                eprintln!("Search failed");
                1
            }
        }
    }
}

async fn get_cache_for_stream(context: &ManagementContext) -> Result<PageMetaCache, CliError> {
    if let Some(cache) = context.page_cache.as_ref() {
        return Ok(cache.as_ref().clone());
    }

    let cache = PageMetaCache::new(
        context.runtime_paths.content_dir.clone(),
        context.runtime_paths.state_sys_dir.clone(),
        ReservedPaths::from_config(&context.config),
    );
    cache
        .rebuild_cache(true)
        .await
        .map_err(|err| CliError::connector(format!("Failed to rebuild cache: {}", err)))?;
    Ok(cache)
}

fn print_user_list(payload: &nop_management_contract::users::UserListResponse) {
    let email_header = "Email";
    let name_header = "Name";
    let mut email_width = email_header.len();
    for user in &payload.users {
        email_width = email_width.max(user.email.chars().count());
    }
    println!(
        "{:<width$}  {}",
        email_header,
        name_header,
        width = email_width
    );
    for user in &payload.users {
        println!("{:<width$}  {}", user.email, user.name, width = email_width);
    }
}

fn print_user_show(payload: &nop_management_contract::users::UserShowResponse) {
    println!("Email: {}", payload.email);
    println!("Name: {}", payload.name);
    if payload.roles.is_empty() {
        println!("Roles: (none)");
    } else {
        println!("Roles: {}", payload.roles.join(", "));
    }
}

fn print_roles_list(payload: &nop_management_contract::users::UserRolesListResponse) {
    for role in &payload.roles {
        println!("{}", role);
    }
}

fn print_logging_config(payload: &nop_management_contract::system::LoggingConfigResponse) {
    println!(
        "level={} rotation_max_size_mb={} rotation_max_files={} run_mode={} file_logging_active={}",
        payload.level,
        payload.rotation_max_size_mb,
        payload.rotation_max_files,
        payload.run_mode,
        payload.file_logging_active
    );
}

fn print_role_list(payload: &nop_management_contract::roles::RoleListResponse) {
    for role in &payload.roles {
        println!("{}", role);
    }
}

fn print_role_show(payload: &nop_management_contract::roles::RoleShowResponse) {
    println!("Role: {}", payload.role);
}

fn print_tag_list(payload: &nop_management_contract::tags::TagListResponse) {
    let id_header = "Id";
    let name_header = "Name";
    let mut id_width = id_header.len();
    for tag in &payload.tags {
        id_width = id_width.max(tag.id.chars().count());
    }
    println!("{:<width$}  {}", id_header, name_header, width = id_width);
    for tag in &payload.tags {
        println!("{:<width$}  {}", tag.id, tag.name, width = id_width);
    }
}

fn print_tag_show(payload: &nop_management_contract::tags::TagShowResponse) {
    println!("Id: {}", payload.id);
    println!("Name: {}", payload.name);
    if payload.roles.is_empty() {
        println!("Roles: (none)");
    } else {
        println!("Roles: {}", payload.roles.join(", "));
    }
    match &payload.access_rule {
        Some(rule) => println!("Access rule: {}", access_rule_label(rule)),
        None => println!("Access rule: (none)"),
    }
}

fn print_content_list(payload: &nop_management_contract::content::ContentListResponse) {
    let title_header = "Title";
    let alias_header = "Alias";
    let mut alias_width = alias_header.len();
    for item in &payload.items {
        alias_width = alias_width.max(item.alias.chars().count());
    }
    println!(
        "{:<width$}  {}",
        alias_header,
        title_header,
        width = alias_width
    );
    for item in &payload.items {
        let title = item.title.as_deref().unwrap_or("(untitled)");
        println!("{:<width$}  {}", item.alias, title, width = alias_width);
    }
}

fn print_content_read(payload: &nop_management_contract::content::ContentReadResponse) {
    println!("Alias: {}", payload.alias);
    if let Some(title) = &payload.title {
        println!("Title: {}", title);
    }
    println!("Mime: {}", payload.mime);
    if !payload.tags.is_empty() {
        println!("Tags: {}", payload.tags.join(", "));
    }
    if let Some(theme) = &payload.theme {
        println!("Theme: {}", theme);
    }
    if let Some(name) = &payload.original_filename {
        println!("Original filename: {}", name);
    }
    if let Some(content) = &payload.content {
        println!("Content:\n{}", content);
    }
}

fn print_search_results(payload: &nop_management_contract::search::SearchFindResponse) {
    for item in &payload.hits {
        let alias = if item.alias.is_empty() {
            "-"
        } else {
            item.alias.as_str()
        };
        let title = item.title.as_deref().unwrap_or("(untitled)");
        println!("{} {} {}", item.id, alias, title);
    }
}

fn print_content_upload(payload: &nop_management_contract::content::ContentUploadResponse) {
    println!("Id: {}", payload.id);
    println!("Alias: {}", payload.alias);
    println!("Mime: {}", payload.mime);
}

fn print_content_nav_index(payload: &nop_management_contract::content::ContentNavIndexResponse) {
    for item in &payload.items {
        let title = item
            .nav_title
            .as_deref()
            .or(item.title.as_deref())
            .unwrap_or(&item.alias);
        println!("{}  {}  {}", item.id, item.alias, title);
    }
}

fn access_rule_label(rule: &nop_roles::AccessRule) -> &'static str {
    match rule {
        nop_roles::AccessRule::Union => "union",
        nop_roles::AccessRule::Intersect => "intersect",
    }
}

fn socket_path(runtime_root: &Path) -> PathBuf {
    let root = if runtime_root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        runtime_root.to_path_buf()
    };
    root.join("state").join("sys").join("management.sock")
}

fn validate_command(
    registry: &crate::ManagementRegistry,
    command: &ManagementCommand,
) -> Result<(), CliError> {
    let key = DomainActionKey::new(command.domain_id(), command.action_id());
    let codec = registry
        .codec_registry()
        .request_codec(&key)
        .ok_or_else(|| {
            CliError::connector(format!(
                "No request codec for domain {} action {}",
                key.domain_id, key.action_id
            ))
        })?;
    codec
        .validate(command)
        .map_err(|err| CliError::connector(format!("Invalid request: {}", err)))
}

impl From<ManagementError> for CliError {
    fn from(err: ManagementError) -> Self {
        CliError::connector(err.to_string())
    }
}

impl From<SocketError> for CliError {
    fn from(err: SocketError) -> Self {
        CliError::connector(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::system::ping_command;
    use nop_config::{
        AdminConfig, AppConfig, AuthMethod, Config, JwtConfig, LocalAuthConfig, LoggingConfig,
        LoggingRotationConfig, NavigationConfig, PasswordHashingConfig, RenderingConfig,
        SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig, UploadConfig, UsersConfig,
    };
    use nop_testing::test_fixtures::TestFixtureRoot;
    use std::path::Path;

    fn write_test_config(root: &Path) {
        let config = Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                http_port: None,
                workers: 1,
            },
            admin: AdminConfig {
                path: "/admin".to_string(),
            },
            users: UsersConfig {
                auth_method: AuthMethod::Local,
                local: Some(LocalAuthConfig {
                    jwt: JwtConfig {
                        secret: "test-secret".to_string(),
                        issuer: "nopressure".to_string(),
                        audience: "nopressure-users".to_string(),
                        expiration_hours: 12,
                        cookie_name: "nop_auth".to_string(),
                        force_secure_cookie: false,
                        disable_refresh: false,
                        refresh_threshold_percentage: 10,
                        refresh_threshold_hours: 24,
                    },
                    password: PasswordHashingConfig::default(),
                    password_complexity_disabled: false,
                }),
                oidc: None,
            },
            navigation: NavigationConfig {
                max_dropdown_items: 7,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                rotation: LoggingRotationConfig::default(),
            },
            security: SecurityConfig {
                max_violations: 10,
                cooldown_seconds: 60,
                use_forwarded_for: false,
                login_sessions: nop_config::LoginSessionConfig::default(),
                hsts_enabled: false,
                hsts_max_age: 31536000,
                hsts_include_subdomains: true,
                hsts_preload: false,
            },
            tls: None,
            app: AppConfig {
                name: "Test App".to_string(),
                description: "Test Description".to_string(),
            },
            upload: UploadConfig {
                max_file_size_mb: 100,
                allowed_extensions: vec!["md".to_string()],
            },
            streaming: StreamingConfig { enabled: false },
            shortcodes: ShortcodeConfig::default(),
            rendering: RenderingConfig::default(),
            search: nop_config::SearchConfig::default(),
            dev_mode: None,
        };

        let content = serde_yaml::to_string(&config).expect("serialize config");
        std::fs::write(root.join("config.yaml"), content).expect("write config");
        std::fs::write(root.join("users.yaml"), "{}\n").expect("write users");
    }

    #[tokio::test]
    async fn bypass_runs_when_socket_missing() {
        let fixture = TestFixtureRoot::new_unique("cli-bypass").unwrap();
        fixture.init_runtime_layout().unwrap();
        write_test_config(fixture.path());
        let runtime_root = fixture.path();
        let command = ping_command().unwrap();
        let exit_code = execute(runtime_root, command).await.unwrap();
        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn stale_socket_falls_back_to_bypass() {
        let fixture = TestFixtureRoot::new_unique("cli-stale").unwrap();
        fixture.init_runtime_layout().unwrap();
        write_test_config(fixture.path());
        let runtime_root = fixture.path();
        let socket_path = runtime_root
            .join("state")
            .join("sys")
            .join("management.sock");
        std::fs::write(&socket_path, "not-a-socket").unwrap();

        let command = ping_command().unwrap();
        let exit_code = execute(runtime_root, command).await.unwrap();
        assert_eq!(exit_code, 0);
        assert!(!socket_path.exists());
    }
}
