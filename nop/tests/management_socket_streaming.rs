// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use nop::config::{
    AdminConfig, AppConfig, AuthMethod, Config, JwtConfig, LocalAuthConfig, LoggingConfig,
    LoggingRotationConfig, NavigationConfig, PasswordHashingConfig, RenderingConfig,
    SecurityConfig, ServerConfig, ShortcodeConfig, StreamingConfig, UploadConfig, UsersConfig,
};
use nop::content::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, content_id_hex, sidecar_path,
    write_sidecar_atomic,
};
use nop::content::reserved_paths::ReservedPaths;
use nop::management::socket::ManagementSocket;
use nop::management::socket::client::{SocketClient, SocketConnect};
use nop::management::ws::{StreamAckFrame, WsFrame};
use nop::management::{
    CONTENT_ACTION_READ_OK, ContentCommand, ContentReadRequest, ManagementBus, ManagementCommand,
    ManagementContext, ResponsePayload, build_default_registry,
};
use nop::public::page_meta_cache::PageMetaCache;
use nop::runtime_paths::RuntimePaths;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

fn write_local_config(root: &Path) {
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
            login_sessions: nop::config::LoginSessionConfig::default(),
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
        search: nop::config::SearchConfig::default(),
        dev_mode: None,
    };

    let content = serde_yaml::to_string(&config).expect("serialize config");
    fs::write(root.join("config.yaml"), content).expect("write config");
    fs::write(root.join("users.yaml"), "{}\n").expect("write users");
    fs::create_dir_all(root.join("state").join("sys")).expect("state sys dir");
    fs::write(
        root.join("state").join("sys").join("roles.yaml"),
        "- admin\n- editor\n",
    )
    .expect("write roles");
}

fn seed_content(runtime_paths: &RuntimePaths) {
    fn write_object(
        runtime_paths: &RuntimePaths,
        content_id: ContentId,
        alias: &str,
        title: Option<&str>,
        mime: &str,
        content: &[u8],
    ) {
        let version = ContentVersion(1);
        let blob = blob_path(&runtime_paths.content_dir, content_id, version);
        if let Some(parent) = blob.parent() {
            fs::create_dir_all(parent).expect("create shard dir");
        }
        fs::write(&blob, content).expect("write blob");
        let sidecar = ContentSidecar {
            alias: alias.to_string(),
            title: title.map(|value| value.to_string()),
            mime: mime.to_string(),
            tags: Vec::new(),
            nav_title: None,
            nav_parent_id: None,
            nav_order: None,
            original_filename: Some(format!(
                "{}.{}",
                alias.rsplit('/').next().unwrap_or("file"),
                mime.rsplit('/').next().unwrap_or("bin")
            )),
            theme: None,
        };
        let sidecar_file = sidecar_path(&runtime_paths.content_dir, content_id, version);
        write_sidecar_atomic(&sidecar_file, &sidecar).expect("write sidecar");
    }

    write_object(
        runtime_paths,
        ContentId(1),
        "index",
        Some("Home"),
        "text/markdown",
        b"# Home\n\nWelcome to the test site.\n",
    );
    write_object(
        runtime_paths,
        ContentId(4),
        "assets/sample.bin",
        None,
        "application/octet-stream",
        b"abcdefghijklmnopqrstuvwxyz012345",
    );
}

async fn setup_runtime() -> (TempDir, RuntimePaths, ManagementBus) {
    let temp = tempfile::Builder::new()
        .prefix("sock")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let root = temp.path();
    write_local_config(root);

    let validated_config = Config::load_and_validate(root).expect("validate config");
    let runtime_paths = RuntimePaths::from_root(root, &validated_config).expect("runtime paths");
    seed_content(&runtime_paths);

    let page_cache = Arc::new(PageMetaCache::new(
        runtime_paths.content_dir.clone(),
        runtime_paths.state_sys_dir.clone(),
        ReservedPaths::from_config(&validated_config),
    ));
    page_cache.rebuild_cache(true).await.expect("cache rebuild");

    let registry = build_default_registry().expect("registry");
    let context = ManagementContext::from_components_with_user_services_and_cache(
        runtime_paths.root.clone(),
        Arc::new(validated_config),
        runtime_paths.clone(),
        None,
        Some(page_cache),
    )
    .expect("context");
    let bus = ManagementBus::start(registry, context);

    (temp, runtime_paths, bus)
}

#[actix_web::test]
async fn socket_streams_binary_content_after_read_response() {
    let (_temp, runtime_paths, bus) = setup_runtime().await;
    let registry = bus.registry();
    let _socket = ManagementSocket::start(&runtime_paths, bus)
        .await
        .expect("socket");

    let socket_path = runtime_paths.state_sys_dir.join("management.sock");
    let mut client = match SocketClient::connect(&socket_path, registry)
        .await
        .expect("socket connect")
    {
        SocketConnect::Ready(client) => client,
        SocketConnect::Stale => panic!("expected socket to be ready"),
        SocketConnect::Incompatible(message) => panic!("socket incompatible: {}", message),
    };

    let content_id = content_id_hex(ContentId(4));
    let response = client
        .send(ManagementCommand::Content(ContentCommand::Read(
            ContentReadRequest {
                id: content_id,
                stream_content: Some(true),
            },
        )))
        .await
        .expect("content read");

    assert_eq!(response.action_id, CONTENT_ACTION_READ_OK);
    let payload = match response.payload {
        ResponsePayload::ContentRead(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert!(payload.content.is_none());
    let stream_id = payload.stream_id.expect("stream id");
    let chunk_bytes = payload.chunk_bytes.expect("chunk bytes");
    let size_bytes = payload.size_bytes.expect("size bytes");

    let mut received = Vec::new();
    let mut expected_seq = 0u32;
    loop {
        let frame = client.read_stream_frame().await.expect("stream frame");
        match frame {
            WsFrame::StreamChunk(chunk) => {
                assert_eq!(chunk.stream_id, stream_id);
                assert_eq!(chunk.seq, expected_seq);
                assert!(chunk.payload.len() <= chunk_bytes as usize);
                received.extend_from_slice(&chunk.payload);
                client
                    .write_stream_frame(&WsFrame::Ack(StreamAckFrame {
                        stream_id,
                        seq: chunk.seq,
                    }))
                    .await
                    .expect("ack");
                if chunk.is_final() {
                    break;
                }
                expected_seq = expected_seq.saturating_add(1);
            }
            other => panic!("unexpected stream frame: {:?}", other),
        }
    }

    assert_eq!(received.len() as u64, size_bytes);
    assert_eq!(received, b"abcdefghijklmnopqrstuvwxyz012345");
}

#[actix_web::test]
async fn socket_read_markdown_returns_inline_content_with_stream_flag() {
    let (_temp, runtime_paths, bus) = setup_runtime().await;
    let registry = bus.registry();
    let _socket = ManagementSocket::start(&runtime_paths, bus)
        .await
        .expect("socket");

    let socket_path = runtime_paths.state_sys_dir.join("management.sock");
    let mut client = match SocketClient::connect(&socket_path, registry)
        .await
        .expect("socket connect")
    {
        SocketConnect::Ready(client) => client,
        SocketConnect::Stale => panic!("expected socket to be ready"),
        SocketConnect::Incompatible(message) => panic!("socket incompatible: {}", message),
    };

    let content_id = content_id_hex(ContentId(1));
    let response = client
        .send(ManagementCommand::Content(ContentCommand::Read(
            ContentReadRequest {
                id: content_id,
                stream_content: Some(true),
            },
        )))
        .await
        .expect("content read");

    assert_eq!(response.action_id, CONTENT_ACTION_READ_OK);
    let payload = match response.payload {
        ResponsePayload::ContentRead(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert!(payload.stream_id.is_none());
    assert!(payload.chunk_bytes.is_none());
    assert!(payload.size_bytes.is_none());
    assert_eq!(
        payload.content.as_deref(),
        Some("# Home\n\nWelcome to the test site.\n")
    );
}
