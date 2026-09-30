// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{body::to_bytes, http::StatusCode, test};
use common::{TestHarness, build_test_app};
use nop_content_store::flat_storage::{ContentVersion, blob_path, parse_content_id_hex};
use nop_management_contract::content::{
    BinaryPrevalidateRequest, BinaryUploadCommitRequest, BinaryUploadInitRequest,
    CONTENT_ACTION_ALIAS_STATUS_OK, CONTENT_ACTION_BINARY_PREVALIDATE_OK,
    CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK, CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
    CONTENT_ACTION_BINARY_UPLOAD_INIT_OK, CONTENT_ACTION_READ_OK,
    CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK, CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
    CONTENT_ACTION_UPLOAD_OK, CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
    CONTENT_ACTION_UPLOAD_STREAM_INIT_OK, ContentAliasStatusRequest, ContentCommand,
    ContentReadRequest, ContentUpdateStreamCommitRequest, ContentUpdateStreamInitRequest,
    ContentUploadRequest, ContentUploadResponse, ContentUploadStreamCommitRequest,
    ContentUploadStreamInitRequest, ContentWidthMode,
};
use nop_management_contract::{ManagementCommand, ManagementRequest, ResponsePayload};
use nop_rt_page_cache::is_temp_upload_name;
use std::fs;
use std::path::{Path, PathBuf};

fn collect_temp_uploads(content_dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut stack = vec![content_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(_) => continue,
                };
                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if is_temp_upload_name(name_str.as_ref()) {
                    results.push(path);
                }
            }
        }
    }
    results
}

async fn upload_binary_stream(
    harness: &TestHarness,
    connection_id: u32,
    alias: &str,
    filename: &str,
    payload: &[u8],
) -> ContentUploadResponse {
    let bus = harness.management_tools.management_bus.clone();
    let upload_registry = harness.management_tools.upload_registry.clone();
    let init_response = bus
        .send_request(ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::BinaryUploadInit(
                BinaryUploadInitRequest {
                    alias: Some(alias.to_string()),
                    title: Some("Streamed".to_string()),
                    tags: vec!["docs".to_string()],
                    filename: filename.to_string(),
                    mime: "application/octet-stream".to_string(),
                    size_bytes: payload.len() as u64,
                },
            )),
            actor_email: None,
        })
        .await
        .expect("init response");

    assert_eq!(
        init_response.action_id,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_OK
    );
    let init_payload = match init_response.payload {
        ResponsePayload::ContentUploadStreamInit(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };

    upload_registry
        .append_chunk(init_payload.stream_id, payload.to_vec(), true, false)
        .await
        .expect("append chunk");

    let commit_response = bus
        .send_request(ManagementRequest {
            workflow_id: 2,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::BinaryUploadCommit(
                BinaryUploadCommitRequest {
                    upload_id: init_payload.upload_id,
                },
            )),
            actor_email: None,
        })
        .await
        .expect("commit response");

    assert_eq!(
        commit_response.action_id,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK
    );
    match commit_response.payload {
        ResponsePayload::ContentUpload(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    }
}

#[actix_web::test]
async fn binary_prevalidate_rejects_disallowed_extension() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();

    let response = bus
        .send(
            nop_management_bus::next_connection_id(),
            1,
            ManagementCommand::Content(ContentCommand::BinaryPrevalidate(
                BinaryPrevalidateRequest {
                    filename: "malware.exe".to_string(),
                    mime: "application/octet-stream".to_string(),
                    size_bytes: 1024,
                },
            )),
        )
        .await
        .expect("prevalidate response");

    assert_eq!(response.action_id, CONTENT_ACTION_BINARY_PREVALIDATE_OK);
    let payload = match response.payload {
        ResponsePayload::ContentBinaryPrevalidate(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert!(!payload.accepted, "expected prevalidation rejection");
}

#[actix_web::test]
async fn binary_prevalidate_rejects_oversize() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let max_mb = harness.config.upload.max_file_size_mb;
    let oversize = (max_mb + 1) * 1024 * 1024;

    let response = bus
        .send(
            nop_management_bus::next_connection_id(),
            1,
            ManagementCommand::Content(ContentCommand::BinaryPrevalidate(
                BinaryPrevalidateRequest {
                    filename: "too-big.bin".to_string(),
                    mime: "application/octet-stream".to_string(),
                    size_bytes: oversize,
                },
            )),
        )
        .await
        .expect("prevalidate response");

    assert_eq!(response.action_id, CONTENT_ACTION_BINARY_PREVALIDATE_OK);
    let payload = match response.payload {
        ResponsePayload::ContentBinaryPrevalidate(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert!(!payload.accepted, "expected oversize rejection");
}

#[actix_web::test]
async fn binary_stream_upload_commits() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let upload_registry = harness.management_tools.upload_registry.clone();
    let connection_id = 7;

    let payload = b"streamed-binary".to_vec();
    let init_request = BinaryUploadInitRequest {
        alias: Some("files/streamed.bin".to_string()),
        title: Some("Streamed".to_string()),
        tags: vec!["docs".to_string()],
        filename: "streamed.bin".to_string(),
        mime: "application/octet-stream".to_string(),
        size_bytes: payload.len() as u64,
    };

    let init_response = bus
        .send_request(ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::BinaryUploadInit(init_request)),
            actor_email: None,
        })
        .await
        .expect("init response");

    assert_eq!(
        init_response.action_id,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_OK
    );
    let init_payload = match init_response.payload {
        ResponsePayload::ContentUploadStreamInit(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };

    upload_registry
        .append_chunk(init_payload.stream_id, payload, true, false)
        .await
        .expect("append chunk");

    let commit_response = bus
        .send_request(ManagementRequest {
            workflow_id: 2,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::BinaryUploadCommit(
                BinaryUploadCommitRequest {
                    upload_id: init_payload.upload_id,
                },
            )),
            actor_email: None,
        })
        .await
        .expect("commit response");

    assert_eq!(
        commit_response.action_id,
        CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK
    );
    let upload_payload = match commit_response.payload {
        ResponsePayload::ContentUpload(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert_eq!(upload_payload.alias, "files/streamed.bin");

    let object = harness
        .page_cache
        .get_by_alias("files/streamed.bin")
        .expect("uploaded file should be in cache");
    assert!(!object.is_markdown, "uploaded file should be non-markdown");
}

#[actix_web::test]
async fn binary_stream_upload_same_alias_creates_new_version() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let alias = "files/versioned.bin";

    let first = upload_binary_stream(&harness, 31, alias, "versioned.bin", b"version-one").await;
    let content_id = parse_content_id_hex(&first.id).expect("content id");
    let first_object = harness
        .page_cache
        .get_by_alias(alias)
        .expect("first upload in cache");
    assert_eq!(first_object.key.id, content_id);
    assert_eq!(first_object.key.version, ContentVersion(1));

    let status_response = bus
        .send_request(ManagementRequest {
            workflow_id: 3,
            connection_id: 31,
            command: ManagementCommand::Content(ContentCommand::AliasStatus(
                ContentAliasStatusRequest {
                    alias: alias.to_string(),
                },
            )),
            actor_email: None,
        })
        .await
        .expect("alias status response");
    assert_eq!(status_response.action_id, CONTENT_ACTION_ALIAS_STATUS_OK);
    let status = match status_response.payload {
        ResponsePayload::ContentAliasStatus(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert!(status.exists);
    assert_eq!(status.id.as_deref(), Some(first.id.as_str()));
    assert_eq!(status.version, Some(1));
    assert_eq!(status.is_markdown, Some(false));

    let second = upload_binary_stream(&harness, 32, alias, "versioned.bin", b"version-two").await;
    assert_eq!(second.id, first.id);

    let second_object = harness
        .page_cache
        .get_by_alias(alias)
        .expect("second upload in cache");
    assert_eq!(second_object.key.id, content_id);
    assert_eq!(second_object.key.version, ContentVersion(2));

    let first_blob = blob_path(
        &harness.runtime_paths.content_dir,
        content_id,
        ContentVersion(1),
    );
    let second_blob = blob_path(
        &harness.runtime_paths.content_dir,
        content_id,
        ContentVersion(2),
    );
    assert_eq!(
        fs::read(first_blob).expect("read first blob"),
        b"version-one"
    );
    assert_eq!(
        fs::read(second_blob).expect("read second blob"),
        b"version-two"
    );

    let app = test::init_service(build_test_app(harness.app_bundle())).await;
    let alias_response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/files/versioned.bin")
            .to_request(),
    )
    .await;
    assert_eq!(alias_response.status(), StatusCode::OK);
    let alias_body = to_bytes(alias_response.into_body())
        .await
        .expect("alias body");
    assert_eq!(alias_body.as_ref(), b"version-two");

    let id_response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/id/{}", first.id))
            .to_request(),
    )
    .await;
    assert_eq!(id_response.status(), StatusCode::OK);
    let id_body = to_bytes(id_response.into_body()).await.expect("id body");
    assert_eq!(id_body.as_ref(), b"version-two");
}

#[actix_web::test]
async fn binary_stream_upload_same_alias_pending_uploads_reserve_distinct_versions() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let upload_registry = harness.management_tools.upload_registry.clone();
    let alias = "files/race.bin";

    let first = upload_binary_stream(&harness, 51, alias, "race.bin", b"version-one").await;
    let content_id = parse_content_id_hex(&first.id).expect("content id");

    let init_pending = |connection_id: u32, workflow_id: u32| {
        let bus = bus.clone();
        let alias = alias.to_string();
        async move {
            let response = bus
                .send_request(ManagementRequest {
                    workflow_id,
                    connection_id,
                    command: ManagementCommand::Content(ContentCommand::BinaryUploadInit(
                        BinaryUploadInitRequest {
                            alias: Some(alias),
                            title: Some("Race".to_string()),
                            tags: vec![],
                            filename: "race.bin".to_string(),
                            mime: "application/octet-stream".to_string(),
                            size_bytes: 11,
                        },
                    )),
                    actor_email: None,
                })
                .await
                .expect("init response");
            assert_eq!(response.action_id, CONTENT_ACTION_BINARY_UPLOAD_INIT_OK);
            match response.payload {
                ResponsePayload::ContentUploadStreamInit(payload) => payload,
                other => panic!("unexpected payload: {:?}", other),
            }
        }
    };

    let second_init = init_pending(52, 2).await;
    let third_init = init_pending(53, 3).await;

    upload_registry
        .append_chunk(second_init.stream_id, b"version-two".to_vec(), true, false)
        .await
        .expect("append second");
    upload_registry
        .append_chunk(third_init.stream_id, b"version-3!!".to_vec(), true, false)
        .await
        .expect("append third");

    for (connection_id, upload_id) in [(52, second_init.upload_id), (53, third_init.upload_id)] {
        let response = bus
            .send_request(ManagementRequest {
                workflow_id: 4,
                connection_id,
                command: ManagementCommand::Content(ContentCommand::BinaryUploadCommit(
                    BinaryUploadCommitRequest { upload_id },
                )),
                actor_email: None,
            })
            .await
            .expect("commit response");
        assert_eq!(response.action_id, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK);
    }

    let second_blob = blob_path(
        &harness.runtime_paths.content_dir,
        content_id,
        ContentVersion(2),
    );
    let third_blob = blob_path(
        &harness.runtime_paths.content_dir,
        content_id,
        ContentVersion(3),
    );
    assert_eq!(
        fs::read(second_blob).expect("read second blob"),
        b"version-two"
    );
    assert_eq!(
        fs::read(third_blob).expect("read third blob"),
        b"version-3!!"
    );
    let latest = harness
        .page_cache
        .get_by_alias(alias)
        .expect("latest object in cache");
    assert_eq!(latest.key.version, ContentVersion(3));
}

#[actix_web::test]
async fn binary_stream_upload_rejects_existing_markdown_alias() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let alias = "docs/markdown-alias";

    let create_response = bus
        .send_request(ManagementRequest {
            workflow_id: 1,
            connection_id: 41,
            command: ManagementCommand::Content(ContentCommand::Upload(ContentUploadRequest {
                alias: Some(alias.to_string()),
                title: Some("Markdown Alias".to_string()),
                mime: "text/markdown".to_string(),
                tags: vec!["docs".to_string()],
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                original_filename: None,
                theme: None,
                disable_navbar: false,
                disable_floating_nav: false,
                content_width: ContentWidthMode::Auto,
                content: b"# Markdown Alias\n".to_vec(),
            })),
            actor_email: None,
        })
        .await
        .expect("markdown create response");
    assert_eq!(create_response.action_id, CONTENT_ACTION_UPLOAD_OK);

    let init_response = bus
        .send_request(ManagementRequest {
            workflow_id: 2,
            connection_id: 41,
            command: ManagementCommand::Content(ContentCommand::BinaryUploadInit(
                BinaryUploadInitRequest {
                    alias: Some(alias.to_string()),
                    title: Some("Binary".to_string()),
                    tags: vec![],
                    filename: "binary.bin".to_string(),
                    mime: "application/octet-stream".to_string(),
                    size_bytes: 6,
                },
            )),
            actor_email: None,
        })
        .await
        .expect("binary init response");
    assert_eq!(
        init_response.action_id,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR
    );
}

#[actix_web::test]
async fn upload_cleanup_removes_temp_files_on_disconnect() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let upload_registry = harness.management_tools.upload_registry.clone();
    let connection_id = 11;

    let init_request = BinaryUploadInitRequest {
        alias: Some("files/temp.bin".to_string()),
        title: None,
        tags: vec![],
        filename: "temp.bin".to_string(),
        mime: "application/octet-stream".to_string(),
        size_bytes: 4,
    };

    let init_response = bus
        .send_request(ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::BinaryUploadInit(init_request)),
            actor_email: None,
        })
        .await
        .expect("init response");

    assert_eq!(
        init_response.action_id,
        CONTENT_ACTION_BINARY_UPLOAD_INIT_OK
    );

    let temp_files = collect_temp_uploads(&harness.runtime_paths.content_dir);
    assert_eq!(temp_files.len(), 1, "expected a temp upload file");

    upload_registry
        .cleanup_connection(connection_id)
        .await
        .expect("cleanup connection");

    let remaining = collect_temp_uploads(&harness.runtime_paths.content_dir);
    assert!(remaining.is_empty(), "temp uploads should be cleaned up");
}

#[actix_web::test]
async fn startup_scan_removes_temp_uploads() {
    let harness = TestHarness::new().await;
    let content_dir = &harness.runtime_paths.content_dir;
    let shard_dir = content_dir.join("00");
    fs::create_dir_all(&shard_dir).expect("create shard dir");
    let temp_path = shard_dir.join("orphan.upload");
    fs::write(&temp_path, b"temp").expect("write temp file");
    assert!(temp_path.exists());

    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("rebuild cache");

    assert!(!temp_path.exists(), "temp upload should be removed");
}

#[actix_web::test]
async fn markdown_stream_create_and_update() {
    let harness = TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let upload_registry = harness.management_tools.upload_registry.clone();
    let connection_id = 21;

    let content = "# Streamed\n\nHello.".to_string();
    let content_bytes = content.as_bytes().to_vec();
    let init_request = ContentUploadStreamInitRequest {
        alias: Some("docs/streamed".to_string()),
        title: Some("Streamed".to_string()),
        tags: vec!["docs".to_string()],
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        theme: None,
        disable_navbar: false,
        disable_floating_nav: false,
        content_width: Default::default(),
        size_bytes: content_bytes.len() as u64,
    };

    let init_response = bus
        .send_request(ManagementRequest {
            workflow_id: 1,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::UploadStreamInit(init_request)),
            actor_email: None,
        })
        .await
        .expect("stream init response");

    assert_eq!(
        init_response.action_id,
        CONTENT_ACTION_UPLOAD_STREAM_INIT_OK
    );
    let init_payload = match init_response.payload {
        ResponsePayload::ContentUploadStreamInit(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };

    upload_registry
        .append_chunk(init_payload.stream_id, content_bytes, true, false)
        .await
        .expect("append stream chunk");

    let commit_response = bus
        .send_request(ManagementRequest {
            workflow_id: 2,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::UploadStreamCommit(
                ContentUploadStreamCommitRequest {
                    upload_id: init_payload.upload_id,
                },
            )),
            actor_email: None,
        })
        .await
        .expect("stream commit response");

    assert_eq!(
        commit_response.action_id,
        CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK
    );

    let commit_payload = match commit_response.payload {
        ResponsePayload::ContentUpload(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    let content_id = commit_payload.id.clone();

    let read_response = bus
        .send(
            nop_management_bus::next_connection_id(),
            3,
            ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
                id: content_id.clone(),
                stream_content: None,
            })),
        )
        .await
        .expect("read response");

    assert_eq!(read_response.action_id, CONTENT_ACTION_READ_OK);
    let read_payload = match read_response.payload {
        ResponsePayload::ContentRead(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert_eq!(read_payload.content.as_deref(), Some(content.as_str()));
    let content_id = read_payload.id.clone();

    let updated = "# Streamed\n\nUpdated.".to_string();
    let updated_bytes = updated.as_bytes().to_vec();
    let update_request = ContentUpdateStreamInitRequest {
        id: content_id.clone(),
        new_alias: None,
        title: Some("Streamed Updated".to_string()),
        tags: Some(vec!["docs".to_string(), "updated".to_string()]),
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        theme: None,
        disable_navbar: None,
        disable_floating_nav: None,
        content_width: Default::default(),
        size_bytes: updated_bytes.len() as u64,
    };

    let update_init = bus
        .send_request(ManagementRequest {
            workflow_id: 4,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::UpdateStreamInit(update_request)),
            actor_email: None,
        })
        .await
        .expect("update init response");

    assert_eq!(update_init.action_id, CONTENT_ACTION_UPDATE_STREAM_INIT_OK);
    let update_payload = match update_init.payload {
        ResponsePayload::ContentUploadStreamInit(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };

    upload_registry
        .append_chunk(update_payload.stream_id, updated_bytes, true, false)
        .await
        .expect("append updated chunk");

    let update_commit = bus
        .send_request(ManagementRequest {
            workflow_id: 5,
            connection_id,
            command: ManagementCommand::Content(ContentCommand::UpdateStreamCommit(
                ContentUpdateStreamCommitRequest {
                    upload_id: update_payload.upload_id,
                },
            )),
            actor_email: None,
        })
        .await
        .expect("update commit response");

    assert_eq!(
        update_commit.action_id,
        CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK
    );

    let read_updated = bus
        .send(
            nop_management_bus::next_connection_id(),
            6,
            ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
                id: content_id,
                stream_content: None,
            })),
        )
        .await
        .expect("read updated response");

    assert_eq!(read_updated.action_id, CONTENT_ACTION_READ_OK);
    let read_payload = match read_updated.payload {
        ResponsePayload::ContentRead(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert_eq!(read_payload.content.as_deref(), Some(updated.as_str()));
}
