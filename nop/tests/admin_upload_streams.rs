// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use common::TestHarness;
use nop::management::{
    BinaryPrevalidateRequest, BinaryUploadCommitRequest, BinaryUploadInitRequest,
    CONTENT_ACTION_BINARY_PREVALIDATE_OK, CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
    CONTENT_ACTION_BINARY_UPLOAD_INIT_OK, CONTENT_ACTION_READ_OK,
    CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK, CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
    CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK, CONTENT_ACTION_UPLOAD_STREAM_INIT_OK, ContentCommand,
    ContentReadRequest, ContentUpdateStreamCommitRequest, ContentUpdateStreamInitRequest,
    ContentUploadStreamCommitRequest, ContentUploadStreamInitRequest, ManagementCommand,
    ManagementRequest, ResponsePayload,
};
use nop::util::is_temp_upload_name;
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

#[actix_web::test]
async fn binary_prevalidate_rejects_disallowed_extension() {
    let harness = TestHarness::new().await;
    let bus = harness.app_state.management_bus.clone();

    let response = bus
        .send(
            nop::management::next_connection_id(),
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
    let bus = harness.app_state.management_bus.clone();
    let max_mb = harness.config.upload.max_file_size_mb;
    let oversize = (max_mb + 1) * 1024 * 1024;

    let response = bus
        .send(
            nop::management::next_connection_id(),
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
    let bus = harness.app_state.management_bus.clone();
    let upload_registry = harness.app_state.upload_registry.clone();
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
async fn upload_cleanup_removes_temp_files_on_disconnect() {
    let harness = TestHarness::new().await;
    let bus = harness.app_state.management_bus.clone();
    let upload_registry = harness.app_state.upload_registry.clone();
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
    let bus = harness.app_state.management_bus.clone();
    let upload_registry = harness.app_state.upload_registry.clone();
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
            nop::management::next_connection_id(),
            3,
            ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
                id: content_id.clone(),
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
            nop::management::next_connection_id(),
            6,
            ManagementCommand::Content(ContentCommand::Read(ContentReadRequest { id: content_id })),
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
