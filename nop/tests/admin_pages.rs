// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use nop::content::flat_storage::content_id_hex;
use nop::management::{
    CONTENT_ACTION_DELETE_OK, CONTENT_ACTION_LIST_OK, CONTENT_ACTION_READ_OK,
    CONTENT_ACTION_UPDATE_ERR, CONTENT_ACTION_UPDATE_OK, CONTENT_ACTION_UPLOAD_OK, ContentCommand,
    ContentDeleteRequest, ContentListRequest, ContentReadRequest, ContentSortDirection,
    ContentSortField, ContentUpdateRequest, ContentUploadRequest, ManagementCommand,
    ResponsePayload,
};

#[actix_web::test]
async fn content_upload_list_update_delete() {
    let harness = common::TestHarness::new().await;
    let bus = harness.app_state.management_bus.clone();

    let upload = ContentUploadRequest {
        alias: Some("docs/getting-started".to_string()),
        title: Some("Getting Started".to_string()),
        mime: "text/markdown".to_string(),
        tags: vec!["docs".to_string()],
        nav_title: Some("Getting Started".to_string()),
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
        content: b"# Getting Started\n\nHello.".to_vec(),
    };

    let response = bus
        .send(
            nop::management::next_connection_id(),
            1,
            ManagementCommand::Content(ContentCommand::Upload(upload)),
        )
        .await
        .expect("upload response");
    assert_eq!(response.action_id, CONTENT_ACTION_UPLOAD_OK);
    let upload_payload = match response.payload {
        ResponsePayload::ContentUpload(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    let content_id = upload_payload.id.clone();
    assert_eq!(upload_payload.alias, "docs/getting-started");
    assert_eq!(upload_payload.mime, "text/markdown");

    let list_response = bus
        .send(
            nop::management::next_connection_id(),
            2,
            ManagementCommand::Content(ContentCommand::List(ContentListRequest {
                page: 1,
                page_size: 50,
                sort_field: ContentSortField::Title,
                sort_direction: ContentSortDirection::Asc,
                query: None,
                tags: None,
                markdown_only: true,
            })),
        )
        .await
        .expect("list response");
    assert_eq!(list_response.action_id, CONTENT_ACTION_LIST_OK);

    let list_payload = match list_response.payload {
        ResponsePayload::ContentList(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert!(
        list_payload
            .items
            .iter()
            .any(|item| item.alias == "docs/getting-started")
    );

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
    assert_eq!(read_payload.title.as_deref(), Some("Getting Started"));
    assert_eq!(read_payload.tags, vec!["docs".to_string()]);

    let update_response = bus
        .send(
            nop::management::next_connection_id(),
            4,
            ManagementCommand::Content(ContentCommand::Update(ContentUpdateRequest {
                id: content_id.clone(),
                new_alias: Some("docs/getting-started-updated".to_string()),
                title: Some("Intro".to_string()),
                tags: Some(vec!["docs".to_string(), "intro".to_string()]),
                nav_title: Some("".to_string()),
                nav_parent_id: None,
                nav_order: None,
                theme: Some("landing".to_string()),
                content: Some("# Intro\n\nUpdated".to_string()),
            })),
        )
        .await
        .expect("update response");
    assert_eq!(update_response.action_id, CONTENT_ACTION_UPDATE_OK);

    let read_updated = bus
        .send(
            nop::management::next_connection_id(),
            5,
            ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
                id: content_id.clone(),
            })),
        )
        .await
        .expect("read response");
    assert_eq!(read_updated.action_id, CONTENT_ACTION_READ_OK);

    let delete_response = bus
        .send(
            nop::management::next_connection_id(),
            6,
            ManagementCommand::Content(ContentCommand::Delete(ContentDeleteRequest {
                id: content_id,
            })),
        )
        .await
        .expect("delete response");
    assert_eq!(delete_response.action_id, CONTENT_ACTION_DELETE_OK);
}

#[actix_web::test]
async fn non_markdown_upload_exposes_id_alias() {
    let harness = common::TestHarness::new().await;
    let bus = harness.app_state.management_bus.clone();

    let pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n".to_vec();
    let upload = ContentUploadRequest {
        alias: Some("files/guide.pdf".to_string()),
        title: Some("Guide".to_string()),
        mime: "application/pdf".to_string(),
        tags: vec!["docs".to_string()],
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: Some("guide.pdf".to_string()),
        theme: None,
        content: pdf_bytes,
    };

    let response = bus
        .send(
            nop::management::next_connection_id(),
            1,
            ManagementCommand::Content(ContentCommand::Upload(upload)),
        )
        .await
        .expect("upload response");
    let upload_payload = match response.payload {
        ResponsePayload::ContentUpload(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };

    let id_alias = format!("id/{}", upload_payload.id);
    let object = harness
        .page_cache
        .get_by_alias(&id_alias)
        .expect("id alias should resolve");
    assert!(!object.is_markdown, "uploaded file should be non-markdown");
}

#[actix_web::test]
async fn index_alias_cannot_be_renamed() {
    let harness = common::TestHarness::new().await;
    let bus = harness.app_state.management_bus.clone();

    let response = bus
        .send(
            nop::management::next_connection_id(),
            1,
            ManagementCommand::Content(ContentCommand::Update(ContentUpdateRequest {
                id: content_id_hex(
                    harness
                        .page_cache
                        .get_by_alias("index")
                        .expect("index content should exist")
                        .key
                        .id,
                ),
                new_alias: Some("home".to_string()),
                title: None,
                tags: None,
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                theme: None,
                content: None,
            })),
        )
        .await
        .expect("update response");

    assert_eq!(response.action_id, CONTENT_ACTION_UPDATE_ERR);
}

#[actix_web::test]
async fn content_read_update_delete_by_id() {
    let harness = common::TestHarness::new().await;
    let bus = harness.app_state.management_bus.clone();

    let upload = ContentUploadRequest {
        alias: None,
        title: Some("ID Only".to_string()),
        mime: "text/markdown".to_string(),
        tags: vec!["docs".to_string()],
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
        content: b"# ID Only\n\nHello.".to_vec(),
    };

    let response = bus
        .send(
            nop::management::next_connection_id(),
            1,
            ManagementCommand::Content(ContentCommand::Upload(upload)),
        )
        .await
        .expect("upload response");
    let upload_payload = match response.payload {
        ResponsePayload::ContentUpload(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    let content_id = upload_payload.id.clone();

    let read_response = bus
        .send(
            nop::management::next_connection_id(),
            2,
            ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
                id: content_id.clone(),
            })),
        )
        .await
        .expect("read response");
    assert_eq!(read_response.action_id, CONTENT_ACTION_READ_OK);

    let update_response = bus
        .send(
            nop::management::next_connection_id(),
            3,
            ManagementCommand::Content(ContentCommand::Update(ContentUpdateRequest {
                id: content_id.clone(),
                new_alias: Some("docs/id-only".to_string()),
                title: Some("ID Only Updated".to_string()),
                tags: Some(vec!["docs".to_string(), "id".to_string()]),
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                theme: None,
                content: Some("# ID Only\n\nUpdated.".to_string()),
            })),
        )
        .await
        .expect("update response");
    assert_eq!(update_response.action_id, CONTENT_ACTION_UPDATE_OK);

    let read_updated = bus
        .send(
            nop::management::next_connection_id(),
            4,
            ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
                id: content_id.clone(),
            })),
        )
        .await
        .expect("read updated response");
    assert_eq!(read_updated.action_id, CONTENT_ACTION_READ_OK);
    let read_payload = match read_updated.payload {
        ResponsePayload::ContentRead(payload) => payload,
        other => panic!("unexpected payload: {:?}", other),
    };
    assert_eq!(read_payload.alias, "docs/id-only");

    let delete_response = bus
        .send(
            nop::management::next_connection_id(),
            5,
            ManagementCommand::Content(ContentCommand::Delete(ContentDeleteRequest {
                id: content_id,
            })),
        )
        .await
        .expect("delete response");
    assert_eq!(delete_response.action_id, CONTENT_ACTION_DELETE_OK);
}
