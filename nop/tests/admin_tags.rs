// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use awc::Client;
use awc::ws::Message as ClientMessage;
use common::ws;
use futures_util::SinkExt;
use nop_management_bus::ws::{AuthFrame, WsFrame, encode_frame};
use nop_management_contract::content::{
    CONTENT_ACTION_DELETE_OK, CONTENT_ACTION_UPDATE_OK, CONTENT_ACTION_UPLOAD_OK, ContentCommand,
    ContentDeleteRequest, ContentUpdateRequest, ContentUploadRequest,
};
use nop_management_contract::tags::{
    TAG_ACTION_ADD, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE, TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE,
    TAG_ACTION_DELETE_OK, TAG_ACTION_LIST_OK, TAG_ACTION_SHOW, TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID,
    TagAddRequest, TagChangeRequest, TagCommand, TagDeleteRequest, TagListRequest, TagShowRequest,
};
use nop_management_contract::{AccessRule, ManagementCommand, MessageResponse, ResponsePayload};
use std::collections::BTreeMap;

#[actix_web::test]
async fn create_update_delete_tag() {
    let harness = common::TestHarness::new().await;
    let session = harness.admin_auth();
    let base_url = ws::start_test_server(harness.app_bundle()).await;

    let client = Client::new();
    let ticket = harness.ws_ticket_store.issue(&session.jwt_id);

    let (_resp, mut framed) = client
        .ws(format!("{}/admin/ws", base_url))
        .cookie(session.cookie.clone())
        .connect()
        .await
        .expect("connect");

    let auth = WsFrame::Auth(AuthFrame {
        ticket,
        csrf_token: session.csrf_token.clone(),
    });
    let auth_bytes = encode_frame(&auth).expect("encode auth");
    framed
        .send(ClientMessage::Binary(auth_bytes.into()))
        .await
        .expect("send auth");

    match ws::read_ws_frame(&mut framed).await {
        WsFrame::AuthOk(_) => {}
        other => panic!("Expected AuthOk, got {:?}", other),
    }

    let tag_id = "news/alerts";
    let add_payload = ws::encode_payload(&TagAddRequest {
        id: tag_id.to_string(),
        name: "News Alerts".to_string(),
        roles: vec!["editor".to_string()],
        access_rule: Some(AccessRule::Union),
    });

    let response =
        ws::send_request(&mut framed, 1, TAGS_DOMAIN_ID, TAG_ACTION_ADD, add_payload).await;
    assert_eq!(response.domain_id, TAGS_DOMAIN_ID);
    assert_eq!(response.action_id, TAG_ACTION_ADD_OK);

    let message: MessageResponse = ws::decode_payload(&response.payload);
    assert!(!message.message.is_empty());

    let show_payload = ws::encode_payload(&TagShowRequest {
        id: tag_id.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        2,
        TAGS_DOMAIN_ID,
        TAG_ACTION_SHOW,
        show_payload,
    )
    .await;
    assert_eq!(response.action_id, TAG_ACTION_SHOW_OK);

    let show: nop_management_contract::tags::TagShowResponse =
        ws::decode_payload(&response.payload);
    assert_eq!(show.id, tag_id);
    assert_eq!(show.name, "News Alerts");
    assert_eq!(show.roles, vec!["editor".to_string()]);
    assert_eq!(show.access_rule, Some(AccessRule::Union));

    let change_payload = ws::encode_payload(&TagChangeRequest {
        id: tag_id.to_string(),
        new_id: None,
        name: Some("News Alerts Updated".to_string()),
        roles: Some(Vec::new()),
        access_rule: Some(AccessRule::Intersect),
        clear_access: false,
    });
    let response = ws::send_request(
        &mut framed,
        3,
        TAGS_DOMAIN_ID,
        TAG_ACTION_CHANGE,
        change_payload,
    )
    .await;
    assert_eq!(response.action_id, TAG_ACTION_CHANGE_OK);

    let delete_payload = ws::encode_payload(&TagDeleteRequest {
        id: tag_id.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        4,
        TAGS_DOMAIN_ID,
        TAG_ACTION_DELETE,
        delete_payload,
    )
    .await;
    assert_eq!(response.action_id, TAG_ACTION_DELETE_OK);
}

#[actix_web::test]
async fn tag_list_reports_usage_counts() {
    let harness = common::TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();

    for (id, name) in [
        ("news", "News"),
        ("updates", "Updates"),
        ("unused", "Unused"),
    ] {
        let response = bus
            .send(
                nop_management_bus::next_connection_id(),
                1,
                ManagementCommand::Tags(TagCommand::Add(TagAddRequest {
                    id: id.to_string(),
                    name: name.to_string(),
                    roles: Vec::new(),
                    access_rule: None,
                })),
            )
            .await
            .expect("add tag");
        assert_eq!(response.action_id, TAG_ACTION_ADD_OK);
    }

    let upload_request = |alias: &str, tags: Vec<&str>| ContentUploadRequest {
        alias: Some(alias.to_string()),
        title: Some(alias.to_string()),
        mime: "text/markdown".to_string(),
        tags: tags.into_iter().map(str::to_string).collect(),
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
        disable_navbar: false,
        disable_floating_nav: false,
        content_width: Default::default(),
        disable_auto_links: false,
        content: b"# Title\n".to_vec(),
    };
    let upload_content = async |alias: &str, tags: Vec<&str>| {
        let response = bus
            .send(
                nop_management_bus::next_connection_id(),
                10,
                ManagementCommand::Content(ContentCommand::Upload(upload_request(alias, tags))),
            )
            .await
            .expect("upload content");
        assert_eq!(response.action_id, CONTENT_ACTION_UPLOAD_OK);
        match response.payload {
            ResponsePayload::ContentUpload(payload) => payload.id,
            other => panic!("unexpected payload: {other:?}"),
        }
    };

    let list_counts = || async {
        let response = bus
            .send(
                nop_management_bus::next_connection_id(),
                20,
                ManagementCommand::Tags(TagCommand::List(TagListRequest {})),
            )
            .await
            .expect("list tags");
        assert_eq!(response.action_id, TAG_ACTION_LIST_OK);
        match response.payload {
            ResponsePayload::TagList(payload) => payload
                .tags
                .into_iter()
                .map(|tag| (tag.id, tag.usage_count))
                .collect::<BTreeMap<String, u32>>(),
            other => panic!("unexpected payload: {other:?}"),
        }
    };

    let first_id = upload_content("first", vec!["news"]).await;
    let second_id = upload_content("second", vec!["news", "updates"]).await;
    let counts = list_counts().await;
    assert_eq!(
        counts,
        BTreeMap::from([
            ("admin".to_string(), 1),
            ("news".to_string(), 2),
            ("unused".to_string(), 0),
            ("updates".to_string(), 1),
        ])
    );

    let response = bus
        .send(
            nop_management_bus::next_connection_id(),
            30,
            ManagementCommand::Content(ContentCommand::Update(ContentUpdateRequest {
                id: first_id,
                new_alias: None,
                title: None,
                tags: Some(vec!["updates".to_string()]),
                nav_title: None,
                nav_parent_id: None,
                nav_order: None,
                theme: None,
                disable_navbar: None,
                disable_floating_nav: None,
                content_width: None,
                disable_auto_links: None,
                content: None,
            })),
        )
        .await
        .expect("update content");
    assert_eq!(response.action_id, CONTENT_ACTION_UPDATE_OK);
    let counts = list_counts().await;
    assert_eq!(
        counts,
        BTreeMap::from([
            ("admin".to_string(), 1),
            ("news".to_string(), 1),
            ("unused".to_string(), 0),
            ("updates".to_string(), 2),
        ])
    );

    let response = bus
        .send(
            nop_management_bus::next_connection_id(),
            40,
            ManagementCommand::Content(ContentCommand::Delete(ContentDeleteRequest {
                id: second_id,
            })),
        )
        .await
        .expect("delete content");
    assert_eq!(response.action_id, CONTENT_ACTION_DELETE_OK);
    let counts = list_counts().await;
    assert_eq!(
        counts,
        BTreeMap::from([
            ("admin".to_string(), 1),
            ("news".to_string(), 0),
            ("unused".to_string(), 0),
            ("updates".to_string(), 1),
        ])
    );
}
