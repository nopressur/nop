// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use awc::Client;
use awc::ws::Message as ClientMessage;
use common::ws;
use futures_util::SinkExt;
use nop::management::ws::{AuthFrame, WsFrame, encode_frame};
use nop::management::{
    AccessRule, MessageResponse, TAG_ACTION_ADD, TAG_ACTION_ADD_OK, TAG_ACTION_CHANGE,
    TAG_ACTION_CHANGE_OK, TAG_ACTION_DELETE, TAG_ACTION_DELETE_OK, TAG_ACTION_SHOW,
    TAG_ACTION_SHOW_OK, TAGS_DOMAIN_ID, TagAddRequest, TagChangeRequest, TagDeleteRequest,
    TagShowRequest,
};

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

    let show: nop::management::TagShowResponse = ws::decode_payload(&response.payload);
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
