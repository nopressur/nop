// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use awc::Client;
use awc::ws::Message as ClientMessage;
use common::ws;
use futures_util::SinkExt;
use nop::config::PasswordHashingParams;
use nop::iam::derive_front_end_hash;
use nop::management::ws::{AuthFrame, WsFrame, encode_frame};
use nop::management::{
    MessageResponse, PasswordPayload, PasswordSaltResponse, PasswordValidateResponse,
    USER_ACTION_ADD, USER_ACTION_ADD_OK, USER_ACTION_CHANGE, USER_ACTION_CHANGE_OK,
    USER_ACTION_DELETE, USER_ACTION_DELETE_OK, USER_ACTION_PASSWORD_SALT,
    USER_ACTION_PASSWORD_SALT_OK, USER_ACTION_PASSWORD_SET, USER_ACTION_PASSWORD_SET_OK,
    USER_ACTION_PASSWORD_UPDATE, USER_ACTION_PASSWORD_UPDATE_ERR, USER_ACTION_PASSWORD_VALIDATE,
    USER_ACTION_PASSWORD_VALIDATE_OK, USER_ACTION_ROLE_ADD, USER_ACTION_ROLE_ADD_OK,
    USER_ACTION_ROLE_REMOVE, USER_ACTION_ROLE_REMOVE_OK, USER_ACTION_SHOW, USER_ACTION_SHOW_OK,
    USERS_DOMAIN_ID, UserAddRequest, UserChangeRequest, UserDeleteRequest, UserPasswordSaltRequest,
    UserPasswordSetRequest, UserPasswordUpdateRequest, UserPasswordValidateRequest,
    UserRoleAddRequest, UserRoleRemoveRequest, UserShowRequest, UserShowResponse,
};

#[actix_web::test]
async fn create_update_delete_user() {
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

    let user_email = "editor@example.com";
    let salt_payload = ws::encode_payload(&UserPasswordSaltRequest {
        email: user_email.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        1,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT,
        salt_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_SALT_OK);

    let salt: PasswordSaltResponse = ws::decode_payload(&response.payload);
    let params = PasswordHashingParams::default();
    let front_end_hash = derive_front_end_hash(
        "editor-password",
        &salt.next_front_end_salt,
        &params.front_end,
    )
    .expect("front_end_hash");

    let add_payload = ws::encode_payload(&UserAddRequest {
        email: user_email.to_string(),
        name: "Editor User".to_string(),
        password: PasswordPayload::FrontEndHash {
            front_end_hash,
            front_end_salt: salt.next_front_end_salt,
        },
        roles: vec!["editor".to_string()],
        change_token: Some(salt.change_token),
    });

    let response = ws::send_request(
        &mut framed,
        2,
        USERS_DOMAIN_ID,
        USER_ACTION_ADD,
        add_payload,
    )
    .await;
    assert_eq!(response.domain_id, USERS_DOMAIN_ID);
    assert_eq!(response.action_id, USER_ACTION_ADD_OK);

    let message: MessageResponse = ws::decode_payload(&response.payload);
    assert!(!message.message.is_empty());

    let users_yaml =
        std::fs::read_to_string(&harness.runtime_paths.users_file).expect("users.yaml");
    assert!(users_yaml.contains(user_email));

    let change_payload = ws::encode_payload(&UserChangeRequest {
        email: user_email.to_string(),
        name: Some("Editor User Updated".to_string()),
        roles: None,
    });

    let response = ws::send_request(
        &mut framed,
        3,
        USERS_DOMAIN_ID,
        USER_ACTION_CHANGE,
        change_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_CHANGE_OK);

    let role_payload = ws::encode_payload(&UserRoleAddRequest {
        email: user_email.to_string(),
        role: "writer".to_string(),
    });

    let response = ws::send_request(
        &mut framed,
        4,
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_ADD,
        role_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_ROLE_ADD_OK);

    let users_yaml =
        std::fs::read_to_string(&harness.runtime_paths.users_file).expect("users.yaml");
    assert!(users_yaml.contains("writer"));

    let delete_payload = ws::encode_payload(&UserDeleteRequest {
        email: user_email.to_string(),
    });

    let response = ws::send_request(
        &mut framed,
        5,
        USERS_DOMAIN_ID,
        USER_ACTION_DELETE,
        delete_payload,
    )
    .await;
    if response.action_id != USER_ACTION_DELETE_OK {
        let message: MessageResponse = ws::decode_payload(&response.payload);
        panic!("delete failed: {}", message.message);
    }

    let users_yaml =
        std::fs::read_to_string(&harness.runtime_paths.users_file).expect("users.yaml");
    assert!(!users_yaml.contains(user_email));
}

#[actix_web::test]
async fn password_set_via_salt() {
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

    let user_email = "salted@example.com";
    let salt_payload = ws::encode_payload(&UserPasswordSaltRequest {
        email: user_email.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        1,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT,
        salt_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_SALT_OK);

    let salt: PasswordSaltResponse = ws::decode_payload(&response.payload);
    let params = PasswordHashingParams::default();
    let initial_hash =
        derive_front_end_hash("initial-pass", &salt.next_front_end_salt, &params.front_end)
            .expect("front_end_hash");

    let add_payload = ws::encode_payload(&UserAddRequest {
        email: user_email.to_string(),
        name: "Salted User".to_string(),
        password: PasswordPayload::FrontEndHash {
            front_end_hash: initial_hash,
            front_end_salt: salt.next_front_end_salt.clone(),
        },
        roles: vec!["editor".to_string()],
        change_token: Some(salt.change_token.clone()),
    });

    let response = ws::send_request(
        &mut framed,
        2,
        USERS_DOMAIN_ID,
        USER_ACTION_ADD,
        add_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_ADD_OK);

    let salt_payload = ws::encode_payload(&UserPasswordSaltRequest {
        email: user_email.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        3,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT,
        salt_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_SALT_OK);

    let salt: PasswordSaltResponse = ws::decode_payload(&response.payload);
    let new_password = "updated-pass";
    let front_end_hash =
        derive_front_end_hash(new_password, &salt.next_front_end_salt, &params.front_end)
            .expect("front_end_hash");

    let set_payload = ws::encode_payload(&UserPasswordSetRequest {
        email: user_email.to_string(),
        password: PasswordPayload::FrontEndHash {
            front_end_hash: front_end_hash.clone(),
            front_end_salt: salt.next_front_end_salt.clone(),
        },
        change_token: Some(salt.change_token.clone()),
    });
    let response = ws::send_request(
        &mut framed,
        4,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SET,
        set_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_SET_OK);

    let validate_payload = ws::encode_payload(&UserPasswordValidateRequest {
        email: user_email.to_string(),
        front_end_hash,
    });
    let response = ws::send_request(
        &mut framed,
        5,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_VALIDATE,
        validate_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_VALIDATE_OK);

    let validate: PasswordValidateResponse = ws::decode_payload(&response.payload);
    assert!(validate.valid);
}

#[actix_web::test]
async fn password_update_rejects_invalid_current() {
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

    let user_email = "update@example.com";
    let salt_payload = ws::encode_payload(&UserPasswordSaltRequest {
        email: user_email.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        1,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT,
        salt_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_SALT_OK);

    let salt: PasswordSaltResponse = ws::decode_payload(&response.payload);
    let params = PasswordHashingParams::default();
    let initial_hash =
        derive_front_end_hash("initial-pass", &salt.next_front_end_salt, &params.front_end)
            .expect("front_end_hash");

    let add_payload = ws::encode_payload(&UserAddRequest {
        email: user_email.to_string(),
        name: "Update User".to_string(),
        password: PasswordPayload::FrontEndHash {
            front_end_hash: initial_hash,
            front_end_salt: salt.next_front_end_salt.clone(),
        },
        roles: vec!["editor".to_string()],
        change_token: Some(salt.change_token.clone()),
    });

    let response = ws::send_request(
        &mut framed,
        2,
        USERS_DOMAIN_ID,
        USER_ACTION_ADD,
        add_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_ADD_OK);

    let salt_payload = ws::encode_payload(&UserPasswordSaltRequest {
        email: user_email.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        3,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT,
        salt_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_SALT_OK);

    let salt: PasswordSaltResponse = ws::decode_payload(&response.payload);
    let wrong_hash = derive_front_end_hash(
        "wrong-pass",
        &salt.current_front_end_salt,
        &params.front_end,
    )
    .expect("wrong_hash");
    let new_hash = derive_front_end_hash("new-pass", &salt.next_front_end_salt, &params.front_end)
        .expect("new_hash");

    let update_payload = ws::encode_payload(&UserPasswordUpdateRequest {
        email: user_email.to_string(),
        current_front_end_hash: wrong_hash,
        new_front_end_hash: new_hash,
        new_front_end_salt: salt.next_front_end_salt,
        change_token: salt.change_token,
    });
    let response = ws::send_request(
        &mut framed,
        4,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_UPDATE,
        update_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_UPDATE_ERR);

    let message: MessageResponse = ws::decode_payload(&response.payload);
    assert!(!message.message.is_empty());
}

#[actix_web::test]
async fn role_remove_removes_role() {
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

    let user_email = "roles@example.com";
    let salt_payload = ws::encode_payload(&UserPasswordSaltRequest {
        email: user_email.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        1,
        USERS_DOMAIN_ID,
        USER_ACTION_PASSWORD_SALT,
        salt_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_PASSWORD_SALT_OK);

    let salt: PasswordSaltResponse = ws::decode_payload(&response.payload);
    let params = PasswordHashingParams::default();
    let front_end_hash =
        derive_front_end_hash("initial-pass", &salt.next_front_end_salt, &params.front_end)
            .expect("front_end_hash");

    let add_payload = ws::encode_payload(&UserAddRequest {
        email: user_email.to_string(),
        name: "Role User".to_string(),
        password: PasswordPayload::FrontEndHash {
            front_end_hash,
            front_end_salt: salt.next_front_end_salt,
        },
        roles: vec!["editor".to_string(), "writer".to_string()],
        change_token: Some(salt.change_token),
    });

    let response = ws::send_request(
        &mut framed,
        2,
        USERS_DOMAIN_ID,
        USER_ACTION_ADD,
        add_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_ADD_OK);

    let role_payload = ws::encode_payload(&UserRoleRemoveRequest {
        email: user_email.to_string(),
        role: "writer".to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        3,
        USERS_DOMAIN_ID,
        USER_ACTION_ROLE_REMOVE,
        role_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_ROLE_REMOVE_OK);

    let show_payload = ws::encode_payload(&UserShowRequest {
        email: user_email.to_string(),
    });
    let response = ws::send_request(
        &mut framed,
        4,
        USERS_DOMAIN_ID,
        USER_ACTION_SHOW,
        show_payload,
    )
    .await;
    assert_eq!(response.action_id, USER_ACTION_SHOW_OK);

    let show: UserShowResponse = ws::decode_payload(&response.payload);
    assert!(show.roles.contains(&"editor".to_string()));
    assert!(!show.roles.contains(&"writer".to_string()));
}
