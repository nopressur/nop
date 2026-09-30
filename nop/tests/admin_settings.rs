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
use nop_management_contract::settings::{
    SETTINGS_ACTION_GET, SETTINGS_ACTION_GET_OK, SETTINGS_ACTION_SET_TITLE,
    SETTINGS_ACTION_SET_TITLE_OK, SETTINGS_DOMAIN_ID, SettingsGetRequest, SettingsResponse,
    SettingsSetTitleRequest,
};
use std::fs;

#[actix_web::test]
async fn get_and_update_settings_over_admin_websocket() {
    let harness = common::TestHarness::new().await;
    fs::write(
        harness.fixture.path().join("config.yaml"),
        valid_config_yaml(),
    )
    .expect("write config");
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

    let get_payload = ws::encode_payload(&SettingsGetRequest {});
    let response = ws::send_request(
        &mut framed,
        1,
        SETTINGS_DOMAIN_ID,
        SETTINGS_ACTION_GET,
        get_payload,
    )
    .await;
    assert_eq!(response.domain_id, SETTINGS_DOMAIN_ID);
    assert_eq!(response.action_id, SETTINGS_ACTION_GET_OK);
    let settings: SettingsResponse = ws::decode_payload(&response.payload);
    assert_eq!(settings.name, "NoPressure");
    assert_eq!(settings.title, None);
    assert_eq!(settings.description, None);

    let set_payload = ws::encode_payload(&SettingsSetTitleRequest {
        title: Some("Example Site".to_string()),
    });
    let response = ws::send_request(
        &mut framed,
        2,
        SETTINGS_DOMAIN_ID,
        SETTINGS_ACTION_SET_TITLE,
        set_payload,
    )
    .await;
    assert_eq!(response.action_id, SETTINGS_ACTION_SET_TITLE_OK);
    let settings: SettingsResponse = ws::decode_payload(&response.payload);
    assert_eq!(settings.title.as_deref(), Some("Example Site"));
    assert_eq!(
        harness.runtime_settings.website_title().as_deref(),
        Some("Example Site")
    );
}

fn valid_config_yaml() -> &'static str {
    r#"server:
  host: "127.0.0.1"
  port: 8080
admin:
  path: "/admin"
users:
  auth_method: local
  local:
    jwt:
      secret: "test-secret"
      issuer: "nopressure"
      audience: "nopressure-users"
      expiration_hours: 12
      cookie_name: "nop_auth"
      force_secure_cookie: false
      disable_refresh: false
      refresh_threshold_percentage: 10
      refresh_threshold_hours: 24
    password:
      memory_cost: 65536
      time_cost: 3
      parallelism: 4
      output_length: 32
      salt_length: 32
    password_complexity_disabled: false
navigation:
  max_dropdown_items: 7
logging:
  level: info
  rotation:
    max_size_mb: 10
    max_files: 5
security:
  max_violations: 10
  cooldown_seconds: 60
  use_forwarded_for: false
  login_sessions:
    timeout_minutes: 480
    absolute_timeout_hours: 24
  hsts_enabled: false
  hsts_max_age: 31536000
  hsts_include_subdomains: true
  hsts_preload: false
app:
  name: "Test App"
  description: "Test Description"
upload:
  max_file_size_mb: 100
  allowed_extensions: ["md"]
streaming:
  enabled: false
shortcodes:
  builtin:
    enabled: true
rendering:
  short_paragraph_length: 120
search:
  enabled: false
settings:
  name: "NoPressure"
  title: null
  description: null
"#
}
