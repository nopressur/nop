// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};
use serde_json::Value;

#[actix_web::test]
async fn profile_api_anonymous_returns_minimal_payload() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/api/profile").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("profile json");
    assert_eq!(
        json.get("authenticated").and_then(Value::as_bool),
        Some(false)
    );
    assert!(json.get("display_name").is_none());
    assert!(json.get("menu_items").is_none());
}

#[actix_web::test]
async fn profile_api_admin_includes_admin_menu_item() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let session = harness.admin_auth();

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/api/profile"),
        &session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("profile json");
    assert_eq!(
        json.get("authenticated").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        json.get("display_name").and_then(Value::as_str),
        Some(session.user.name.as_str())
    );

    let items = json
        .get("menu_items")
        .and_then(Value::as_array)
        .expect("menu_items array");
    assert_eq!(items.len(), 3);

    assert_eq!(items[0].get("key").and_then(Value::as_str), Some("profile"));
    assert_eq!(
        items[0].get("label").and_then(Value::as_str),
        Some("Profile")
    );
    assert_eq!(
        items[0].get("href").and_then(Value::as_str),
        Some("/login/profile")
    );

    assert_eq!(items[1].get("key").and_then(Value::as_str), Some("admin"));
    assert_eq!(items[1].get("label").and_then(Value::as_str), Some("Admin"));
    assert_eq!(
        items[1].get("href").and_then(Value::as_str),
        Some(harness.config.admin.path.as_str())
    );

    assert_eq!(items[2].get("key").and_then(Value::as_str), Some("logout"));
    assert_eq!(
        items[2].get("label").and_then(Value::as_str),
        Some("Logout")
    );
    assert_eq!(
        items[2].get("href").and_then(Value::as_str),
        Some("/login/logout-api")
    );
    assert_eq!(items[2].get("method").and_then(Value::as_str), Some("POST"));
}
