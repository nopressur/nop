// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};
use serde::Serialize;

#[derive(Serialize)]
struct ThemePayload {
    content: String,
}

#[derive(Serialize)]
struct NewThemePayload {
    name: String,
    content: String,
}

#[actix_web::test]
async fn create_save_delete_theme() {
    let harness = common::TestHarness::new().await;
    let session = harness.admin_auth();
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let create_payload = NewThemePayload {
        name: "blue".to_string(),
        content: "<style>.blue{color:#00f;}</style>".to_string(),
    };
    let req = common::add_auth_headers(
        test::TestRequest::post()
            .uri("/admin/themes/create-api")
            .set_json(&create_payload),
        &session,
        true,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let theme_path = harness.runtime_paths.themes_dir.join("blue.html");
    assert!(theme_path.exists(), "theme should be created");

    let save_payload = ThemePayload {
        content: "<style>.blue{color:#009;}</style>".to_string(),
    };
    let req = common::add_auth_headers(
        test::TestRequest::post()
            .uri("/admin/themes/save-api/blue")
            .set_json(&save_payload),
        &session,
        true,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = std::fs::read_to_string(&theme_path).expect("theme contents");
    assert!(updated.contains("#009"));

    let req = common::add_auth_headers(
        test::TestRequest::delete().uri("/admin/themes/delete-api?theme=blue"),
        &session,
        true,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!theme_path.exists(), "theme should be deleted");
}

#[actix_web::test]
async fn delete_default_theme_is_forbidden() {
    let harness = common::TestHarness::new().await;
    let session = harness.admin_auth();
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = common::add_auth_headers(
        test::TestRequest::delete().uri("/admin/themes/delete-api?theme=default"),
        &session,
        true,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
