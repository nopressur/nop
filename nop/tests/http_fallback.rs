// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, http::header::ACCEPT, test};

#[actix_web::test]
async fn unknown_api_route_returns_json_not_found() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::post()
        .uri("/api/missing")
        .insert_header((ACCEPT, "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let content_type = resp
        .headers()
        .get(actix_web::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("application/json"));

    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
}
