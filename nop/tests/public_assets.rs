// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};

#[actix_web::test]
async fn serves_assets_and_supports_range_requests() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get()
        .uri("/assets/sample.bin")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    assert_eq!(body.len(), 32);

    let req = test::TestRequest::get()
        .uri("/assets/sample.bin")
        .insert_header(("Range", "bytes=0-3"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let body = test::read_body(resp).await;
    assert_eq!(&body[..], b"abcd");
}

#[actix_web::test]
async fn serves_assets_by_id() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get()
        .uri("/id/0000000000000004")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    assert_eq!(body.len(), 32);

    let req = test::TestRequest::get()
        .uri("/id/0000000000000005")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    assert_eq!(body.len(), 11);

    let req = test::TestRequest::get()
        .uri("/id/0000000000000006")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    assert_eq!(body.len(), 12);
}
