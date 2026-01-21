// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};

#[actix_web::test]
async fn renders_public_pages() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<h1>Home</h1>"));

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<h1>Intro</h1>"));

    let req = test::TestRequest::get()
        .uri("/id/0000000000000002")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<h1>Intro</h1>"));
}

#[actix_web::test]
async fn role_restricted_page_requires_auth() {
    let harness = common::TestHarness::new().await;
    let session = harness.admin_auth();
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/secret").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp
        .headers()
        .get("Location")
        .expect("location header")
        .to_str()
        .expect("location string");
    assert!(location.contains("/login"));

    let req = common::add_auth_headers(test::TestRequest::get().uri("/secret"), &session, false)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<h1>Secret</h1>"));

    let req = test::TestRequest::get()
        .uri("/id/0000000000000003")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/id/0000000000000003"),
        &session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<h1>Secret</h1>"));
}
