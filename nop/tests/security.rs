// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};

#[actix_web::test]
async fn traversal_requests_return_404() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/../secret").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = test::TestRequest::get().uri("/%2e%2e/secret").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
