// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};

#[actix_web::test]
async fn unknown_admin_path_serves_spa_shell_for_admins() {
    let harness = common::TestHarness::new().await;
    let session = harness.admin_auth();
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/admin/pages/index.md"),
        &session,
        false,
    )
    .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).expect("admin shell utf8");
    assert!(body_str.contains("id=\"admin-app\""));
}
