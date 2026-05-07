// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test, web};
use nop_content_store::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
};
use serde_json::Value;
use std::fs;

#[actix_web::test]
async fn search_api_anonymous_returns_public_matches_only() {
    let harness = common::TestHarness::new().await;
    let search_startup = nop_rt_search_service::initialize(
        &harness.runtime_paths,
        &harness.config.search,
        nop_content_store::reserved_paths::ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/search?q=page")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("search json");
    let items = json.as_array().expect("array response");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("id").and_then(Value::as_str),
        Some("0000000000000002")
    );
    assert_eq!(
        items[0].get("alias").and_then(Value::as_str),
        Some("docs/intro")
    );
    assert_eq!(items[0].get("title").and_then(Value::as_str), Some("Intro"));
    assert!(items[0].get("tags").is_none());
    assert!(items[0].get("url").is_none());
}

#[actix_web::test]
async fn search_api_admin_can_view_restricted_hits() {
    let harness = common::TestHarness::new().await;
    let search_startup = nop_rt_search_service::initialize(
        &harness.runtime_paths,
        &harness.config.search,
        nop_content_store::reserved_paths::ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;
    let session = harness.admin_auth();

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/api/search?q=secret"),
        &session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("search json");
    let items = json.as_array().expect("array response");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("id").and_then(Value::as_str),
        Some("0000000000000003")
    );
    assert_eq!(
        items[0].get("alias").and_then(Value::as_str),
        Some("secret")
    );
    assert_eq!(
        items[0].get("title").and_then(Value::as_str),
        Some("Secret")
    );
}

#[actix_web::test]
async fn search_api_public_profile_does_not_match_tags() {
    let harness = common::TestHarness::new().await;
    let search_startup = nop_rt_search_service::initialize(
        &harness.runtime_paths,
        &harness.config.search,
        nop_content_store::reserved_paths::ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;
    let session = harness.admin_auth();

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/api/search?q=admin"),
        &session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("search json");
    let items = json.as_array().expect("array response");
    assert!(items.is_empty());
}

#[actix_web::test]
async fn search_api_sorts_results_by_title_after_filtering() {
    let harness = common::TestHarness::new().await;
    let search_startup = nop_rt_search_service::initialize(
        &harness.runtime_paths,
        &harness.config.search,
        nop_content_store::reserved_paths::ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;
    let session = harness.admin_auth();

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/api/search?q=page"),
        &session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("search json");
    let items = json.as_array().expect("array response");
    assert_eq!(items.len(), 2);
    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(Value::as_str))
        .collect();
    assert_eq!(titles, vec!["Intro", "Secret"]);
}

#[actix_web::test]
async fn search_api_rejects_invalid_query_lengths() {
    let harness = common::TestHarness::new().await;
    let search_startup = nop_rt_search_service::initialize(
        &harness.runtime_paths,
        &harness.config.search,
        nop_content_store::reserved_paths::ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;

    let too_long = format!("/api/search?q={}", "x".repeat(257));
    for uri in [
        "/api/search",
        "/api/search?q=%20%20%20",
        "/api/search?q=ab",
        too_long.as_str(),
    ] {
        let req = test::TestRequest::get().uri(uri).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = test::read_body(resp).await;
        let json: Value = serde_json::from_slice(&body).expect("search json");
        assert_eq!(
            json.get("message").and_then(Value::as_str),
            Some("Search query must be between 3 and 256 characters.")
        );
    }
}

#[actix_web::test]
async fn search_api_denied_role_sets_are_admin_only() {
    let harness = common::TestHarness::new().await;
    let tags_yaml = r#"admin:
  name: admin
  roles:
    - admin
alpha:
  name: alpha
  roles:
    - alpha
  access_rule: intersect
beta:
  name: beta
  roles:
    - beta
  access_rule: intersect
"#;
    fs::write(
        harness.runtime_paths.state_sys_dir.join("tags.yaml"),
        tags_yaml,
    )
    .expect("tags");
    fs::write(
        harness.runtime_paths.state_sys_dir.join("roles.yaml"),
        "- admin\n- alpha\n- beta\n",
    )
    .expect("roles");

    write_markdown(
        &harness.runtime_paths,
        ContentId(2000),
        "deny-case",
        Some("Deny Case"),
        vec!["alpha".to_string(), "beta".to_string()],
        "deny token",
    );
    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("cache rebuild");

    let search_startup = nop_rt_search_service::initialize(
        &harness.runtime_paths,
        &harness.config.search,
        nop_content_store::reserved_paths::ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/search?q=deny")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("search json");
    let items = json.as_array().expect("array response");
    assert!(items.is_empty());

    let session = harness.admin_auth();
    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/api/search?q=deny"),
        &session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("search json");
    let items = json.as_array().expect("array response");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("alias").and_then(Value::as_str),
        Some("deny-case")
    );
}

#[actix_web::test]
async fn search_api_returns_public_hits_beyond_restricted_top_n() {
    let harness = common::TestHarness::new().await;

    for idx in 0u64..20u64 {
        write_markdown(
            &harness.runtime_paths,
            ContentId(3000 + idx),
            &format!("restricted-{:02}", idx),
            Some(&format!("Restricted {:02}", idx)),
            vec!["admin".to_string()],
            "overflow token",
        );
    }
    write_markdown(
        &harness.runtime_paths,
        ContentId(4000),
        "public-overflow",
        Some("Public Overflow"),
        Vec::new(),
        "overflow token",
    );
    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("cache rebuild");

    let search_startup = nop_rt_search_service::initialize(
        &harness.runtime_paths,
        &harness.config.search,
        nop_content_store::reserved_paths::ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/api/search?q=overflow")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("search json");
    let items = json.as_array().expect("array response");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("alias").and_then(Value::as_str),
        Some("public-overflow")
    );
}

fn write_markdown(
    runtime_paths: &nop_rt_paths::RuntimePaths,
    id: ContentId,
    alias: &str,
    title: Option<&str>,
    tags: Vec<String>,
    body: &str,
) {
    let version = ContentVersion(1);
    let blob = blob_path(&runtime_paths.content_dir, id, version);
    if let Some(parent) = blob.parent() {
        fs::create_dir_all(parent).expect("create shard");
    }
    fs::write(&blob, body).expect("write body");
    let sidecar = ContentSidecar {
        alias: alias.to_string(),
        title: title.map(|value| value.to_string()),
        mime: "text/markdown".to_string(),
        tags,
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
    };
    let sidecar_path = sidecar_path(&runtime_paths.content_dir, id, version);
    write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
}
