// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::test as actix_test;
use actix_web::{http::StatusCode, web};
use nop_config::SearchConfig;
use nop_content_store::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
};
use nop_content_store::reserved_paths::ReservedPaths;
use nop_iam_passwords::build_password_provider_block;
use nop_rt_paths::RuntimePaths;
use nop_rt_search_service::{ReindexReason, initialize};
use nop_testing::test_fixtures::TestFixtureRoot;
use serde_json::Value;

mod common;

fn write_markdown(
    runtime_paths: &RuntimePaths,
    id: ContentId,
    version: ContentVersion,
    alias: &str,
    title: &str,
    body: &str,
) {
    let blob = blob_path(&runtime_paths.content_dir, id, version);
    if let Some(parent) = blob.parent() {
        std::fs::create_dir_all(parent).expect("create shard");
    }
    std::fs::write(&blob, body).expect("write markdown body");
    let sidecar = ContentSidecar {
        alias: alias.to_string(),
        title: Some(title.to_string()),
        mime: "text/markdown".to_string(),
        tags: vec![],
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
    };
    let sidecar_file = sidecar_path(&runtime_paths.content_dir, id, version);
    write_sidecar_atomic(&sidecar_file, &sidecar).expect("write sidecar");
}

fn index_doc_count(index_dir: &std::path::Path) -> usize {
    let index = tantivy::Index::open_in_dir(index_dir).expect("open index");
    let reader = index.reader().expect("reader");
    let searcher = reader.searcher();
    searcher
        .segment_readers()
        .iter()
        .map(|segment| segment.num_docs() as usize)
        .sum()
}

async fn roleless_auth(harness: &common::TestHarness) -> common::AuthSession {
    let email = "roleless@example.com";
    let password = "roleless-pass";
    let password_params = harness
        .config
        .users
        .local()
        .expect("local auth config")
        .password
        .clone();
    let password_block =
        build_password_provider_block(password, &password_params).expect("password block");
    harness
        .user_services
        .add_user(email, "Roleless User", password_block, Vec::new())
        .await
        .expect("add user");

    let user = harness
        .user_services
        .get_user(email)
        .expect("get user")
        .expect("user");
    let jwt_service = harness.user_services.jwt_service().expect("jwt service");
    let token = jwt_service
        .create_token(&user.email, &user)
        .expect("jwt token");
    let claims = jwt_service.verify_token(&token).expect("jwt claims");
    let cookie = jwt_service.create_auth_cookie(&token).into_owned();
    let csrf_token = harness.csrf_store.get_or_refresh_token(&claims.jti);

    common::AuthSession {
        user,
        jwt_token: token,
        jwt_id: claims.jti,
        cookie,
        csrf_token,
    }
}

#[test]
fn missing_index_startup_rebuilds_from_seeded_markdown_files() {
    let fixture = TestFixtureRoot::new_unique("search-it-missing-index").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");

    write_markdown(
        &runtime_paths,
        ContentId(1),
        ContentVersion(1),
        "docs/intro",
        "Intro",
        "hello world",
    );
    write_markdown(
        &runtime_paths,
        ContentId(2),
        ContentVersion(1),
        "docs/guide",
        "Guide",
        "full text",
    );

    let startup = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("search startup");

    assert_eq!(
        startup.startup_reindex_reason,
        Some(ReindexReason::MissingIndex)
    );
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 2);
}

#[test]
fn existing_index_startup_skips_forced_rebuild_when_not_requested() {
    let fixture = TestFixtureRoot::new_unique("search-it-existing-index").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");
    write_markdown(
        &runtime_paths,
        ContentId(1),
        ContentVersion(1),
        "docs/intro",
        "Intro",
        "hello world",
    );

    let first = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("first startup");
    assert_eq!(
        first.startup_reindex_reason,
        Some(ReindexReason::MissingIndex)
    );
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 1);
    drop(first);

    std::thread::sleep(std::time::Duration::from_millis(100));

    let second = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("second startup");
    assert_eq!(second.startup_reindex_reason, None);
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 1);
}

#[test]
fn forced_reindex_rebuilds_from_current_markdown_files() {
    let fixture = TestFixtureRoot::new_unique("search-it-forced-reindex").expect("fixture");
    fixture.init_runtime_layout().expect("layout");
    let runtime_paths = fixture.runtime_paths().expect("paths");
    write_markdown(
        &runtime_paths,
        ContentId(1),
        ContentVersion(1),
        "docs/intro",
        "Intro",
        "hello world",
    );
    write_markdown(
        &runtime_paths,
        ContentId(2),
        ContentVersion(1),
        "docs/second",
        "Second",
        "second body",
    );

    let startup = initialize(
        &runtime_paths,
        &SearchConfig {
            max_memory_mb: 128,
            worker_count: 1,
        },
        ReservedPaths::default(),
        false,
    )
    .expect("startup");
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 2);

    let second_blob = blob_path(&runtime_paths.content_dir, ContentId(2), ContentVersion(1));
    let second_sidecar = sidecar_path(&runtime_paths.content_dir, ContentId(2), ContentVersion(1));
    std::fs::remove_file(second_blob).expect("remove blob");
    std::fs::remove_file(second_sidecar).expect("remove sidecar");

    startup
        .service
        .reindex_all_markdown(ReindexReason::Forced)
        .expect("forced reindex");
    assert_eq!(index_doc_count(&runtime_paths.state_search_index_dir), 1);
}

#[actix_web::test]
async fn search_reindex_route_requires_authentication() {
    let harness = common::TestHarness::new().await;
    let search_startup = initialize(
        &harness.runtime_paths,
        &harness.config.search,
        ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = actix_test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;

    let req = actix_test::TestRequest::post()
        .uri("/api/internal/search/reindex")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = actix_test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("response json");
    assert_eq!(
        json.get("message").and_then(Value::as_str),
        Some("Authentication required")
    );
}

#[actix_web::test]
async fn search_reindex_route_rejects_non_admin() {
    let harness = common::TestHarness::new().await;
    let search_startup = initialize(
        &harness.runtime_paths,
        &harness.config.search,
        ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = actix_test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;
    let session = roleless_auth(&harness).await;

    let req = common::add_auth_headers(
        actix_test::TestRequest::post().uri("/api/internal/search/reindex"),
        &session,
        true,
    )
    .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = actix_test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("response json");
    assert_eq!(
        json.get("message").and_then(Value::as_str),
        Some("Admin role required")
    );
}

#[actix_web::test]
async fn search_reindex_route_accepts_admin() {
    let harness = common::TestHarness::new().await;
    let search_startup = initialize(
        &harness.runtime_paths,
        &harness.config.search,
        ReservedPaths::from_config(&harness.config),
        false,
    )
    .expect("search startup");
    let app = actix_test::init_service(
        common::build_test_app(harness.app_bundle())
            .app_data(web::Data::from(search_startup.service.clone())),
    )
    .await;
    let session = harness.admin_auth();

    let req = common::add_auth_headers(
        actix_test::TestRequest::post().uri("/api/internal/search/reindex"),
        &session,
        true,
    )
    .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = actix_test::read_body(resp).await;
    let json: Value = serde_json::from_slice(&body).expect("response json");
    assert_eq!(
        json.get("message").and_then(Value::as_str),
        Some("Search reindex completed")
    );
}
