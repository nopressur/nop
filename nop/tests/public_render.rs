// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};
use nop_content_store::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, ContentWidthMode, blob_path, sidecar_path,
    write_sidecar_atomic,
};
use nop_rt_paths::RuntimePaths;
use std::fs;

fn write_markdown_object(
    runtime_paths: &RuntimePaths,
    content_id: ContentId,
    alias: &str,
    title: &str,
    body: &[u8],
    disable_navbar: bool,
) {
    write_markdown_object_with_width(
        runtime_paths,
        content_id,
        alias,
        title,
        body,
        disable_navbar,
        ContentWidthMode::Auto,
    )
}

fn write_markdown_object_with_width(
    runtime_paths: &RuntimePaths,
    content_id: ContentId,
    alias: &str,
    title: &str,
    body: &[u8],
    disable_navbar: bool,
    content_width: ContentWidthMode,
) {
    let version = ContentVersion(1);
    let blob = blob_path(&runtime_paths.content_dir, content_id, version);
    if let Some(parent) = blob.parent() {
        fs::create_dir_all(parent).expect("create shard dir");
    }
    fs::write(&blob, body).expect("write blob");
    let sidecar = ContentSidecar {
        alias: alias.to_string(),
        title: Some(title.to_string()),
        mime: "text/markdown".to_string(),
        tags: Vec::new(),
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        disable_navbar,
        disable_floating_nav: false,
        content_width,
        original_filename: Some(format!("{}.md", alias.replace('/', "-"))),
        theme: None,
    };
    let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, version);
    write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
}

#[actix_web::test]
async fn renders_public_pages() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"<h1 id="home">Home</h1>"#));
    assert!(html.contains(r#"<link rel="icon" href="/favicon.ico">"#));
    assert!(!html.contains("/builtin/favicon.ico"));

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"<h1 id="intro">Intro</h1>"#));
    assert!(html.contains("data-site-navbar"));
    assert!(html.contains(r#"data-site-page-footer"#));
    assert!(html.contains(r#"data-site-asset-reload"#));
    assert!(!html.contains("data-site-admin-version"));
    assert!(!html.contains("{#"));
    assert!(!html.contains("SPDX-FileCopyrightText"));

    let req = test::TestRequest::get()
        .uri("/id/0000000000000002")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"<h1 id="intro">Intro</h1>"#));
}

#[actix_web::test]
async fn renders_version_footer_only_for_admin_users() {
    let harness = common::TestHarness::new().await;
    let admin_session = harness.admin_auth();
    let user_session = harness
        .user_auth_with_roles(
            "editor@example.com",
            "Editor User",
            vec!["editor".to_string()],
        )
        .await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"data-site-page-footer"#));
    assert!(html.contains(r#"data-site-asset-reload"#));
    assert!(html.contains(">reload</a>"));
    assert!(!html.contains("data-site-admin-version"));
    assert!(!html.contains("Release 1"));

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/docs/intro"),
        &user_session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"data-site-page-footer"#));
    assert!(html.contains(r#"data-site-asset-reload"#));
    assert!(!html.contains("data-site-admin-version"));
    assert!(!html.contains("Release 1"));

    let req = common::add_auth_headers(
        test::TestRequest::get().uri("/docs/intro"),
        &admin_session,
        false,
    )
    .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"<footer class="site-page-footer" data-site-page-footer>"#));
    assert!(html.contains(r#"data-site-admin-version"#));
    assert!(html.contains("NoPressure Release 1"));
    assert!(html.contains(r#"data-site-asset-reload"#));
    assert!(html.contains(">reload</a>"));
}

#[actix_web::test]
async fn appends_configured_website_title_to_public_page_title() {
    let harness = common::TestHarness::new().await;
    harness
        .runtime_settings
        .set_website_title(Some("Example Site"))
        .expect("set website title");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<title>Intro | Example Site</title>"));
}

#[actix_web::test]
async fn escapes_website_title_in_public_page_title() {
    let harness = common::TestHarness::new().await;
    harness
        .runtime_settings
        .set_website_title(Some("<Example & Site>"))
        .expect("set website title");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<title>Intro | &lt;Example &amp; Site&gt;</title>"));
}

#[actix_web::test]
async fn renders_runtime_website_name_in_public_navbar() {
    let harness = common::TestHarness::new().await;
    harness
        .runtime_settings
        .set_name("Example Name")
        .expect("set website name");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("<strong>Example Name</strong>"));
}

#[actix_web::test]
async fn renders_public_meta_description_when_configured() {
    let harness = common::TestHarness::new().await;
    harness
        .runtime_settings
        .set_description(Some("Example & \"Site\""))
        .expect("set description");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"<meta name="description" content="Example &amp; &quot;Site&quot;">"#));
}

#[actix_web::test]
async fn omits_public_meta_description_when_unset() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/docs/intro").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(!html.contains(r#"<meta name="description""#));
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
    assert!(html.contains(r#"<h1 id="secret">Secret</h1>"#));

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
    assert!(html.contains(r#"<h1 id="secret">Secret</h1>"#));
}

#[actix_web::test]
async fn page_with_disable_navbar_omits_public_navbar() {
    let harness = common::TestHarness::new().await;
    write_markdown_object(
        &harness.runtime_paths,
        ContentId(7),
        "no-navbar",
        "No Navbar",
        b"# No Navbar\n\nThis page has no public navbar.\n",
        true,
    );
    harness
        .page_cache
        .invalidate()
        .await
        .expect("cache invalidated");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/no-navbar").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"<h1 id="no-navbar">No Navbar</h1>"#));
    assert!(!html.contains("data-site-navbar"));
}

#[actix_web::test]
async fn leading_hero_image_does_not_emit_empty_initial_content_container() {
    let harness = common::TestHarness::new().await;
    write_markdown_object(
        &harness.runtime_paths,
        ContentId(8),
        "hero-first",
        "Hero First",
        br#"((hero-img src="assets/sample.png" title="Hero"))

# After Hero
"#,
        false,
    );
    harness
        .page_cache
        .invalidate()
        .await
        .expect("cache invalidated");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get().uri("/hero-first").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("sc-hero-img"));
    assert!(html.contains(r#"<h1 id="after-hero">After Hero</h1>"#));

    let band_index = html.find("site-doc-band").expect("escape band");
    let hero_index = html.find("sc-hero-img").expect("hero image");
    let wrapper_index = html
        .find(r#"<div class="content-wrapper"#)
        .expect("content wrapper");
    let content_container_index = html
        .find("container content-container")
        .expect("content container");
    assert!(band_index < hero_index);
    assert!(hero_index < wrapper_index);
    assert!(wrapper_index < content_container_index);
}

#[actix_web::test]
async fn hero_reopened_container_preserves_compact_width() {
    let harness = common::TestHarness::new().await;
    write_markdown_object(
        &harness.runtime_paths,
        ContentId(9),
        "hero-compact-width",
        "Hero Compact Width",
        br#"Short intro.

((hero-img src="assets/sample.png" title="Hero"))

Short outro.
"#,
        false,
    );
    harness
        .page_cache
        .invalidate()
        .await
        .expect("cache invalidated");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get()
        .uri("/hero-compact-width")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);

    assert!(html.contains(r#"data-compact="true""#));
    assert!(html.contains("sc-hero-img"));
    assert!(html.contains(r#"style="max-width: min(var(--size-content-measure, 75ch), 100%);""#));
    assert!(!html.contains(r#"style="max-width: 1152px;""#));
}

#[actix_web::test]
async fn hero_reopened_container_preserves_wide_width() {
    let harness = common::TestHarness::new().await;
    let long_paragraph = "w".repeat(300);
    let body = format!(
        "Short intro.\n\n((hero-img src=\"assets/sample.png\" title=\"Hero\"))\n\n{}\n",
        long_paragraph
    );
    write_markdown_object_with_width(
        &harness.runtime_paths,
        ContentId(10),
        "hero-wide-width",
        "Hero Wide Width",
        body.as_bytes(),
        false,
        ContentWidthMode::Wide,
    );
    harness
        .page_cache
        .invalidate()
        .await
        .expect("cache invalidated");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get()
        .uri("/hero-wide-width")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let html = String::from_utf8_lossy(&body);

    assert!(html.contains(r#"data-compact="false""#));
    assert!(html.contains("sc-hero-img"));
    assert!(html.contains(r#"style="max-width: 1152px;""#));
    assert!(!html.contains(r#"style="max-width: min(var(--size-content-measure, 75ch), 100%);""#));
}
