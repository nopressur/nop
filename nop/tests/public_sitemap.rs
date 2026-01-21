// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::{http::StatusCode, test};
use chrono::{DateTime, Utc};
use nop::content::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, content_id_hex, sidecar_path,
    write_sidecar_atomic,
};
use std::fs;

fn write_markdown_object(
    runtime_paths: &nop::runtime_paths::RuntimePaths,
    content_id: ContentId,
    alias: &str,
) {
    let version = ContentVersion(1);
    let blob = blob_path(&runtime_paths.content_dir, content_id, version);
    if let Some(parent) = blob.parent() {
        fs::create_dir_all(parent).expect("create shard dir");
    }
    fs::write(&blob, b"# Test\n").expect("write blob");
    let sidecar = ContentSidecar {
        alias: alias.to_string(),
        title: Some("Test".to_string()),
        mime: "text/markdown".to_string(),
        tags: Vec::new(),
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        original_filename: None,
        theme: None,
    };
    let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, version);
    write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
}

#[actix_web::test]
async fn robots_txt_includes_sitemap_and_hides_admin_path() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get()
        .uri("/robots.txt")
        .insert_header(("Host", "public.example"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let text = String::from_utf8_lossy(&body);

    assert!(text.contains("User-agent: *"));
    assert!(text.contains("Disallow: /login/"));
    assert!(text.contains("Disallow: /api/"));
    assert!(text.contains("Disallow: /builtin/"));
    assert!(text.contains("Sitemap: http://public.example/sitemap.xml"));
    assert!(!text.contains("/admin"));
}

#[actix_web::test]
async fn sitemap_includes_markdown_aliases_and_ids() {
    let harness = common::TestHarness::new().await;

    let aliasless_id = ContentId(0x63);
    let reserved_id = ContentId(0x64);
    write_markdown_object(&harness.runtime_paths, aliasless_id, "");
    write_markdown_object(&harness.runtime_paths, reserved_id, "robots.txt");

    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("cache rebuild");

    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let req = test::TestRequest::get()
        .uri("/sitemap.xml")
        .insert_header(("Host", "public.example"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    let xml = String::from_utf8_lossy(&body);

    assert!(xml.contains("http://public.example/docs/intro"));
    assert!(xml.contains("http://public.example/index"));
    assert!(!xml.contains("http://public.example/secret"));
    assert!(!xml.contains("http://public.example/robots.txt"));

    let id_hex = content_id_hex(aliasless_id);
    let id_loc = format!("http://public.example/id/{}", id_hex);
    assert!(xml.contains(&id_loc));

    let blob = blob_path(
        &harness.runtime_paths.content_dir,
        aliasless_id,
        ContentVersion(1),
    );
    let sidecar = sidecar_path(
        &harness.runtime_paths.content_dir,
        aliasless_id,
        ContentVersion(1),
    );
    let blob_modified = fs::metadata(&blob)
        .expect("blob meta")
        .modified()
        .expect("blob mtime");
    let sidecar_modified = fs::metadata(&sidecar)
        .expect("sidecar meta")
        .modified()
        .expect("sidecar mtime");
    let expected = std::cmp::max(blob_modified, sidecar_modified);
    let expected_date = DateTime::<Utc>::from(expected)
        .format("%Y-%m-%d")
        .to_string();

    assert!(xml.contains(&format!("<lastmod>{}</lastmod>", expected_date)));
}
