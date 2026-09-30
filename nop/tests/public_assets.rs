// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod common;

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::{Error, http::StatusCode, test};
use nop_content_store::flat_storage::{
    ContentId, ContentSidecar, ContentVersion, blob_path, sidecar_path, write_sidecar_atomic,
};
use nop_management_contract::ManagementCommand;
use nop_management_contract::ResponsePayload;
use nop_management_contract::content::{
    CONTENT_ACTION_READ_OK, CONTENT_ACTION_UPDATE_OK, CONTENT_ACTION_UPLOAD_OK, ContentCommand,
    ContentReadRequest, ContentUpdateRequest, ContentUploadRequest,
};
use nop_rt_paths::RuntimePaths;
use std::fs;

fn write_asset_object(
    runtime_paths: &RuntimePaths,
    content_id: ContentId,
    alias: &str,
    title: Option<&str>,
    mime: &str,
    tags: Vec<String>,
    body: &[u8],
) {
    let version = ContentVersion(1);
    let blob = blob_path(&runtime_paths.content_dir, content_id, version);
    if let Some(parent) = blob.parent() {
        fs::create_dir_all(parent).expect("create shard dir");
    }
    fs::write(&blob, body).expect("write blob");
    let sidecar = ContentSidecar {
        alias: alias.to_string(),
        title: title.map(|value| value.to_string()),
        mime: mime.to_string(),
        tags,
        nav_title: None,
        nav_parent_id: None,
        nav_order: None,
        disable_navbar: false,
        disable_floating_nav: false,
        content_width: Default::default(),
        original_filename: Some(alias.to_string()),
        theme: None,
    };
    let sidecar_path = sidecar_path(&runtime_paths.content_dir, content_id, version);
    write_sidecar_atomic(&sidecar_path, &sidecar).expect("write sidecar");
}

async fn builtin_favicon_body<S, B>(app: &S) -> Vec<u8>
where
    S: Service<actix_http::Request, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody + 'static,
    B::Error: std::fmt::Debug,
{
    let resp = test::call_service(
        app,
        test::TestRequest::get()
            .uri("/builtin/favicon.ico")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    test::read_body(resp).await.to_vec()
}

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

#[actix_web::test]
async fn builtin_favicon_remains_available() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/builtin/favicon.ico")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    assert!(!body.is_empty());
}

#[actix_web::test]
async fn favicon_uses_public_uploaded_image_alias() {
    let harness = common::TestHarness::new().await;
    let favicon = b"public-favicon-bytes";
    write_asset_object(
        &harness.runtime_paths,
        ContentId(0x51),
        "favicon.ico",
        None,
        "image/png",
        Vec::new(),
        favicon,
    );
    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("cache rebuild");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/favicon.ico").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), favicon);
}

#[actix_web::test]
async fn favicon_falls_back_to_builtin_when_alias_is_missing() {
    let harness = common::TestHarness::new().await;
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let builtin = builtin_favicon_body(&app).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/favicon.ico").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), builtin.as_slice());
}

#[actix_web::test]
async fn favicon_falls_back_to_builtin_when_alias_is_not_public() {
    let harness = common::TestHarness::new().await;
    write_asset_object(
        &harness.runtime_paths,
        ContentId(0x52),
        "favicon.ico",
        None,
        "image/png",
        vec!["admin".to_string()],
        b"private-favicon-bytes",
    );
    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("cache rebuild");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let builtin = builtin_favicon_body(&app).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/favicon.ico").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), builtin.as_slice());
}

#[actix_web::test]
async fn favicon_falls_back_to_builtin_when_alias_is_markdown() {
    let harness = common::TestHarness::new().await;
    write_asset_object(
        &harness.runtime_paths,
        ContentId(0x53),
        "favicon.ico",
        Some("Favicon"),
        "text/markdown",
        Vec::new(),
        b"# Not a favicon\n",
    );
    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("cache rebuild");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let builtin = builtin_favicon_body(&app).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/favicon.ico").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), builtin.as_slice());
}

#[actix_web::test]
async fn favicon_falls_back_to_builtin_when_alias_is_not_image() {
    let harness = common::TestHarness::new().await;
    write_asset_object(
        &harness.runtime_paths,
        ContentId(0x54),
        "favicon.ico",
        None,
        "text/plain",
        Vec::new(),
        b"not image",
    );
    harness
        .page_cache
        .rebuild_cache(true)
        .await
        .expect("cache rebuild");
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let builtin = builtin_favicon_body(&app).await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get().uri("/favicon.ico").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), builtin.as_slice());
}

#[actix_web::test]
async fn binary_image_alias_reassignment_updates_live_public_routes_without_restart() {
    let harness = common::TestHarness::new().await;
    let bus = harness.management_tools.management_bus.clone();
    let app = test::init_service(common::build_test_app(harness.app_bundle())).await;
    let image_a = b"image-a-unique-bytes".to_vec();
    let image_b = b"image-b-different-bytes".to_vec();

    let upload_image =
        |workflow_id: u32, alias: &'static str, title: &'static str, body: Vec<u8>| {
            let bus = bus.clone();
            async move {
                let response = bus
                    .send(
                        nop_management_bus::next_connection_id(),
                        workflow_id,
                        ManagementCommand::Content(ContentCommand::Upload(ContentUploadRequest {
                            alias: Some(alias.to_string()),
                            title: Some(title.to_string()),
                            mime: "image/png".to_string(),
                            tags: Vec::new(),
                            nav_title: None,
                            nav_parent_id: None,
                            nav_order: None,
                            original_filename: Some(format!("{}.png", title.to_lowercase())),
                            theme: None,
                            disable_navbar: false,
                            disable_floating_nav: false,
                            content_width: Default::default(),
                            content: body,
                        })),
                    )
                    .await
                    .expect("upload response");
                assert_eq!(response.action_id, CONTENT_ACTION_UPLOAD_OK);
                match response.payload {
                    ResponsePayload::ContentUpload(payload) => payload.id,
                    other => panic!("unexpected upload payload: {:?}", other),
                }
            }
        };

    let id_a = upload_image(10, "images/a", "A", image_a.clone()).await;
    let id_b = upload_image(11, "images/b", "B", image_b.clone()).await;

    let resp =
        test::call_service(&app, test::TestRequest::get().uri("/images/a").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_a.as_slice());

    let resp =
        test::call_service(&app, test::TestRequest::get().uri("/images/b").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_b.as_slice());

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/id/{}", id_a))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_a.as_slice());

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/id/{}", id_b))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_b.as_slice());

    let update_alias = |workflow_id: u32, id: String, alias: &'static str| {
        let bus = bus.clone();
        async move {
            let response = bus
                .send(
                    nop_management_bus::next_connection_id(),
                    workflow_id,
                    ManagementCommand::Content(ContentCommand::Update(ContentUpdateRequest {
                        id,
                        new_alias: Some(alias.to_string()),
                        title: None,
                        tags: None,
                        nav_title: None,
                        nav_parent_id: None,
                        nav_order: None,
                        theme: None,
                        disable_navbar: None,
                        disable_floating_nav: None,
                        content_width: Default::default(),
                        content: None,
                    })),
                )
                .await
                .expect("update response");
            assert_eq!(response.action_id, CONTENT_ACTION_UPDATE_OK);
        }
    };

    update_alias(12, id_a.clone(), "images/c").await;
    update_alias(13, id_b.clone(), "images/a").await;
    update_alias(14, id_a.clone(), "images/b").await;

    let read_alias = |workflow_id: u32, id: String| {
        let bus = bus.clone();
        async move {
            let response = bus
                .send(
                    nop_management_bus::next_connection_id(),
                    workflow_id,
                    ManagementCommand::Content(ContentCommand::Read(ContentReadRequest {
                        id,
                        stream_content: None,
                    })),
                )
                .await
                .expect("read response");
            assert_eq!(response.action_id, CONTENT_ACTION_READ_OK);
            match response.payload {
                ResponsePayload::ContentRead(payload) => payload.alias,
                other => panic!("unexpected read payload: {:?}", other),
            }
        }
    };

    assert_eq!(read_alias(15, id_a.clone()).await, "images/b");
    assert_eq!(read_alias(16, id_b.clone()).await, "images/a");

    let resp =
        test::call_service(&app, test::TestRequest::get().uri("/images/a").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_b.as_slice());

    let resp =
        test::call_service(&app, test::TestRequest::get().uri("/images/b").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_a.as_slice());

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/id/{}", id_a))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_a.as_slice());

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/id/{}", id_b))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await.as_ref(), image_b.as_slice());
}
