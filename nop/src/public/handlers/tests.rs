// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::serve_streaming_file;
use super::test_support::build_test_config;
use crate::app_state::AppState;
use crate::util::test_fixtures::TestFixtureRoot;
use actix_web::{body::to_bytes, http::StatusCode, test::TestRequest};
use std::fs;

#[actix_web::test]
async fn test_streaming_range_response_matches_expected_bytes() {
    let fixture = TestFixtureRoot::new_unique("public-streaming-range").unwrap();
    fixture.init_runtime_layout().unwrap();
    let content_dir = fixture.content_dir();

    let file_path = content_dir.join("video.bin");
    let content: Vec<u8> = (0u8..=255).collect();
    fs::write(&file_path, &content).unwrap();

    let runtime_paths = fixture.runtime_paths().unwrap();
    let config = build_test_config(true);

    let req = TestRequest::default()
        .insert_header(("range", "bytes=5-9"))
        .to_http_request();
    let app_state = AppState::new_for_tests("Test App", runtime_paths, config.clone());
    let response = serve_streaming_file(
        &file_path,
        "video/bin",
        &req,
        &config,
        &app_state.error_renderer,
        app_state.templates.as_ref(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

    let headers = response.headers();
    assert_eq!(
        headers.get("Accept-Ranges").and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    assert_eq!(
        headers.get("Content-Range").and_then(|v| v.to_str().ok()),
        Some("bytes 5-9/256")
    );
    assert_eq!(
        headers.get("Content-Length").and_then(|v| v.to_str().ok()),
        Some("5")
    );
    assert_eq!(
        headers.get("Cache-Control").and_then(|v| v.to_str().ok()),
        Some("public, max-age=31536000, immutable")
    );

    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(body.as_ref(), &content[5..=9]);
}

#[actix_web::test]
async fn test_streaming_unsatisfiable_range_returns_416() {
    let fixture = TestFixtureRoot::new_unique("public-streaming-416").unwrap();
    fixture.init_runtime_layout().unwrap();
    let content_dir = fixture.content_dir();

    let file_path = content_dir.join("video.bin");
    let content: Vec<u8> = (0u8..=9).collect();
    fs::write(&file_path, &content).unwrap();

    let runtime_paths = fixture.runtime_paths().unwrap();
    let config = build_test_config(true);

    let req = TestRequest::default()
        .insert_header(("range", "bytes=30-40"))
        .to_http_request();
    let app_state = AppState::new_for_tests("Test App", runtime_paths, config.clone());
    let response = serve_streaming_file(
        &file_path,
        "video/bin",
        &req,
        &config,
        &app_state.error_renderer,
        app_state.templates.as_ref(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response
            .headers()
            .get("Content-Range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes */10")
    );
}

#[actix_web::test]
async fn test_streaming_without_range_returns_full_body() {
    let fixture = TestFixtureRoot::new_unique("public-streaming-full").unwrap();
    fixture.init_runtime_layout().unwrap();
    let content_dir = fixture.content_dir();

    let file_path = content_dir.join("asset.bin");
    let content: Vec<u8> = (0u8..=15).collect();
    fs::write(&file_path, &content).unwrap();

    let runtime_paths = fixture.runtime_paths().unwrap();
    let config = build_test_config(true);

    let req = TestRequest::default().to_http_request();
    let app_state = AppState::new_for_tests("Test App", runtime_paths, config.clone());
    let response = serve_streaming_file(
        &file_path,
        "application/octet-stream",
        &req,
        &config,
        &app_state.error_renderer,
        app_state.templates.as_ref(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Accept-Ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    assert_eq!(
        response
            .headers()
            .get("Content-Length")
            .and_then(|v| v.to_str().ok()),
        Some("16")
    );

    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(body.as_ref(), &content);
}
