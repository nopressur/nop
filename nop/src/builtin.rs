// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::{HttpRequest, HttpResponse, Result, web};

#[cfg(debug_assertions)]
use actix_files::NamedFile;
#[cfg(debug_assertions)]
use std::path::PathBuf;

#[cfg(not(debug_assertions))]
use flate2::read::GzDecoder;
#[cfg(not(debug_assertions))]
use std::io::Read;

// Include the generated builtin files (only contains data in release mode)
include!(concat!(env!("OUT_DIR"), "/builtin_files.rs"));

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/favicon.ico", web::get().to(serve_favicon));
    cfg.route("/builtin/{filename:.*}", web::get().to(serve_builtin_file));
}

#[allow(unused_variables)]
async fn serve_favicon(req: HttpRequest) -> Result<HttpResponse> {
    #[cfg(debug_assertions)]
    {
        // Development mode: serve from filesystem
        serve_from_filesystem("favicon.ico", &req).await
    }

    #[cfg(not(debug_assertions))]
    {
        // Release mode: serve from embedded compressed data
        serve_from_embedded("favicon.ico").await
    }
}

async fn serve_builtin_file(req: HttpRequest) -> Result<HttpResponse> {
    let filename: String = match req.match_info().get("filename") {
        Some(f) => f.to_string(),
        None => {
            log::error!("Missing 'filename' parameter in builtin file handler");
            return Ok(HttpResponse::InternalServerError().body("Internal Server Error"));
        }
    };

    #[cfg(debug_assertions)]
    {
        // Development mode: serve from filesystem
        serve_from_filesystem(&filename, &req).await
    }

    #[cfg(not(debug_assertions))]
    {
        // Release mode: serve from embedded compressed data
        serve_from_embedded(&filename).await
    }
}

#[cfg(debug_assertions)]
async fn serve_from_filesystem(filename: &str, req: &HttpRequest) -> Result<HttpResponse> {
    let mut tried = Vec::new();
    let mut candidates = Vec::new();

    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("builtin"));
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("builtin"));
        candidates.push(cwd.join("nop").join("builtin"));
    }

    for root in candidates {
        let candidate = root.join(filename);
        tried.push(candidate.clone());
        if candidate.is_file() {
            return match NamedFile::open(&candidate) {
                Ok(file) => {
                    let response = file.into_response(req);
                    Ok(response)
                }
                Err(err) => {
                    log::warn!(
                        "Failed to open builtin asset {}: {}",
                        candidate.display(),
                        err
                    );
                    Ok(HttpResponse::NotFound().finish())
                }
            };
        }
    }

    log::warn!("Builtin asset missing: {} (tried: {:?})", filename, tried);

    Ok(HttpResponse::NotFound().finish())
}

#[cfg(not(debug_assertions))]
async fn serve_from_embedded(filename: &str) -> Result<HttpResponse> {
    if let Some((compressed_data, mime_type)) = BUILTIN_FILES.get(filename) {
        // Decompress the data
        let mut decoder = GzDecoder::new(&compressed_data[..]);
        let mut decompressed = Vec::new();

        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => Ok(HttpResponse::Ok()
                .content_type(*mime_type)
                .append_header(("Content-Encoding", "identity"))
                .body(decompressed)),
            Err(_) => Ok(HttpResponse::InternalServerError().finish()),
        }
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
