// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::web;

pub mod cache;
mod context;
pub mod error;
pub mod handlers;
pub mod markdown;
pub mod nav;
pub mod page_meta_cache;
pub mod seo;
pub mod shortcode;

pub use context::{PageRenderContext, PublicRequestContext};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/robots.txt", web::get().to(seo::robots_txt))
        .route("/sitemap.xml", web::get().to(seo::sitemap_xml))
        .route("/", web::get().to(handlers::index))
        .route("/{path:.*}", web::get().to(handlers::handle_route));
}
