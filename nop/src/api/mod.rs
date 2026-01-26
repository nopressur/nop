// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::web;

mod profile;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api").route("/profile", web::get().to(profile::get_profile)));
}
