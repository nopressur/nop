// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Serialize;

use crate::config::ValidatedConfig;
use crate::iam::AuthRequest;

#[derive(Serialize)]
struct ProfileMenuItem {
    key: String,
    label: String,
    href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
}

#[derive(Serialize)]
struct ProfileResponse {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    menu_items: Option<Vec<ProfileMenuItem>>,
}

fn menu_item(key: &str, label: &str, href: &str, method: Option<&str>) -> ProfileMenuItem {
    ProfileMenuItem {
        key: key.to_string(),
        label: label.to_string(),
        href: href.to_string(),
        method: method.map(|value| value.to_string()),
    }
}

pub async fn get_profile(req: HttpRequest, config: web::Data<ValidatedConfig>) -> HttpResponse {
    let Some(user) = req.user_info() else {
        return HttpResponse::Ok().json(ProfileResponse {
            authenticated: false,
            display_name: None,
            menu_items: None,
        });
    };

    let mut menu_items = Vec::new();
    menu_items.push(menu_item("profile", "Profile", "/login/profile", None));

    if user.roles.iter().any(|role| role == "admin") {
        menu_items.push(menu_item("admin", "Admin", &config.admin.path, None));
    }

    menu_items.push(menu_item(
        "logout",
        "Logout",
        "/login/logout-api",
        Some("POST"),
    ));

    HttpResponse::Ok().json(ProfileResponse {
        authenticated: true,
        display_name: Some(user.name.clone()),
        menu_items: Some(menu_items),
    })
}
