// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::runtime_paths::RuntimePaths;
use crate::security;
use log::{debug, error, warn};
use std::time::SystemTime;
use tokio::fs;

pub(super) async fn load_theme_content(
    runtime_paths: &RuntimePaths,
    theme: Option<&str>,
) -> String {
    let now = SystemTime::now();
    log::debug!("Loading theme content at {:?}", now);

    // Determine which theme to load
    let theme_name_str = if let Some(theme_name_opt) = theme {
        if theme_name_opt.is_empty() {
            log::warn!("Empty theme name specified, using default theme");
            "default"
        } else {
            theme_name_opt
        }
    } else {
        "default"
    };

    let themes_dir_str = runtime_paths.themes_dir.to_string_lossy();

    // Attempt to load the requested theme
    let mut theme_path = runtime_paths.themes_dir.clone();
    theme_path.push(format!("{}.html", theme_name_str));

    match security::canonical_path_checks(&theme_path, &themes_dir_str, None) {
        Ok(canonical_theme_path) => {
            match fs::read_to_string(&canonical_theme_path).await {
                Ok(content) => {
                    debug!(
                        "Successfully loaded theme '{}': {} ({} bytes) at {:?}",
                        theme_name_str,
                        canonical_theme_path.display(),
                        content.len(),
                        now
                    );
                    return content;
                }
                Err(e) => {
                    if theme_name_str != "default" {
                        warn!(
                            "Could not load theme '{}' from {}: {}, falling back to default theme",
                            theme_name_str,
                            canonical_theme_path.display(),
                            e
                        );
                        // Fall through to default theme loading
                    } else {
                        error!(
                            "Could not load default theme '{}' from {}: {}, using fallback theme",
                            theme_name_str,
                            canonical_theme_path.display(),
                            e
                        );
                        return get_fallback_theme();
                    }
                }
            }
        }
        Err(_) => {
            // canonical_path_checks failed
            if theme_name_str != "default" {
                warn!(
                    "Invalid path for theme '{}' ({}), falling back to default theme",
                    theme_name_str,
                    theme_path.display()
                );
                // Fall through to default theme loading
            } else {
                error!(
                    "Invalid path for default theme '{}' ({}), using fallback theme",
                    theme_name_str,
                    theme_path.display()
                );
                return get_fallback_theme();
            }
        }
    }

    // Fallback to default theme if initial load failed (and it wasn't default already)
    // or if canonical_path_checks failed for the requested theme
    debug!("Attempting to load default theme as fallback.");
    let mut default_theme_path = runtime_paths.themes_dir.clone();
    default_theme_path.push("default.html");

    match security::canonical_path_checks(&default_theme_path, &themes_dir_str, None) {
        Ok(canonical_default_path) => match fs::read_to_string(&canonical_default_path).await {
            Ok(content) => {
                debug!(
                    "Successfully loaded default theme: {} ({} bytes) at {:?}",
                    canonical_default_path.display(),
                    content.len(),
                    now
                );
                content
            }
            Err(e) => {
                error!(
                    "Could not load default theme from {}: {}, using fallback theme",
                    canonical_default_path.display(),
                    e
                );
                get_fallback_theme()
            }
        },
        Err(_) => {
            // canonical_path_checks failed for default theme
            error!(
                "Invalid path for default theme file ({}), using fallback theme",
                default_theme_path.display()
            );
            get_fallback_theme()
        }
    }
}

fn get_fallback_theme() -> String {
    // Minimal fallback theme in case the theme file cannot be loaded
    "    <style>\
        body {\
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;\
            background-color: #f5f7fa;\
            color: #363636;\
        }\
        .main-container {\
            min-height: 100vh;\
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);\
        }\
        .content-wrapper {\
            padding: 2rem 0;\
        }\
        .content {\
            color: #363636;\
            padding: 2rem;\
            margin: 1rem 0;\
        }\
        .navbar {\
            background: transparent !important;\
        }\
        .navbar-brand .navbar-item {\
            color: #363636 !important;\
        }\
    </style>"
        .to_string()
}
