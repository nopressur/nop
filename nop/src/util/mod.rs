// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#![allow(unused_imports)]
pub mod color_hsv;
pub mod csrf_helper;
pub mod csrf_middleware;
pub mod csrf_validation;
pub mod daemon;
pub mod log_level_changer;
pub mod log_rotation;
pub mod mime_helper;
pub mod pid_file;
pub mod release_tracker;
pub mod streaming_helper;
pub mod test_config;
pub mod test_fixtures;
#[cfg(test)]
pub mod test_runtime_paths;
pub mod upload_temp;
pub mod ws_ticket;

// Re-export commonly used items for convenience
pub use color_hsv::{hsv_to_rgb, increase_saturation, rgb_to_hsv};
pub use csrf_helper::{CsrfTokenOutcome, CsrfTokenStore, issue_csrf_token};
pub use csrf_middleware::CsrfValidationMiddlewareFactory;
pub use csrf_validation::{
    CSRF_HEADER_NAME, ValidatedCsrfToken, mark_csrf_validated, validate_csrf_token,
};
pub use daemon::daemonize_or_warn;
pub use log_level_changer::init_logger;
pub use mime_helper::detect_mime_type;
pub use release_tracker::ReleaseTracker;
pub use streaming_helper::{
    calculate_range_bounds, format_content_range_header, parse_range_header,
};
pub use test_config::{TestConfigBuilder, test_config};
#[cfg(test)]
pub use test_runtime_paths::short_runtime_paths;
pub use upload_temp::{TEMP_UPLOAD_PREFIX, TEMP_UPLOAD_SUFFIXES, is_temp_upload_name};
pub use ws_ticket::WsTicketStore;
