// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

mod action_limits;
mod path;
mod routing;
mod threats;
mod validation;

pub use action_limits::{AuthAction, AuthActionLimiter};
pub use path::{canonical_path_checks, validate_new_file_path};
pub use routing::{
    is_link_valid, normalize_relative_path, route_checks, route_checks_legacy,
    validate_login_return_path,
};
#[allow(unused_imports)]
pub use threats::extract_client_ip;
pub use threats::{ThreatTracker, is_dev_mode_bypass_allowed, is_ip_blocked, record_login_failure};
pub use validation::{
    MAX_EMAIL_CHARS, MAX_NAME_CHARS, validate_and_sanitize_user_name, validate_email_field,
    validate_new_file_name,
};
