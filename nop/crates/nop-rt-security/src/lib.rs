// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use log::debug;
use nop_rt_page_cache::PageMetaCache;

mod action_limits;
mod path;
mod routing;
pub mod threats;

pub use action_limits::{AuthAction, AuthActionLimiter};
pub use path::canonical_path_checks;
pub use routing::{
    is_link_valid, normalize_relative_path, route_checks, route_checks_legacy,
    validate_login_return_path,
};
pub use threats::{ThreatTracker, is_dev_mode_bypass_allowed, is_ip_blocked, record_login_failure};

#[derive(Clone)]
pub struct SecurityTools {
    pub threat_tracker: ThreatTracker,
    pub auth_action_limiter: AuthActionLimiter,
}

impl SecurityTools {
    pub fn new() -> Self {
        Self {
            threat_tracker: ThreatTracker::new(),
            auth_action_limiter: AuthActionLimiter::new(),
        }
    }
}

impl Default for SecurityTools {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an alias exists and if user has access (using tag-based role resolution).
pub fn check_file_access(
    cache: &PageMetaCache,
    alias: &str,
    user_roles: Option<&[String]>,
    dev_mode_bypass_allowed: bool,
) -> (bool, bool) {
    match cache.get_by_alias(alias) {
        Some(_) => {
            if dev_mode_bypass_allowed {
                return (true, true);
            }

            let has_access = cache.user_has_access(alias, user_roles).unwrap_or(false);
            (true, has_access)
        }
        None => {
            debug!("Alias not found: {}", alias);
            (false, false)
        }
    }
}
