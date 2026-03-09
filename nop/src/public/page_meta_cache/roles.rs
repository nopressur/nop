// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::cache::{PageMetaCache, ResolvedRoles};
use crate::config::ValidatedConfig;
use crate::iam::User;
use crate::iam::roles::{ResolvedRoleSet, has_access_for_roles};
use actix_web::HttpRequest;
use log::debug;

impl PageMetaCache {
    pub fn user_has_access(&self, alias: &str, user: Option<&User>) -> Option<bool> {
        let object = self.get_by_alias(alias)?;
        Some(has_access_for_cached_roles(&object.resolved_roles, user))
    }

    pub fn resolved_roles(&self, alias: &str) -> Option<ResolvedRoles> {
        let object = self.get_by_alias(alias)?;
        Some(object.resolved_roles)
    }
}

fn has_access_for_cached_roles(resolved_roles: &ResolvedRoles, user: Option<&User>) -> bool {
    let resolved = match resolved_roles {
        ResolvedRoles::Public => ResolvedRoleSet::Public,
        ResolvedRoles::Deny => ResolvedRoleSet::Deny,
        ResolvedRoles::Restricted(roles) => ResolvedRoleSet::Restricted(roles.clone()),
    };
    has_access_for_roles(&resolved, user)
}

/// Check if an alias exists and if user has access (using tag-based role resolution).
pub fn check_file_access(
    cache: &PageMetaCache,
    alias: &str,
    user: Option<&User>,
    req: Option<&HttpRequest>,
    config: Option<&ValidatedConfig>,
) -> (bool, bool) {
    match cache.get_by_alias(alias) {
        Some(object) => {
            if let (Some(req), Some(config)) = (req, config)
                && crate::security::is_dev_mode_bypass_allowed(req, config)
            {
                return (true, true);
            }

            let has_access = has_access_for_cached_roles(&object.resolved_roles, user);
            (true, has_access)
        }
        None => {
            debug!("Alias not found: {}", alias);
            (false, false)
        }
    }
}
