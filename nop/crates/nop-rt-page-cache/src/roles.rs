// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::cache::{PageMetaCache, ResolvedRoles};
use nop_roles::{ResolvedRoleSet, has_access_for_roles};

impl PageMetaCache {
    pub fn user_has_access(&self, alias: &str, user_roles: Option<&[String]>) -> Option<bool> {
        let object = self.get_by_alias(alias)?;
        Some(has_access_for_cached_roles(
            &object.resolved_roles,
            user_roles,
        ))
    }

    pub fn resolved_roles(&self, alias: &str) -> Option<ResolvedRoles> {
        let object = self.get_by_alias(alias)?;
        Some(object.resolved_roles)
    }
}

fn has_access_for_cached_roles(
    resolved_roles: &ResolvedRoles,
    user_roles: Option<&[String]>,
) -> bool {
    let resolved = match resolved_roles {
        ResolvedRoles::Public => ResolvedRoleSet::Public,
        ResolvedRoles::Deny => ResolvedRoleSet::Deny,
        ResolvedRoles::Restricted(roles) => ResolvedRoleSet::Restricted(roles.clone()),
    };
    has_access_for_roles(&resolved, user_roles)
}
