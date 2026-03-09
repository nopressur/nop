// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::iam::User;
use crate::management::AccessRule;
use log::warn;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;

pub const ADMIN_ROLE: &str = "admin";
pub const MAX_ROLE_COUNT: usize = 64;
pub const MAX_ROLE_CHARS: usize = 64;

#[derive(Debug)]
pub struct RoleValidationError {
    message: String,
}

impl RoleValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RoleValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for RoleValidationError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRoleRecord {
    #[serde(rename = "name")]
    _name: String,
    #[serde(default)]
    pub roles: Vec<String>,
    pub access_rule: Option<AccessRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedRoleSet {
    Public,
    Restricted(Vec<String>),
    Deny,
}

pub fn normalize_role(role: &str) -> Result<String, RoleValidationError> {
    let trimmed = role.trim();
    if trimmed.is_empty() {
        return Err(RoleValidationError::new("Role is required"));
    }
    let normalized = trimmed.to_ascii_lowercase();
    if normalized.chars().count() > MAX_ROLE_CHARS {
        return Err(RoleValidationError::new(format!(
            "Role must be at most {} characters",
            MAX_ROLE_CHARS
        )));
    }
    if !normalized
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(RoleValidationError::new(format!(
            "Role '{}' contains invalid characters",
            trimmed
        )));
    }
    Ok(normalized)
}

pub fn normalize_roles(roles: &[String]) -> Result<Vec<String>, RoleValidationError> {
    if roles.len() > MAX_ROLE_COUNT {
        return Err(RoleValidationError::new(format!(
            "Roles must be at most {} entries",
            MAX_ROLE_COUNT
        )));
    }
    let mut normalized = Vec::with_capacity(roles.len());
    for role in roles {
        normalized.push(normalize_role(role)?);
    }
    Ok(normalized)
}

pub fn resolve_roles_for_tags(
    tags: &[String],
    tag_map: &BTreeMap<String, TagRoleRecord>,
) -> ResolvedRoleSet {
    if tags.is_empty() || tag_map.is_empty() {
        return ResolvedRoleSet::Public;
    }

    let mut role_sets = Vec::<HashSet<String>>::new();
    let mut any_union = false;
    let mut any_intersect = false;
    let mut has_roles = false;
    let mut any_roles_declared = false;

    for tag in tags {
        if let Some(record) = tag_map.get(tag) {
            if record.access_rule == Some(AccessRule::Union) {
                any_union = true;
            }
            if record.access_rule == Some(AccessRule::Intersect) {
                any_intersect = true;
            }
            if !record.roles.is_empty() {
                any_roles_declared = true;
                let mut role_set = HashSet::new();
                for role in &record.roles {
                    match normalize_role(role) {
                        Ok(normalized) => {
                            role_set.insert(normalized);
                        }
                        Err(err) => {
                            warn!("Skipping invalid role '{}' in tag '{}': {}", role, tag, err);
                        }
                    }
                }
                if !role_set.is_empty() {
                    has_roles = true;
                    role_sets.push(role_set);
                }
            }
        }
    }

    if !has_roles {
        return if any_roles_declared {
            ResolvedRoleSet::Deny
        } else {
            ResolvedRoleSet::Public
        };
    }

    let resolved = if any_intersect {
        intersect_role_sets(&role_sets)
    } else if any_union {
        union_role_sets(&role_sets)
    } else {
        intersect_role_sets(&role_sets)
    };

    if resolved.is_empty() {
        return ResolvedRoleSet::Deny;
    }

    let mut roles: Vec<String> = resolved.into_iter().collect();
    roles.sort();
    ResolvedRoleSet::Restricted(roles)
}

pub fn has_access_for_roles(resolved_roles: &ResolvedRoleSet, user: Option<&User>) -> bool {
    match resolved_roles {
        ResolvedRoleSet::Public => true,
        ResolvedRoleSet::Deny => {
            user.is_some_and(|user| user.roles.iter().any(|role| role == ADMIN_ROLE))
        }
        ResolvedRoleSet::Restricted(required_roles) => {
            let Some(user) = user else {
                return false;
            };

            if user.roles.iter().any(|role| role == ADMIN_ROLE) {
                return true;
            }

            user.roles
                .iter()
                .any(|role| required_roles.iter().any(|required| required == role))
        }
    }
}

fn union_role_sets(sets: &[HashSet<String>]) -> HashSet<String> {
    let mut union = HashSet::new();
    for set in sets {
        for role in set {
            union.insert(role.clone());
        }
    }
    union
}

fn intersect_role_sets(sets: &[HashSet<String>]) -> HashSet<String> {
    let mut iter = sets.iter();
    let Some(first) = iter.next() else {
        return HashSet::new();
    };

    let mut intersection = first.clone();
    for set in iter {
        intersection.retain(|role| set.contains(role));
    }
    intersection
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn normalize_role_lowercases_and_validates() {
        assert_eq!(normalize_role("Editor").unwrap(), "editor");
        assert!(normalize_role(" ").is_err());
        assert!(normalize_role("bad!role").is_err());
    }

    #[test]
    fn normalize_roles_enforces_count_limit() {
        let roles = vec!["role".to_string(); MAX_ROLE_COUNT + 1];
        assert!(normalize_roles(&roles).is_err());
    }

    #[test]
    fn resolve_roles_honors_union_and_intersect() {
        let mut tag_map = BTreeMap::new();
        tag_map.insert(
            "union".to_string(),
            TagRoleRecord {
                _name: "Union".to_string(),
                roles: vec!["alpha".to_string()],
                access_rule: Some(AccessRule::Union),
            },
        );
        tag_map.insert(
            "intersect".to_string(),
            TagRoleRecord {
                _name: "Intersect".to_string(),
                roles: vec!["beta".to_string()],
                access_rule: Some(AccessRule::Intersect),
            },
        );

        let union = resolve_roles_for_tags(&vec!["union".to_string()], &tag_map);
        assert_eq!(
            union,
            ResolvedRoleSet::Restricted(vec!["alpha".to_string()])
        );

        let intersect = resolve_roles_for_tags(
            &vec!["union".to_string(), "intersect".to_string()],
            &tag_map,
        );
        assert_eq!(intersect, ResolvedRoleSet::Deny);
    }

    #[test]
    fn resolve_roles_invalid_entries_result_in_deny() {
        let mut tag_map = BTreeMap::new();
        tag_map.insert(
            "invalid".to_string(),
            TagRoleRecord {
                _name: "Invalid".to_string(),
                roles: vec!["bad role".to_string()],
                access_rule: None,
            },
        );

        let resolved = resolve_roles_for_tags(&vec!["invalid".to_string()], &tag_map);
        assert_eq!(resolved, ResolvedRoleSet::Deny);
    }

    #[test]
    fn has_access_for_roles_allows_admin() {
        let user = User {
            email: "admin@example.com".to_string(),
            name: "Admin".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec![ADMIN_ROLE.to_string()],
            password_version: 1,
        };
        let resolved = ResolvedRoleSet::Restricted(vec!["viewer".to_string()]);
        assert!(has_access_for_roles(&resolved, Some(&user)));
    }

    #[test]
    fn has_access_for_roles_allows_admin_on_deny() {
        let user = User {
            email: "admin@example.com".to_string(),
            name: "Admin".to_string(),
            password: None,
            legacy_password_hash: None,
            roles: vec![ADMIN_ROLE.to_string()],
            password_version: 1,
        };
        let resolved = ResolvedRoleSet::Deny;
        assert!(has_access_for_roles(&resolved, Some(&user)));
    }
}
