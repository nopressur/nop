// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::cache;
use crate::capabilities::{PageCacheAccess, RoleStoreAccess, TagStoreAccess, UserServicesAccess};
use nop_roles::MAX_ROLE_COUNT;
use std::collections::HashSet;

pub async fn rename_role<C>(context: &C, role: &str, new_role: &str) -> Result<(), String>
where
    C: RoleStoreAccess + TagStoreAccess + UserServicesAccess + PageCacheAccess,
{
    let mut roles = context.roles_snapshot()?;
    if !roles.contains(role) {
        return Err("Role not found".to_string());
    }
    if roles.contains(new_role) {
        return Err("New role already exists".to_string());
    }

    let tags_changed = if roles.len() >= MAX_ROLE_COUNT {
        roles.remove(role);
        roles.insert(new_role.to_string());
        context.persist_roles(roles)?;
        let tags_changed = replace_role_in_tags(context, role, new_role)?;
        replace_role_in_users(context, role, new_role).await?;
        tags_changed
    } else {
        roles.insert(new_role.to_string());
        context.persist_roles(roles.clone())?;
        let tags_changed = replace_role_in_tags(context, role, new_role)?;
        replace_role_in_users(context, role, new_role).await?;
        roles.remove(role);
        context.persist_roles(roles)?;
        tags_changed
    };

    if tags_changed {
        cache::invalidate_cache(context).await;
    }

    Ok(())
}

pub async fn delete_role<C>(context: &C, role: &str) -> Result<(), String>
where
    C: RoleStoreAccess + TagStoreAccess + UserServicesAccess + PageCacheAccess,
{
    let roles = context.roles_snapshot()?;
    if !roles.contains(role) {
        return Err("Role not found".to_string());
    }
    let tags_changed = remove_role_from_tags(context, role)?;
    remove_role_from_users(context, role).await?;
    let mut updated_roles = roles;
    updated_roles.remove(role);
    context.persist_roles(updated_roles)?;
    if tags_changed {
        cache::invalidate_cache(context).await;
    }
    Ok(())
}

fn replace_role_in_tags<C>(context: &C, from_role: &str, to_role: &str) -> Result<bool, String>
where
    C: TagStoreAccess,
{
    let mut tags = context.tags_snapshot()?;
    let mut changed = false;
    for record in tags.values_mut() {
        if record.roles.is_empty() {
            continue;
        }
        let mut seen = HashSet::new();
        let mut updated = Vec::with_capacity(record.roles.len());
        for role in &record.roles {
            let candidate = if role == from_role { to_role } else { role };
            if seen.insert(candidate.to_string()) {
                updated.push(candidate.to_string());
            }
        }
        if updated != record.roles {
            record.roles = updated;
            changed = true;
        }
    }
    if changed {
        context.persist_tags(tags)?;
    }
    Ok(changed)
}

fn remove_role_from_tags<C>(context: &C, role: &str) -> Result<bool, String>
where
    C: TagStoreAccess,
{
    let mut tags = context.tags_snapshot()?;
    let mut changed = false;
    for record in tags.values_mut() {
        if record.roles.is_empty() {
            continue;
        }
        let before = record.roles.len();
        record.roles.retain(|item| item != role);
        if record.roles.len() != before {
            changed = true;
        }
    }
    if changed {
        context.persist_tags(tags)?;
    }
    Ok(changed)
}

async fn replace_role_in_users<C>(context: &C, from_role: &str, to_role: &str) -> Result<(), String>
where
    C: UserServicesAccess,
{
    let users = context.list_user_roles().await?;
    for user in users {
        if user.roles.is_empty() {
            continue;
        }
        let mut seen = HashSet::new();
        let mut updated = Vec::with_capacity(user.roles.len());
        for role in &user.roles {
            let candidate = if role == from_role { to_role } else { role };
            if seen.insert(candidate.to_string()) {
                updated.push(candidate.to_string());
            }
        }
        if updated != user.roles {
            context.update_user_roles(&user.email, updated).await?;
        }
    }
    Ok(())
}

async fn remove_role_from_users<C>(context: &C, role: &str) -> Result<(), String>
where
    C: UserServicesAccess,
{
    let users = context.list_user_roles().await?;
    for user in users {
        if user.roles.is_empty() {
            continue;
        }
        let before = user.roles.len();
        let updated: Vec<String> = user
            .roles
            .iter()
            .filter(|item| item.as_str() != role)
            .cloned()
            .collect();
        if updated.len() != before {
            context.update_user_roles(&user.email, updated).await?;
        }
    }
    Ok(())
}
