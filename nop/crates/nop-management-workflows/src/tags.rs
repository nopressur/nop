// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::cache;
use crate::capabilities::{ConfigAccess, PageCacheAccess};
use nop_content_store::flat_storage::{read_sidecar, sidecar_path, write_sidecar_atomic};

pub async fn remove_tag_from_content<C>(context: &C, tag_id: &str) -> Result<(), String>
where
    C: PageCacheAccess + ConfigAccess,
{
    let cache = cache::load_page_cache(context).await?;
    let objects = cache.list_objects();
    for object in objects {
        if !object.tags.iter().any(|tag| tag == tag_id) {
            continue;
        }
        let sidecar_path = sidecar_path(
            &context.runtime_paths().content_dir,
            object.key.id,
            object.key.version,
        );
        let mut sidecar = read_sidecar(&sidecar_path)
            .map_err(|err| format!("Failed to read sidecar {}: {}", sidecar_path.display(), err))?;
        let before = sidecar.tags.len();
        sidecar.tags.retain(|tag| tag != tag_id);
        if sidecar.tags.len() == before {
            continue;
        }
        write_sidecar_atomic(&sidecar_path, &sidecar).map_err(|err| {
            format!(
                "Failed to update sidecar {}: {}",
                sidecar_path.display(),
                err
            )
        })?;
    }

    Ok(())
}

pub async fn rename_tag_in_content<C>(
    context: &C,
    tag_id: &str,
    new_tag_id: &str,
) -> Result<(), String>
where
    C: PageCacheAccess + ConfigAccess,
{
    let cache = cache::load_page_cache(context).await?;
    let objects = cache.list_objects();
    for object in objects {
        if !object.tags.iter().any(|tag| tag == tag_id) {
            continue;
        }
        let sidecar_path = sidecar_path(
            &context.runtime_paths().content_dir,
            object.key.id,
            object.key.version,
        );
        let mut sidecar = read_sidecar(&sidecar_path)
            .map_err(|err| format!("Failed to read sidecar {}: {}", sidecar_path.display(), err))?;
        let mut seen = std::collections::BTreeSet::new();
        let mut updated = Vec::with_capacity(sidecar.tags.len());
        let mut changed = false;
        for tag in &sidecar.tags {
            let candidate = if tag == tag_id { new_tag_id } else { tag };
            if seen.insert(candidate.to_string()) {
                updated.push(candidate.to_string());
            }
            if candidate != tag {
                changed = true;
            }
        }
        if !changed {
            continue;
        }
        sidecar.tags = updated;
        write_sidecar_atomic(&sidecar_path, &sidecar).map_err(|err| {
            format!(
                "Failed to update sidecar {}: {}",
                sidecar_path.display(),
                err
            )
        })?;
    }

    Ok(())
}

pub async fn invalidate_cache<C>(context: &C)
where
    C: PageCacheAccess,
{
    cache::invalidate_cache(context).await;
}
