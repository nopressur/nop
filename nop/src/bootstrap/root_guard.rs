// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::{BootstrapError, log_action};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const EXPECTED_ROOT_ENTRIES: [&str; 7] = [
    "config.yaml",
    "users.yaml",
    "content",
    "themes",
    "state",
    "logs",
    "nop.pid",
];

pub fn ensure_root_is_clean(root: &Path) -> Result<PathBuf, BootstrapError> {
    let root_path = normalize_root(root)?;
    verify_root_entries(&root_path)?;
    Ok(root_path)
}

fn normalize_root(root: &Path) -> Result<PathBuf, BootstrapError> {
    let root_path = if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root.to_path_buf()
    };

    if root_path.exists() {
        if !root_path.is_dir() {
            return Err(BootstrapError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Runtime root is not a directory: {}", root_path.display()),
            )));
        }
        return Ok(root_path);
    }

    fs::create_dir_all(&root_path)?;
    log_action(format!(
        "created runtime root directory {}",
        root_path.display()
    ));
    Ok(root_path)
}

fn verify_root_entries(root: &Path) -> Result<(), BootstrapError> {
    let mut unexpected = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry.map_err(BootstrapError::Io)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if EXPECTED_ROOT_ENTRIES.contains(&name.as_ref()) {
            continue;
        }
        unexpected.push(name.into_owned());
    }

    if unexpected.is_empty() {
        return Ok(());
    }

    unexpected.sort();
    let expected = EXPECTED_ROOT_ENTRIES.join(", ");
    let unexpected_list = unexpected.join(", ");
    Err(BootstrapError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "Runtime root '{}' contains unexpected entries: {}. Expected only: {}.",
            root.display(),
            unexpected_list,
            expected
        ),
    )))
}
