// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#![allow(dead_code)]

use crate::runtime_paths::RuntimePaths;
use tempfile::TempDir;

pub fn short_runtime_paths(prefix: &str) -> (TempDir, RuntimePaths) {
    let temp_dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/tmp")
        .expect("tempdir");
    let root = temp_dir.path().to_path_buf();
    let content_dir = root.join("content");
    let themes_dir = root.join("themes");
    let state_dir = root.join("state");
    let state_sys_dir = state_dir.join("sys");
    let state_sc_dir = state_dir.join("sc");

    std::fs::create_dir_all(&content_dir).expect("content dir");
    std::fs::create_dir_all(&themes_dir).expect("themes dir");
    std::fs::create_dir_all(&state_sys_dir).expect("state/sys dir");
    std::fs::create_dir_all(&state_sc_dir).expect("state/sc dir");

    let runtime_paths = RuntimePaths {
        root: root.clone(),
        config_file: root.join("config.yaml"),
        users_file: root.join("users.yaml"),
        content_dir: content_dir.canonicalize().expect("content canonical"),
        themes_dir: themes_dir.canonicalize().expect("themes canonical"),
        state_dir: state_dir.canonicalize().expect("state canonical"),
        state_sys_dir: state_sys_dir.canonicalize().expect("state/sys canonical"),
        state_sc_dir: state_sc_dir.canonicalize().expect("state/sc canonical"),
        logs_dir: root.join("logs"),
    };

    (temp_dir, runtime_paths)
}
