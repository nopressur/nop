// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::runtime_paths::RuntimePaths;

#[derive(Debug)]
pub struct TestFixtureRoot {
    path: PathBuf,
}

impl TestFixtureRoot {
    pub fn new_fixed(name: &str) -> std::io::Result<Self> {
        let root = fixtures_root().join(name);
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { path: root })
    }

    pub fn new_unique(prefix: &str) -> std::io::Result<Self> {
        let name = format!("{}-{}", prefix, Uuid::new_v4());
        Self::new_fixed(&name)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn content_dir(&self) -> PathBuf {
        self.path.join("content")
    }

    pub fn themes_dir(&self) -> PathBuf {
        self.path.join("themes")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.path.join("state")
    }

    pub fn init_runtime_layout(&self) -> std::io::Result<()> {
        fs::create_dir_all(self.content_dir())?;
        fs::create_dir_all(self.themes_dir())?;
        fs::create_dir_all(self.state_dir().join("sys"))?;
        fs::create_dir_all(self.state_dir().join("sc"))?;
        Ok(())
    }

    pub fn runtime_paths(&self) -> std::io::Result<RuntimePaths> {
        self.init_runtime_layout()?;
        let root = self.path.canonicalize()?;
        let content_dir = self.content_dir().canonicalize()?;
        let themes_dir = self.themes_dir().canonicalize()?;
        let state_dir = self.state_dir().canonicalize()?;
        let state_sys_dir = self.state_dir().join("sys").canonicalize()?;
        let state_sc_dir = self.state_dir().join("sc").canonicalize()?;

        Ok(RuntimePaths {
            root,
            config_file: self.path.join("config.yaml"),
            users_file: self.path.join("users.yaml"),
            content_dir,
            themes_dir,
            state_dir,
            state_sys_dir,
            state_sc_dir,
            logs_dir: self.path.join("logs"),
        })
    }
}

impl Drop for TestFixtureRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn fixtures_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap_or(&manifest_dir);
    repo_root.join("target").join("test-fixtures")
}
