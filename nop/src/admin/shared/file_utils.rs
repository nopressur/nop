// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use log::{error, warn};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, mpsc};
use std::thread;

static WARNED_THEME_FILES: OnceLock<ThemeWarnCache> = OnceLock::new();

struct ThemeWarnCache {
    sender: mpsc::Sender<ThemeWarnCommand>,
}

enum ThemeWarnCommand {
    CheckAndInsert {
        path: PathBuf,
        reply: mpsc::Sender<bool>,
    },
}

impl ThemeWarnCache {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let thread = thread::Builder::new().name("theme-warn-cache".to_string());
        if let Err(err) = thread.spawn(move || run_theme_warn_cache(receiver)) {
            error!("Theme warning cache worker failed to start: {}", err);
        }
        Self { sender }
    }

    fn should_warn(&self, path: PathBuf) -> bool {
        let (reply, receive) = mpsc::channel();
        if self
            .sender
            .send(ThemeWarnCommand::CheckAndInsert { path, reply })
            .is_err()
        {
            error!("Theme warning cache channel closed");
            return true;
        }
        receive.recv().unwrap_or(true)
    }
}

fn run_theme_warn_cache(receiver: mpsc::Receiver<ThemeWarnCommand>) {
    let mut warned: HashSet<PathBuf> = HashSet::new();
    while let Ok(command) = receiver.recv() {
        match command {
            ThemeWarnCommand::CheckAndInsert { path, reply } => {
                let should_warn = warned.insert(path);
                let _ = reply.send(should_warn);
            }
        }
    }
}

fn warn_theme_file_stem_once(path: &Path) {
    let cache = WARNED_THEME_FILES.get_or_init(ThemeWarnCache::new);
    if cache.should_warn(path.to_path_buf()) {
        warn!(
            "Skipping theme file with no stem (unexpected path): {}",
            path.display()
        );
    }
}

#[derive(Debug, Clone)]
pub struct ThemeFile {
    pub name: String,
    pub file_size: u64,
    pub is_default: bool,
}

pub fn scan_themes_directory(themes_dir: &Path) -> Vec<ThemeFile> {
    let mut theme_files = Vec::new();

    if let Ok(entries) = fs::read_dir(themes_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Skip hidden files and directories starting with '.'
            if name_str.starts_with('.') {
                continue;
            }

            // Only include .html files
            if path.is_file() && name_str.ends_with(".html") {
                let file_stem = match path.file_stem() {
                    Some(stem) => stem.to_string_lossy(),
                    None => {
                        warn_theme_file_stem_once(&path);
                        continue;
                    }
                };
                let file_size = path.metadata().map(|m| m.len()).unwrap_or(0);
                let is_default = file_stem == "default";

                theme_files.push(ThemeFile {
                    name: file_stem.to_string(),
                    file_size,
                    is_default,
                });
            }
        }
    }

    // Sort alphabetically by name
    theme_files.sort_by(|a, b| a.name.cmp(&b.name));

    theme_files
}

pub fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
