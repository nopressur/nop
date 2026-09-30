// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const MANIFEST: &str = ".release-assets.sha256";

pub fn validate_outputs(builtin: &Path, login_version: &str) -> Result<(), String> {
    if !login_version.starts_with("login-")
        || !login_version[6..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || login_version.len() != 14
    {
        return Err("Invalid login asset version".into());
    }
    let mut required: Vec<PathBuf> = [
        "admin/admin-spa.js",
        "admin/admin-spa.css",
        "admin/index.html",
        "site.js",
        "bulma.min.css",
        "theme-preset.css",
        "copy.svg",
        "favicon.ico",
        "ace.js",
        "ext-language_tools.js",
        "mode-html.js",
        "mode-markdown.js",
        "theme-github.js",
        "theme-github_dark.js",
        "theme-github_light_default.js",
        "theme-monokai.js",
    ]
    .into_iter()
    .map(|path| builtin.join(path))
    .collect();
    let login = builtin.join(login_version);
    for name in ["login.js", "login.css", "index.html", "argon2id.asm.js"] {
        required.push(login.join(name));
    }
    let fonts = login.join("files");
    let entries = fs::read_dir(&fonts).map_err(|error| format!("Missing login fonts: {error}"))?;
    let mut has_font = false;
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path
            .extension()
            .is_some_and(|ext| ext == "woff" || ext == "woff2")
        {
            has_font = true;
            required.push(path);
        }
    }
    if !has_font {
        return Err("Missing login fonts".into());
    }
    for path in required {
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("Required builtin missing: {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(format!("Required builtin is empty: {}", path.display()));
        }
    }
    Ok(())
}

// Paths are relative to the checkout so the same digest verifies inside cross containers.
pub fn fingerprint(repo: &Path, sources: &[PathBuf], builtin: &Path) -> Result<String, String> {
    let mut files = sources.to_vec();
    for entry in WalkDir::new(builtin) {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_type().is_file() && entry.file_name() != MANIFEST {
            files.push(entry.into_path());
        }
    }
    files.sort();
    files.dedup();
    let mut digest = Sha256::new();
    for path in files {
        let relative = path.strip_prefix(repo).map_err(|error| error.to_string())?;
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn verify_prebuilt(repo: &Path, sources: &[PathBuf], builtin: &Path) -> Result<String, String> {
    let version = fs::read_to_string(builtin.join("login-spa-version.txt"))
        .map_err(|error| error.to_string())?;
    let version = version.trim().to_string();
    validate_outputs(builtin, &version)?;
    let expected = fs::read_to_string(builtin.join(MANIFEST))
        .map_err(|error| format!("Prepared asset manifest missing: {error}"))?;
    if expected.trim() != fingerprint(repo, sources, builtin)? {
        return Err(
            "Prepared assets or their sources changed; rebuild assets on the release host".into(),
        );
    }
    Ok(version)
}
