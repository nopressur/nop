// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#[path = "../build_assets.rs"]
mod build_assets;

use build_assets::{MANIFEST, fingerprint, validate_outputs, verify_prebuilt};
use std::fs;
use std::path::PathBuf;

fn fixture() -> (tempfile::TempDir, PathBuf, Vec<PathBuf>) {
    let root = tempfile::tempdir().unwrap();
    let builtin = root.path().join("nop/builtin");
    for path in [
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
        "login-1234abcd/login.js",
        "login-1234abcd/login.css",
        "login-1234abcd/index.html",
        "login-1234abcd/argon2id.asm.js",
        "login-1234abcd/files/font.woff2",
    ] {
        let file = builtin.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, "asset").unwrap();
    }
    fs::write(builtin.join("login-spa-version.txt"), "login-1234abcd\n").unwrap();
    let source = root.path().join("package-lock.json");
    fs::write(&source, "source").unwrap();
    let sources = vec![source];
    let digest = fingerprint(root.path(), &sources, &builtin).unwrap();
    fs::write(builtin.join(MANIFEST), digest).unwrap();
    (root, builtin, sources)
}

#[test]
fn accepts_complete_prepared_assets() {
    let (root, builtin, sources) = fixture();
    assert_eq!(
        verify_prebuilt(root.path(), &sources, &builtin).unwrap(),
        "login-1234abcd"
    );
}

#[test]
fn rejects_missing_or_empty_required_assets() {
    for path in [
        "site.js",
        "admin/admin-spa.css",
        "login-1234abcd/login.js",
        "login-1234abcd/argon2id.asm.js",
    ] {
        let (_root, builtin, _sources) = fixture();
        fs::write(builtin.join(path), "").unwrap();
        assert!(validate_outputs(&builtin, "login-1234abcd").is_err());
        fs::remove_file(builtin.join(path)).unwrap();
        assert!(validate_outputs(&builtin, "login-1234abcd").is_err());
    }
}

#[test]
fn rejects_changed_assets_and_sources() {
    let (root, builtin, sources) = fixture();
    fs::write(&sources[0], "changed source").unwrap();
    assert!(verify_prebuilt(root.path(), &sources, &builtin).is_err());
    fs::write(&sources[0], "source").unwrap();
    fs::write(builtin.join("site.js"), "changed asset").unwrap();
    assert!(verify_prebuilt(root.path(), &sources, &builtin).is_err());
}

#[test]
fn rejects_missing_manifest_fonts_and_unsafe_version() {
    let (root, builtin, sources) = fixture();
    fs::remove_file(builtin.join(MANIFEST)).unwrap();
    assert!(verify_prebuilt(root.path(), &sources, &builtin).is_err());
    fs::remove_file(builtin.join("login-1234abcd/files/font.woff2")).unwrap();
    assert!(validate_outputs(&builtin, "login-1234abcd").is_err());
    assert!(validate_outputs(&builtin, "login-../../..").is_err());
}

#[test]
fn fingerprint_is_independent_of_checkout_path_and_source_order() {
    let (first, builtin, sources) = fixture();
    let (second, other_builtin, other_sources) = fixture();
    assert_eq!(
        fingerprint(first.path(), &sources, &builtin).unwrap(),
        fingerprint(second.path(), &other_sources, &other_builtin).unwrap()
    );
    let repeated = vec![sources[0].clone(), sources[0].clone()];
    assert_eq!(
        fingerprint(first.path(), &sources, &builtin).unwrap(),
        fingerprint(first.path(), &repeated, &builtin).unwrap()
    );
}
