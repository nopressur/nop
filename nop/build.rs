// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

// Build script for embedding builtin files into the release binary
// This script only embeds files in release mode to keep dev builds fast

use flate2::{Compression, write::GzEncoder};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

fn main() {
    // Tell Cargo to rerun this build script if these files change
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.parent().unwrap_or(&manifest_dir).to_path_buf();
    let scripts_root = repo_root.join("scripts");
    let builtin_root = manifest_dir.join("builtin");
    let admin_root = manifest_dir.join("ts").join("admin");
    let admin_output = builtin_root.join("admin");
    let login_root = manifest_dir.join("ts").join("login");
    let site_root = manifest_dir.join("ts").join("site");
    let site_output = builtin_root.join("site.js");
    let login_version_file = builtin_root.join("login-spa-version.txt");
    let bulma_script = scripts_root.join("update-bulma.sh");
    let bulma_version = scripts_root.join("bulma-version.txt");
    let bulma_css = builtin_root.join("bulma.min.css");
    let ace_script = scripts_root.join("update-ace.sh");
    let ace_version = scripts_root.join("ace-version.txt");
    let ace_assets = vec![
        "ace.js",
        "ext-language_tools.js",
        "mode-html.js",
        "mode-markdown.js",
        "theme-github.js",
        "theme-github_dark.js",
        "theme-github_light_default.js",
        "theme-monokai.js",
    ];

    println!("cargo:rerun-if-changed={}", builtin_root.display());
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("package.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("package-lock.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("vite.config.ts").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("svelte.config.js").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("tailwind.config.cjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("postcss.config.cjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("tsconfig.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        admin_root.join("index.html").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("package.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("package-lock.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("vite.config.ts").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("svelte.config.js").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("tailwind.config.cjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("postcss.config.cjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("tsconfig.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        login_root.join("index.html").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        site_root.join("package.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        site_root.join("package-lock.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        site_root.join("vite.config.ts").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        site_root.join("tsconfig.json").display()
    );
    println!("cargo:rerun-if-changed={}", bulma_script.display());
    println!("cargo:rerun-if-changed={}", bulma_version.display());
    println!("cargo:rerun-if-changed={}", bulma_css.display());
    println!("cargo:rerun-if-changed={}", ace_script.display());
    println!("cargo:rerun-if-changed={}", ace_version.display());
    for asset in &ace_assets {
        println!(
            "cargo:rerun-if-changed={}",
            builtin_root.join(asset).display()
        );
    }
    println!("cargo:rerun-if-changed={}", login_version_file.display());

    if admin_root.join("src").exists() {
        for entry in WalkDir::new(admin_root.join("src"))
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    }
    if login_root.join("src").exists() {
        for entry in WalkDir::new(login_root.join("src"))
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    }
    if site_root.join("src").exists() {
        for entry in WalkDir::new(site_root.join("src"))
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    }

    ensure_bulma_css(&bulma_script, &bulma_version, &bulma_css, &manifest_dir);
    ensure_ace_assets(
        &ace_script,
        &ace_version,
        &builtin_root,
        &ace_assets,
        &manifest_dir,
    );
    ensure_admin_spa(&admin_root, &admin_output);
    let login_version = ensure_login_spa(&login_root, &builtin_root, &login_version_file);
    ensure_site_bundle(&site_root, &site_output);

    let out_dir = env::var("OUT_DIR").unwrap();
    write_login_spa_version(&out_dir, &login_version);
    let builtin_rs_path = Path::new(&out_dir).join("builtin_files.rs");

    // Only embed files in release mode for smaller binary size in development
    if env::var("PROFILE").unwrap() == "release" {
        embed_builtin_files(&builtin_rs_path, &builtin_root);
    } else {
        // In debug mode, create empty file - files are served from filesystem
        fs::write(
            &builtin_rs_path,
            "// Dev mode - files served from filesystem\n",
        )
        .unwrap();
    }
}

fn ensure_bulma_css(
    bulma_script: &Path,
    bulma_version: &Path,
    bulma_css: &Path,
    manifest_dir: &Path,
) {
    if bulma_css.is_file() {
        return;
    }

    if !bulma_script.is_file() {
        panic!("Bulma updater script missing: {}", bulma_script.display());
    }
    if !bulma_version.is_file() {
        panic!("Bulma version file missing: {}", bulma_version.display());
    }

    println!("cargo:warning=Bulma CSS missing; running updater");
    let mut command = Command::new(bulma_script);
    command.arg("--ensure").current_dir(manifest_dir);
    run_command(command, "update-bulma.sh --ensure");

    if !bulma_css.is_file() {
        panic!(
            "Bulma CSS still missing after update: {}",
            bulma_css.display()
        );
    }
}

fn ensure_ace_assets(
    ace_script: &Path,
    ace_version: &Path,
    builtin_root: &Path,
    ace_assets: &[&str],
    manifest_dir: &Path,
) {
    let mut missing = vec![];
    for asset in ace_assets {
        let path = builtin_root.join(asset);
        if !path.is_file() {
            missing.push(path);
        }
    }

    if missing.is_empty() {
        return;
    }

    if !ace_script.is_file() {
        panic!("Ace updater script missing: {}", ace_script.display());
    }
    if !ace_version.is_file() {
        panic!("Ace version file missing: {}", ace_version.display());
    }

    println!("cargo:warning=Ace assets missing; running updater");
    let mut command = Command::new(ace_script);
    command.arg("--ensure").current_dir(manifest_dir);
    run_command(command, "update-ace.sh --ensure");

    for asset in ace_assets {
        let path = builtin_root.join(asset);
        if !path.is_file() {
            panic!("Ace asset still missing after update: {}", path.display());
        }
        if let Ok(metadata) = fs::metadata(&path)
            && metadata.len() == 0
        {
            panic!("Ace asset is empty after update: {}", path.display());
        }
    }
}

fn ensure_admin_spa(admin_root: &Path, admin_output: &Path) {
    let admin_js = admin_output.join("admin-spa.js");
    let admin_css = admin_output.join("admin-spa.css");
    let admin_html = admin_output.join("index.html");
    let outputs = vec![admin_js, admin_css, admin_html];

    if needs_admin_build(admin_root, &outputs) {
        println!("cargo:warning=Building admin SPA via npm run build");
        run_admin_build(admin_root);
    }
}

fn ensure_site_bundle(site_root: &Path, site_output: &Path) {
    if needs_site_build(site_root, site_output) {
        println!("cargo:warning=Building site bundle via npm run build");
        run_site_build(site_root);
    }
}

fn ensure_login_spa(login_root: &Path, builtin_root: &Path, version_file: &Path) -> String {
    if !login_root.is_dir() {
        panic!("Login SPA directory missing: {}", login_root.display());
    }

    let existing_version = read_login_version(version_file);
    let mut version = existing_version
        .clone()
        .unwrap_or_else(generate_login_version);
    let mut output_dir = builtin_root.join(&version);

    let outputs = collect_login_outputs(&output_dir);
    let needs_build = needs_login_build(login_root, &outputs);

    if needs_build {
        version = generate_login_version();
        output_dir = builtin_root.join(&version);
        prune_login_outputs(builtin_root, &version);
        println!("cargo:warning=Building login SPA via npm run build");
        run_login_build(login_root, &output_dir, &version);
        write_login_version(version_file, &version);
    } else if existing_version.is_none() {
        write_login_version(version_file, &version);
    }

    version
}

fn needs_site_build(site_root: &Path, output: &Path) -> bool {
    if !output.is_file() {
        return true;
    }

    let source_files = collect_site_sources(site_root);
    let Some(latest_source) = max_mtime(&source_files) else {
        return true;
    };
    let Some(oldest_output) = min_mtime(&[output.to_path_buf()]) else {
        return true;
    };

    latest_source > oldest_output
}

fn needs_admin_build(admin_root: &Path, outputs: &[PathBuf]) -> bool {
    if outputs.iter().any(|path| !path.is_file()) {
        return true;
    }

    let source_files = collect_admin_sources(admin_root);
    let Some(latest_source) = max_mtime(&source_files) else {
        return true;
    };
    let Some(oldest_output) = min_mtime(outputs) else {
        return true;
    };

    latest_source > oldest_output
}

fn needs_login_build(login_root: &Path, outputs: &[PathBuf]) -> bool {
    if outputs.is_empty() {
        return true;
    }

    let source_files = collect_login_sources(login_root);
    let Some(latest_source) = max_mtime(&source_files) else {
        return true;
    };
    let Some(oldest_output) = min_mtime(outputs) else {
        return true;
    };

    latest_source > oldest_output
}

fn collect_admin_sources(admin_root: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    let config_files = [
        "package.json",
        "package-lock.json",
        "vite.config.ts",
        "svelte.config.js",
        "tailwind.config.cjs",
        "postcss.config.cjs",
        "tsconfig.json",
        "index.html",
        "src/app.css",
    ];

    for file in config_files {
        let path = admin_root.join(file);
        if path.is_file() {
            sources.push(path);
        }
    }

    let src_root = admin_root.join("src");
    if src_root.is_dir() {
        for entry in WalkDir::new(src_root).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                sources.push(entry.path().to_path_buf());
            }
        }
    }

    sources
}

fn collect_site_sources(site_root: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    let config_files = [
        "package.json",
        "package-lock.json",
        "vite.config.ts",
        "tsconfig.json",
    ];

    for file in config_files {
        let path = site_root.join(file);
        if path.is_file() {
            sources.push(path);
        }
    }

    let src_root = site_root.join("src");
    if src_root.is_dir() {
        for entry in WalkDir::new(src_root).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                sources.push(entry.path().to_path_buf());
            }
        }
    }

    sources
}

fn collect_login_sources(login_root: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    let config_files = [
        "package.json",
        "package-lock.json",
        "vite.config.ts",
        "svelte.config.js",
        "tailwind.config.cjs",
        "postcss.config.cjs",
        "tsconfig.json",
        "index.html",
        "src/app.css",
    ];

    for file in config_files {
        let path = login_root.join(file);
        if path.is_file() {
            sources.push(path);
        }
    }

    let src_root = login_root.join("src");
    if src_root.is_dir() {
        for entry in WalkDir::new(src_root).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                sources.push(entry.path().to_path_buf());
            }
        }
    }

    sources
}

fn collect_login_outputs(output_dir: &Path) -> Vec<PathBuf> {
    let mut outputs = Vec::new();
    if output_dir.is_dir() {
        for entry in WalkDir::new(output_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                outputs.push(entry.path().to_path_buf());
            }
        }
    }
    outputs
}

fn max_mtime(paths: &[PathBuf]) -> Option<SystemTime> {
    let mut latest = None;
    for path in paths {
        let modified = fs::metadata(path).and_then(|meta| meta.modified()).ok()?;
        latest = Some(match latest {
            Some(current) if current > modified => current,
            _ => modified,
        });
    }
    latest
}

fn min_mtime(paths: &[PathBuf]) -> Option<SystemTime> {
    let mut oldest = None;
    for path in paths {
        let modified = fs::metadata(path).and_then(|meta| meta.modified()).ok()?;
        oldest = Some(match oldest {
            Some(current) if current < modified => current,
            _ => modified,
        });
    }
    oldest
}

fn run_admin_build(admin_root: &Path) {
    if !admin_root.is_dir() {
        panic!("Admin SPA directory missing: {}", admin_root.display());
    }

    if !node_modules_ready(admin_root) {
        let mut command = Command::new("npm");
        command.arg("install").current_dir(admin_root);
        run_command(command, "npm install");
    }

    let mut command = Command::new("npm");
    command.arg("run").arg("build").current_dir(admin_root);
    run_command(command, "npm run build");
}

fn run_site_build(site_root: &Path) {
    if !site_root.is_dir() {
        panic!("Site bundle directory missing: {}", site_root.display());
    }

    if !node_modules_ready(site_root) {
        let mut command = Command::new("npm");
        command.arg("install").current_dir(site_root);
        run_command(command, "npm install (site)");
    }

    let mut command = Command::new("npm");
    command.arg("run").arg("build").current_dir(site_root);
    run_command(command, "npm run build (site)");
}

fn run_login_build(login_root: &Path, output_dir: &Path, version: &str) {
    if !login_root.is_dir() {
        panic!("Login SPA directory missing: {}", login_root.display());
    }

    if !node_modules_ready(login_root) {
        let mut command = Command::new("npm");
        command.arg("install").current_dir(login_root);
        run_command(command, "npm install (login)");
    }

    let mut command = Command::new("npm");
    command
        .arg("run")
        .arg("build")
        .current_dir(login_root)
        .env("LOGIN_SPA_OUT_DIR", output_dir)
        .env("LOGIN_SPA_BASE", format!("/builtin/{}/", version));
    run_command(command, "npm run build (login)");
}

fn generate_login_version() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis();
    let mut hasher = Sha256::new();
    hasher.update(millis.to_string().as_bytes());
    let hash = hasher.finalize();
    let hash_hex = format!("{:x}", hash);
    format!("login-{}", &hash_hex[..8])
}

fn node_modules_ready(package_root: &Path) -> bool {
    let node_modules = package_root.join("node_modules");
    if !node_modules.is_dir() {
        return false;
    }

    let package_json = package_root.join("package.json");
    let contents = match fs::read_to_string(&package_json) {
        Ok(contents) => contents,
        Err(_) => return false,
    };
    let parsed: Value = match serde_json::from_str(&contents) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };

    let mut deps: Vec<&str> = Vec::new();
    if let Some(map) = parsed
        .get("dependencies")
        .and_then(|value| value.as_object())
    {
        deps.extend(map.keys().map(|key| key.as_str()));
    }
    if let Some(map) = parsed
        .get("devDependencies")
        .and_then(|value| value.as_object())
    {
        deps.extend(map.keys().map(|key| key.as_str()));
    }

    deps.iter()
        .all(|dep| dependency_installed(&node_modules, dep))
}

fn dependency_installed(node_modules: &Path, package: &str) -> bool {
    if let Some((scope, name)) = package.split_once('/') {
        node_modules.join(scope).join(name).is_dir()
    } else {
        node_modules.join(package).is_dir()
    }
}

fn read_login_version(version_file: &Path) -> Option<String> {
    fs::read_to_string(version_file)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| value.starts_with("login-"))
}

fn write_login_version(version_file: &Path, version: &str) {
    if let Some(parent) = version_file.parent()
        && !parent.exists()
        && let Err(err) = fs::create_dir_all(parent)
    {
        panic!("Failed to create builtin directory: {}", err);
    }
    if let Err(err) = fs::write(version_file, format!("{}\n", version)) {
        panic!("Failed to write login spa version file: {}", err);
    }
}

fn write_login_spa_version(out_dir: &str, version: &str) {
    let path = Path::new(out_dir).join("login_spa_version.rs");
    let content = format!("pub const LOGIN_SPA_DIR: &str = \"{}\";\n", version);
    if let Err(err) = fs::write(path, content) {
        panic!("Failed to write login spa version file: {}", err);
    }
}

fn prune_login_outputs(builtin_root: &Path, keep_version: &str) {
    if let Ok(entries) = fs::read_dir(builtin_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with("login-") && name != keep_version {
                let _ = fs::remove_dir_all(&path);
            }
        }
    }
}

fn run_command(mut command: Command, label: &str) {
    let status = command.status().unwrap_or_else(|err| {
        panic!("Failed to spawn {}: {}", label, err);
    });
    if !status.success() {
        panic!("{} failed with status {}", label, status);
    }
}

/// Embeds all files from the builtin directory into a compressed format
/// for inclusion in the release binary.
///
/// This function generates Rust code that creates a HashMap containing
/// all builtin files as compressed byte arrays with their MIME types.
fn embed_builtin_files(output_path: &Path, builtin_root: &Path) {
    let mut output = BufWriter::new(File::create(output_path).unwrap());

    // Write the necessary imports for the generated code
    writeln!(output, "use std::collections::HashMap;").unwrap();
    writeln!(output, "use once_cell::sync::Lazy;").unwrap();
    writeln!(output).unwrap();

    // Generate constants for each file's compressed data
    let mut file_constants = Vec::new();

    if builtin_root.exists() {
        for entry in WalkDir::new(builtin_root)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let path = entry.path();
                let relative_path = path.strip_prefix(builtin_root).unwrap();
                let path_str = relative_path.to_string_lossy();

                // Read and compress the file content
                let content = fs::read(path).unwrap();
                let compressed = compress_data(&content);

                // Generate a safe constant name from the file path
                let const_name = format!(
                    "FILE_{}",
                    path_str.replace(['.', '/', '-'], "_").to_uppercase()
                );

                writeln!(output, "const {}: &[u8] = &{:?};", const_name, compressed).unwrap();

                // Determine MIME type for HTTP serving
                let mime_type = mime_guess::from_path(path)
                    .first_or_octet_stream()
                    .to_string();

                file_constants.push((path_str.to_string(), const_name, mime_type));
            }
        }
    }

    writeln!(output).unwrap();

    // Generate the static HashMap that maps file paths to (data, mime_type) tuples
    writeln!(output, "pub static BUILTIN_FILES: Lazy<HashMap<&'static str, (&'static [u8], &'static str)>> = Lazy::new(|| {{").unwrap();
    writeln!(output, "    let mut files = HashMap::new();").unwrap();

    // Insert all file mappings into the HashMap
    for (path, const_name, mime_type) in file_constants {
        writeln!(
            output,
            "    files.insert(\"{}\", ({}, \"{}\"));",
            path, const_name, mime_type
        )
        .unwrap();
    }

    writeln!(output, "    files").unwrap();
    writeln!(output, "}});").unwrap();

    output.flush().unwrap();
}

/// Compresses data using gzip compression for smaller binary size.
///
/// Returns the compressed data as a Vec<u8> suitable for embedding
/// in the generated Rust code.
fn compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}
