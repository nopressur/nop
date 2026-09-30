// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use log::{debug, error, warn};
use nop_rt_paths::RuntimePaths;
use nop_rt_security as security;
use std::collections::BTreeMap;
use std::time::SystemTime;
use tokio::fs;

pub(super) async fn load_theme_content(
    runtime_paths: &RuntimePaths,
    theme: Option<&str>,
    release_hex: &str,
) -> String {
    let now = SystemTime::now();
    log::debug!("Loading theme content at {:?}", now);

    // Determine which theme to load
    let theme_name_str = if let Some(theme_name_opt) = theme {
        if theme_name_opt.is_empty() {
            log::warn!("Empty theme name specified, using default theme");
            "default"
        } else {
            theme_name_opt
        }
    } else {
        "default"
    };

    let themes_dir_str = runtime_paths.themes_dir.to_string_lossy();

    // Attempt to load the requested theme
    let mut theme_path = runtime_paths.themes_dir.clone();
    theme_path.push(format!("{}.theme", theme_name_str));

    match security::canonical_path_checks(&theme_path, &themes_dir_str, None) {
        Ok(canonical_theme_path) => {
            match fs::read_to_string(&canonical_theme_path).await {
                Ok(content) => {
                    let theme_content = build_theme_content(&content, theme_name_str, release_hex);
                    debug!(
                        "Successfully loaded theme '{}': {} ({} bytes) at {:?}",
                        theme_name_str,
                        canonical_theme_path.display(),
                        content.len(),
                        now
                    );
                    return theme_content;
                }
                Err(e) => {
                    if theme_name_str != "default" {
                        warn!(
                            "Could not load theme '{}' from {}: {}, falling back to default theme",
                            theme_name_str,
                            canonical_theme_path.display(),
                            e
                        );
                        // Fall through to default theme loading
                    } else {
                        error!(
                            "Could not load default theme '{}' from {}: {}, using fallback theme",
                            theme_name_str,
                            canonical_theme_path.display(),
                            e
                        );
                        return get_fallback_theme();
                    }
                }
            }
        }
        Err(_) => {
            // canonical_path_checks failed
            if theme_name_str != "default" {
                warn!(
                    "Invalid path for theme '{}' ({}), falling back to default theme",
                    theme_name_str,
                    theme_path.display()
                );
                // Fall through to default theme loading
            } else {
                error!(
                    "Invalid path for default theme '{}' ({}), using fallback theme",
                    theme_name_str,
                    theme_path.display()
                );
                return get_fallback_theme();
            }
        }
    }

    // Fallback to default theme if initial load failed (and it wasn't default already)
    // or if canonical_path_checks failed for the requested theme
    debug!("Attempting to load default theme as fallback.");
    let mut default_theme_path = runtime_paths.themes_dir.clone();
    default_theme_path.push("default.theme");

    match security::canonical_path_checks(&default_theme_path, &themes_dir_str, None) {
        Ok(canonical_default_path) => match fs::read_to_string(&canonical_default_path).await {
            Ok(content) => {
                let theme_content = build_theme_content(&content, "default", release_hex);
                debug!(
                    "Successfully loaded default theme: {} ({} bytes) at {:?}",
                    canonical_default_path.display(),
                    content.len(),
                    now
                );
                theme_content
            }
            Err(e) => {
                error!(
                    "Could not load default theme from {}: {}, using fallback theme",
                    canonical_default_path.display(),
                    e
                );
                get_fallback_theme()
            }
        },
        Err(_) => {
            // canonical_path_checks failed for default theme
            error!(
                "Invalid path for default theme file ({}), using fallback theme",
                default_theme_path.display()
            );
            get_fallback_theme()
        }
    }
}

fn get_fallback_theme() -> String {
    // Minimal fallback theme in case the theme file cannot be loaded
    "    <style>\
        body {\
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;\
            background-color: #f5f7fa;\
            color: #363636;\
        }\
        .main-container {\
            min-height: 100vh;\
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);\
        }\
        .content-wrapper {\
            padding: 0 0 2rem;\
        }\
        .content {\
            color: #363636;\
            padding: 2rem;\
            margin: 1rem 0;\
        }\
        .navbar {\
            background: transparent !important;\
        }\
        .navbar-brand .navbar-item {\
            color: #363636 !important;\
        }\
    </style>"
        .to_string()
}

fn build_theme_content(theme_file: &str, theme_name: &str, release_hex: &str) -> String {
    let parsed = parse_theme_file(theme_file, theme_name);
    let preset_href = format!("/builtin/theme-preset.css?v={}", release_hex);
    let mut content = String::new();
    content.push_str(&format!(
        "<link rel=\"stylesheet\" href=\"{}\">",
        preset_href
    ));
    content.push_str("\n<style>\n");
    for font_face in parsed.font_faces {
        write_font_face_rule(&mut content, &font_face, release_hex);
    }
    content.push_str(":root {\n");
    for (key, value) in parsed.variables {
        content.push_str("    --");
        content.push_str(&key);
        content.push_str(": ");
        content.push_str(&value);
        content.push_str(";\n");
    }
    content.push_str("}\n</style>\n");
    content
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTheme {
    variables: Vec<(String, String)>,
    font_faces: Vec<FontFaceRule>,
}

#[derive(Debug, Clone, Default)]
struct FontFaceDraft {
    first_line: usize,
    family: Option<String>,
    src: Option<String>,
    weight: Option<String>,
    style: Option<String>,
    display: Option<String>,
    unicode_range: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FontFaceRule {
    family: String,
    src: String,
    weight: Option<String>,
    style: Option<String>,
    display: Option<String>,
    unicode_range: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FontFaceField {
    Family,
    Src,
    Weight,
    Style,
    Display,
    UnicodeRange,
}

fn parse_theme_file(theme_file: &str, theme_name: &str) -> ParsedTheme {
    let mut variables = Vec::new();
    let mut font_face_drafts: BTreeMap<String, FontFaceDraft> = BTreeMap::new();
    for (line_number, raw_line) in theme_file.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_whitespace());
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if key.is_empty() || value.is_empty() {
            warn!(
                "Skipping invalid theme line {} for '{}': {}",
                line_number + 1,
                theme_name,
                raw_line
            );
            continue;
        }
        if !is_valid_theme_key(key) {
            warn!(
                "Skipping invalid theme key on line {} for '{}': {}",
                line_number + 1,
                theme_name,
                key
            );
            continue;
        }

        if let Some((slot, field)) = parse_font_face_key(key) {
            let draft = font_face_drafts
                .entry(slot.to_string())
                .or_insert_with(|| FontFaceDraft {
                    first_line: line_number + 1,
                    ..Default::default()
                });
            apply_font_face_field(draft, field, value.to_string());
            continue;
        }

        if key.starts_with("font-face-") {
            warn!(
                "Skipping unknown font-face directive on line {} for '{}': {}",
                line_number + 1,
                theme_name,
                key
            );
            continue;
        }

        variables.push((key.to_string(), value.to_string()));
    }

    let font_faces = font_face_drafts
        .into_iter()
        .filter_map(|(slot, draft)| validate_font_face_draft(theme_name, &slot, draft))
        .collect();

    if variables.is_empty() {
        warn!("Theme '{}' contained no usable variables", theme_name);
    }

    ParsedTheme {
        variables,
        font_faces,
    }
}

#[cfg(test)]
fn parse_theme_variables(theme_file: &str, theme_name: &str) -> Vec<(String, String)> {
    parse_theme_file(theme_file, theme_name).variables
}

fn is_valid_theme_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn parse_font_face_key(key: &str) -> Option<(&str, FontFaceField)> {
    let remainder = key.strip_prefix("font-face-")?;
    for (suffix, field) in [
        ("-unicode-range", FontFaceField::UnicodeRange),
        ("-display", FontFaceField::Display),
        ("-family", FontFaceField::Family),
        ("-style", FontFaceField::Style),
        ("-weight", FontFaceField::Weight),
        ("-src", FontFaceField::Src),
    ] {
        if let Some(slot) = remainder.strip_suffix(suffix)
            && is_valid_theme_key(slot)
        {
            return Some((slot, field));
        }
    }
    None
}

fn apply_font_face_field(draft: &mut FontFaceDraft, field: FontFaceField, value: String) {
    match field {
        FontFaceField::Family => draft.family = Some(value),
        FontFaceField::Src => draft.src = Some(value),
        FontFaceField::Weight => draft.weight = Some(value),
        FontFaceField::Style => draft.style = Some(value),
        FontFaceField::Display => draft.display = Some(value),
        FontFaceField::UnicodeRange => draft.unicode_range = Some(value),
    }
}

fn validate_font_face_draft(
    theme_name: &str,
    slot: &str,
    draft: FontFaceDraft,
) -> Option<FontFaceRule> {
    let Some(family) = draft.family else {
        warn!(
            "Skipping font-face '{}' for '{}' from line {}: missing family",
            slot, theme_name, draft.first_line
        );
        return None;
    };
    let Some(src) = draft.src else {
        warn!(
            "Skipping font-face '{}' for '{}' from line {}: missing src",
            slot, theme_name, draft.first_line
        );
        return None;
    };
    if !is_safe_css_descriptor_value(&family) {
        warn!(
            "Skipping font-face '{}' for '{}' from line {}: invalid family",
            slot, theme_name, draft.first_line
        );
        return None;
    }
    if let Err(err) = validate_font_src_path(&src) {
        warn!(
            "Skipping font-face '{}' for '{}' from line {}: {}",
            slot, theme_name, draft.first_line, err
        );
        return None;
    }

    for value in [
        draft.weight.as_deref(),
        draft.style.as_deref(),
        draft.display.as_deref(),
        draft.unicode_range.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !is_safe_css_descriptor_value(value) {
            warn!(
                "Skipping font-face '{}' for '{}' from line {}: invalid descriptor value",
                slot, theme_name, draft.first_line
            );
            return None;
        }
    }

    Some(FontFaceRule {
        family,
        src,
        weight: draft.weight,
        style: draft.style,
        display: draft.display,
        unicode_range: draft.unicode_range,
    })
}

fn validate_font_src_path(src: &str) -> Result<(), &'static str> {
    let trimmed = src.trim();
    if trimmed != src || trimmed.is_empty() {
        return Err("font src must be a non-empty public path");
    }
    if !trimmed.starts_with('/') || trimmed.starts_with("//") {
        return Err("font src must be a same-origin absolute path");
    }
    if trimmed.contains('\\') {
        return Err("font src must not contain backslashes");
    }
    if trimmed.contains('#') {
        return Err("font src must not contain a fragment");
    }
    if trimmed.chars().any(|ch| ch.is_control()) {
        return Err("font src must not contain control characters");
    }
    if trimmed.contains('"') || trimmed.contains('\'') || trimmed.contains(')') {
        return Err("font src contains unsupported URL characters");
    }

    let path = trimmed.split_once('?').map_or(trimmed, |(path, _)| path);
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("font src must not contain dot segments");
    }

    let lower = path.to_ascii_lowercase();
    for reserved in [
        "/admin",
        "/api",
        "/builtin",
        "/csrf-token-api",
        "/login",
        "/theme",
    ] {
        if lower == reserved || lower.starts_with(&format!("{reserved}/")) {
            return Err("font src must point to public content");
        }
    }

    if let Some(id_hex) = lower.strip_prefix("/id/")
        && (id_hex.len() != 16 || !id_hex.chars().all(|ch| ch.is_ascii_hexdigit()))
    {
        return Err("font id src must be /id/<16-hex>");
    }

    Ok(())
}

fn is_safe_css_descriptor_value(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed == value
        && !trimmed
            .chars()
            .any(|ch| ch.is_control() || ch == ';' || ch == '{' || ch == '}')
}

fn write_font_face_rule(content: &mut String, rule: &FontFaceRule, release_hex: &str) {
    content.push_str("@font-face {\n");
    content.push_str("    font-family: \"");
    content.push_str(&escape_css_string(&rule.family));
    content.push_str("\";\n");
    content.push_str("    src: url(\"");
    content.push_str(&escape_css_url(&cache_busted_font_src(
        &rule.src,
        release_hex,
    )));
    content.push_str("\");\n");
    if let Some(weight) = rule.weight.as_ref() {
        write_font_face_descriptor(content, "font-weight", weight);
    }
    if let Some(style) = rule.style.as_ref() {
        write_font_face_descriptor(content, "font-style", style);
    }
    if let Some(display) = rule.display.as_ref() {
        write_font_face_descriptor(content, "font-display", display);
    }
    if let Some(unicode_range) = rule.unicode_range.as_ref() {
        write_font_face_descriptor(content, "unicode-range", unicode_range);
    }
    content.push_str("}\n");
}

fn write_font_face_descriptor(content: &mut String, name: &str, value: &str) {
    content.push_str("    ");
    content.push_str(name);
    content.push_str(": ");
    content.push_str(value);
    content.push_str(";\n");
}

fn cache_busted_font_src(src: &str, release_hex: &str) -> String {
    if src.contains('?') {
        format!("{src}&v={release_hex}")
    } else {
        format!("{src}?v={release_hex}")
    }
}

fn escape_css_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_css_url(value: &str) -> String {
    escape_css_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_font_face_groups_and_keeps_regular_variables() {
        let parsed = parse_theme_file(
            r#"
font-face-body-family Inter
font-face-body-src /fonts/inter.woff2
font-face-body-weight 100 900
font-face-body-style normal
font-face-body-display swap
font-face-body-unicode-range U+000-5FF
font-body-family "Inter", system-ui, sans-serif
"#,
            "test",
        );

        assert_eq!(
            parsed.variables,
            vec![(
                "font-body-family".to_string(),
                "\"Inter\", system-ui, sans-serif".to_string()
            )]
        );
        assert_eq!(parsed.font_faces.len(), 1);
        let rule = &parsed.font_faces[0];
        assert_eq!(rule.family, "Inter");
        assert_eq!(rule.src, "/fonts/inter.woff2");
        assert_eq!(rule.weight.as_deref(), Some("100 900"));
        assert_eq!(rule.style.as_deref(), Some("normal"));
        assert_eq!(rule.display.as_deref(), Some("swap"));
        assert_eq!(rule.unicode_range.as_deref(), Some("U+000-5FF"));
    }

    #[test]
    fn parses_multiple_font_slots_for_one_family() {
        let parsed = parse_theme_file(
            r#"
font-face-inter-regular-family Inter
font-face-inter-regular-src /fonts/inter-regular.woff2
font-face-inter-regular-weight 400
font-face-inter-bold-family Inter
font-face-inter-bold-src /fonts/inter-bold.woff2
font-face-inter-bold-weight 700
"#,
            "test",
        );

        assert_eq!(parsed.font_faces.len(), 2);
        assert_eq!(parsed.font_faces[0].src, "/fonts/inter-bold.woff2");
        assert_eq!(parsed.font_faces[1].src, "/fonts/inter-regular.woff2");
    }

    #[test]
    fn skips_font_face_groups_missing_required_fields() {
        let parsed = parse_theme_file(
            r#"
font-face-no-src-family Inter
font-face-no-family-src /fonts/inter.woff2
color-text-primary-light #111
"#,
            "test",
        );

        assert!(parsed.font_faces.is_empty());
        assert_eq!(
            parsed.variables,
            vec![("color-text-primary-light".to_string(), "#111".to_string())]
        );
    }

    #[test]
    fn rejects_invalid_font_src_values() {
        for src in [
            "https://example.com/font.woff2",
            "//example.com/font.woff2",
            "/fonts/../font.woff2",
            "/builtin/font.woff2",
            "/id/not-hex",
            "/fonts/font.woff2#frag",
            "/fonts\\font.woff2",
        ] {
            assert!(validate_font_src_path(src).is_err(), "{src}");
        }

        assert!(validate_font_src_path("/fonts/inter.woff2").is_ok());
        assert!(validate_font_src_path("/id/0123456789abcdef").is_ok());
    }

    #[test]
    fn font_face_invalid_group_does_not_drop_valid_group_or_variables() {
        let parsed = parse_theme_file(
            r#"
font-face-good-family Good
font-face-good-src /fonts/good.woff2
font-face-bad-family Bad
font-face-bad-src /fonts/../bad.woff2
font-body-size 18px
"#,
            "test",
        );

        assert_eq!(parsed.font_faces.len(), 1);
        assert_eq!(parsed.font_faces[0].family, "Good");
        assert_eq!(
            parsed.variables,
            vec![("font-body-size".to_string(), "18px".to_string())]
        );
    }

    #[test]
    fn backward_compatible_variable_parsing_skips_reserved_unknown_directives() {
        let variables = parse_theme_variables(
            r#"
font-face-body-unknown value
custom-variable ok
"#,
            "test",
        );

        assert_eq!(
            variables,
            vec![("custom-variable".to_string(), "ok".to_string())]
        );
    }

    #[test]
    fn theme_snippet_orders_preset_font_faces_and_variables() {
        let html = build_theme_content(
            r#"
font-face-body-family Inter
font-face-body-src /fonts/inter.woff2
font-face-body-weight 400
font-body-family "Inter", sans-serif
"#,
            "test",
            "abc123",
        );

        let preset = html.find("/builtin/theme-preset.css?v=abc123").unwrap();
        let font_face = html.find("@font-face").unwrap();
        let root = html.find(":root").unwrap();
        assert!(preset < font_face);
        assert!(font_face < root);
        assert!(html.contains("font-family: \"Inter\";"));
        assert!(html.contains("src: url(\"/fonts/inter.woff2?v=abc123\");"));
        assert!(html.contains("font-weight: 400;"));
        assert!(html.contains("--font-body-family: \"Inter\", sans-serif;"));
    }
}
