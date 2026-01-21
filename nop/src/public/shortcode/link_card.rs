// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::Shortcode;
use crate::templates::{TemplateEngine, render_minijinja_template};
use crate::util::color_hsv::increase_saturation;
use minijinja::context;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn generate_title_hash(title: &str) -> (u8, u8, u8) {
    let mut hasher = DefaultHasher::new();
    title.hash(&mut hasher);
    let hash = hasher.finish();

    let byte1 = ((hash >> 16) & 0xFF) as u8;
    let byte2 = ((hash >> 8) & 0xFF) as u8;
    let byte3 = (hash & 0xFF) as u8;

    (byte1 / 5, byte2 / 5, byte3 / 5)
}

fn calculate_background_colors(r: u8, g: u8, b: u8) -> (String, String, String, String) {
    // Light mode: subtract from white
    let light_r = 255 - r;
    let light_g = 255 - g;
    let light_b = 255 - b;

    // Dark mode: add brightness offset then increase saturation by 30%
    const DARK_MODE_OFFSET: u8 = 60;
    const DARK_MODE_SATURATION_FACTOR: f32 = 8.0;

    let (saturated_r, saturated_g, saturated_b) =
        increase_saturation(r, g, b, DARK_MODE_SATURATION_FACTOR);

    let dark_r = saturated_r + DARK_MODE_OFFSET;
    let dark_g = saturated_g + DARK_MODE_OFFSET;
    let dark_b = saturated_b + DARK_MODE_OFFSET;

    // Hover effects: 5% darker/lighter
    let light_hover_r = (light_r as f32 * 0.95) as u8;
    let light_hover_g = (light_g as f32 * 0.95) as u8;
    let light_hover_b = (light_b as f32 * 0.95) as u8;

    // Dark mode hover: move 5% closer to white (255)
    let dark_hover_r = (dark_r as f32 + (255 - dark_r) as f32 * 0.05) as u8;
    let dark_hover_g = (dark_g as f32 + (255 - dark_g) as f32 * 0.05) as u8;
    let dark_hover_b = (dark_b as f32 + (255 - dark_b) as f32 * 0.05) as u8;

    (
        format!("rgb({}, {}, {})", light_r, light_g, light_b),
        format!(
            "rgb({}, {}, {})",
            light_hover_r, light_hover_g, light_hover_b
        ),
        format!("rgb({}, {}, {})", dark_r, dark_g, dark_b),
        format!("rgb({}, {}, {})", dark_hover_r, dark_hover_g, dark_hover_b),
    )
}

pub fn handle_link_card_shortcode(
    shortcode: &Shortcode,
    template_engine: &dyn TemplateEngine,
) -> Result<String, String> {
    let title = shortcode
        .attributes
        .get("title")
        .map(|s| s.as_str())
        .unwrap_or("");
    let link = shortcode
        .attributes
        .get("link")
        .map(|s| s.as_str())
        .unwrap_or("");

    // Check if required attributes are missing and return error
    if title.is_empty() || link.is_empty() {
        return Err("Link card shortcode missing title or link attribute".to_string());
    }

    // Check for noblank parameter - can be present by name or set to "true"
    let noblank = shortcode
        .attributes
        .get("noblank")
        .map(|s| s.as_str() == "true" || s.is_empty()) // Empty means parameter present by name
        .unwrap_or(false);

    // Determine target and rel attributes based on noblank
    let (target_attr, rel_attr) = if noblank {
        (None, Some("noopener noreferrer")) // Keep rel for security, but no target
    } else {
        (Some("_blank"), Some("noopener noreferrer"))
    };

    // Generate color scheme based on title hash
    let (r, g, b) = generate_title_hash(title);
    let (light_bg, light_hover_bg, dark_bg, dark_hover_bg) = calculate_background_colors(r, g, b);

    // Generate unique card ID for CSS classes
    let mut hasher_for_id = DefaultHasher::new();
    format!("{}{}", title, link).hash(&mut hasher_for_id);
    let card_id = format!("{:x}", hasher_for_id.finish());

    // Create context for minijinja template
    let context = context! {
        title => title,
        // SECURITY NOTE: The 'link' attribute is marked as 'safe' to prevent HTML escaping.
        // This allows the website operator to use javascript: URLs and other special schemes if needed.
        // Since this is from trusted operator input, not user-generated content, this is acceptable.
        // Future developers: Be careful if this shortcode is ever exposed to untrusted input!
        link => minijinja::Value::from_safe_string(link.to_string()),
        target_attr => target_attr,
        rel_attr => rel_attr,
        card_id => card_id,
        light_bg => light_bg,
        light_hover_bg => light_hover_bg,
        dark_bg => dark_bg,
        dark_hover_bg => dark_hover_bg
    };

    // Render the link card template with minijinja (title is automatically HTML-escaped)
    render_minijinja_template(template_engine, "public/shortcode/link_card.html", context)
        .map_err(|e| format!("Failed to render link card template: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::MiniJinjaEngine;
    use std::collections::HashMap;

    fn create_shortcode(attributes: HashMap<String, String>) -> Shortcode {
        Shortcode {
            name: "link-card".to_string(),
            attributes,
        }
    }

    fn test_success(shortcode: &Shortcode, templates: &MiniJinjaEngine) -> String {
        handle_link_card_shortcode(shortcode, templates).unwrap()
    }

    fn test_error(shortcode: &Shortcode, templates: &MiniJinjaEngine) -> String {
        handle_link_card_shortcode(shortcode, templates).unwrap_err()
    }

    fn create_templates() -> MiniJinjaEngine {
        MiniJinjaEngine::new()
    }

    #[test]
    fn test_default_behavior_opens_in_new_tab() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        assert!(result.contains(r#"target="_blank""#));
        assert!(result.contains(r#"rel="noopener noreferrer""#));
        assert!(result.contains("Test Title"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_noblank_parameter_by_name() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());
        attrs.insert("noblank".to_string(), "".to_string()); // Present by name only

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        assert!(!result.contains(r#"target="_blank""#));
        assert!(result.contains(r#"rel="noopener noreferrer""#)); // Keep rel for security
        assert!(result.contains("Test Title"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_noblank_parameter_true() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());
        attrs.insert("noblank".to_string(), "true".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        assert!(!result.contains(r#"target="_blank""#));
        assert!(result.contains(r#"rel="noopener noreferrer""#)); // Keep rel for security
        assert!(result.contains("Test Title"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_noblank_parameter_unquoted_true() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());
        attrs.insert("noblank".to_string(), "true".to_string()); // This represents noblank=true (unquoted)

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        assert!(!result.contains(r#"target="_blank""#));
        assert!(result.contains(r#"rel="noopener noreferrer""#)); // Keep rel for security
        assert!(result.contains("Test Title"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_noblank_parameter_false() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());
        attrs.insert("noblank".to_string(), "false".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        assert!(result.contains(r#"target="_blank""#));
        assert!(result.contains(r#"rel="noopener noreferrer""#));
        assert!(result.contains("Test Title"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_noblank_parameter_other_value() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());
        attrs.insert("noblank".to_string(), "something".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        assert!(result.contains(r#"target="_blank""#));
        assert!(result.contains(r#"rel="noopener noreferrer""#));
        assert!(result.contains("Test Title"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_missing_title() {
        let mut attrs = HashMap::new();
        attrs.insert("link".to_string(), "https://example.com".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_error(&shortcode, &templates);

        assert!(result.contains("missing title or link attribute"));
    }

    #[test]
    fn test_missing_link() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_error(&shortcode, &templates);

        assert!(result.contains("missing title or link attribute"));
    }

    #[test]
    fn test_empty_title() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_error(&shortcode, &templates);

        assert!(result.contains("missing title or link attribute"));
    }

    #[test]
    fn test_empty_link() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_error(&shortcode, &templates);

        assert!(result.contains("missing title or link attribute"));
    }

    #[test]
    fn test_generated_colors_and_unique_id() {
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Test Title".to_string());
        attrs.insert("link".to_string(), "https://example.com".to_string());

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        // Should contain CSS with background colors
        assert!(result.contains("background-color: "));
        assert!(result.contains("@media (prefers-color-scheme: dark)"));

        // Should contain a unique class name based on hash
        assert!(result.contains("link-card-"));

        // Generate another with different title to ensure different colors
        let mut attrs2 = HashMap::new();
        attrs2.insert("title".to_string(), "Different Title".to_string());
        attrs2.insert("link".to_string(), "https://example.com".to_string());

        let shortcode2 = create_shortcode(attrs2);
        let result2 = test_success(&shortcode2, &templates);

        // Results should be different (different hashes)
        assert_ne!(result, result2);
    }

    #[test]
    fn test_color_generation_consistency() {
        // Same input should always generate same colors
        let (r1, g1, b1) = generate_title_hash("Test Title");
        let (r2, g2, b2) = generate_title_hash("Test Title");

        assert_eq!(r1, r2);
        assert_eq!(g1, g2);
        assert_eq!(b1, b2);

        // Different input should generate different colors
        let (r3, g3, b3) = generate_title_hash("Different Title");
        assert!((r1, g1, b1) != (r3, g3, b3));
    }

    #[test]
    fn test_exact_user_scenario() {
        // Test the exact scenario the user reported
        let mut attrs = HashMap::new();
        attrs.insert("title".to_string(), "Search".to_string());
        attrs.insert("link".to_string(), "https://duckduckgo.com/".to_string());
        attrs.insert("noblank".to_string(), "".to_string()); // noblank parameter present by name

        let shortcode = create_shortcode(attrs);
        let templates = create_templates();
        let result = test_success(&shortcode, &templates);

        println!("Generated HTML: {}", result);

        // Should NOT contain target="_blank" but should still have rel for security
        assert!(
            !result.contains(r#"target="_blank""#),
            "Should not contain target='_blank' when noblank is present"
        );
        assert!(
            result.contains(r#"rel="noopener noreferrer""#),
            "Should contain rel attribute for security even with noblank"
        );

        // Should contain the title and link
        assert!(result.contains("Search"));
        assert!(result.contains("https://duckduckgo.com/"));

        // Should be well-formed HTML
        assert!(result.contains(r#"<a href="https://duckduckgo.com/""#));
        assert!(result.contains(r#"<p class="title">Search</p>"#));
        assert!(result.contains("</a>"));
    }
}
