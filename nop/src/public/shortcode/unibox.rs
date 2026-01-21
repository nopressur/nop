// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::Shortcode;
use crate::config::ValidatedConfig;
use crate::templates::{TemplateEngine, render_minijinja_template};
use minijinja::context;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Start-unibox shortcode handler that generates a universal input box
///
/// This shortcode creates a text input that can handle both URLs and search queries.
/// It detects if the input looks like a URL and either navigates to it or searches for it.
///
/// Supported attributes:
/// - label: Custom placeholder text (optional, defaults to "Enter a URL or search term...")
/// - search: Custom search URL with <QUERY> placeholder (optional, overrides config)
/// - blank: Flag to open in new tab (optional, defaults to same tab)
///
/// Example usage:
/// ```text
/// ((start-unibox))
/// ((start-unibox label="Search or go to site"))
/// ((start-unibox search="https://google.com/search?q=<QUERY>"))
/// ((start-unibox label="My search" search="https://bing.com/search?q=<QUERY>" blank))
/// ```
///
/// Generated HTML:
/// Contains a styled input box with JavaScript that:
/// - Focuses automatically when rendered
/// - Detects URL-like input and normalizes it
/// - Uses configured or custom search URL for non-URL input
/// - Opens in same tab by default, new tab if 'blank' attribute is present
pub fn handle_start_unibox_shortcode(
    shortcode: &Shortcode,
    config: &ValidatedConfig,
    template_engine: &dyn TemplateEngine,
) -> Result<String, String> {
    // Generate a unique ID for this instance
    let mut hasher = DefaultHasher::new();
    "start-unibox".hash(&mut hasher);
    // Add some randomness based on shortcode attributes
    format!("{:?}", shortcode.attributes).hash(&mut hasher);
    let box_id = format!("unibox_{:x}", hasher.finish());

    // Get the label (placeholder text)
    let label = shortcode
        .attributes
        .get("label")
        .map(|s| s.as_str())
        .unwrap_or("Enter a URL or search term...");

    // Get the search URL - either from shortcode attribute or config
    let search_url = if let Some(custom_search) = shortcode.attributes.get("search") {
        // Validate custom search URL has <QUERY> placeholder
        if !custom_search.contains("<QUERY>") {
            return Err("Custom search URL must contain '<QUERY>' placeholder".to_string());
        }

        // Validate it's a proper URL format
        if !custom_search.starts_with("http://") && !custom_search.starts_with("https://") {
            return Err(
                "Custom search URL must be a fully qualified URL starting with http:// or https://"
                    .to_string(),
            );
        }

        custom_search.as_str()
    } else {
        &config.shortcodes.start_unibox
    };

    // Check for 'blank' attribute (opens in new tab if present)
    let open_in_new_tab = shortcode.attributes.contains_key("blank");

    // Create context for minijinja template
    let context = context! {
        box_id => box_id,
        label => label,
        search_url => search_url,
        open_in_new_tab => open_in_new_tab
    };

    // Render the start-unibox template with minijinja
    render_minijinja_template(
        template_engine,
        "public/shortcode/start_unibox.html",
        context,
    )
    .map_err(|e| format!("Failed to render start-unibox template: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::MiniJinjaEngine;
    use crate::util::test_config::test_config;
    use std::collections::HashMap;

    fn create_test_shortcode(attributes: HashMap<String, String>) -> Shortcode {
        Shortcode {
            name: "start-unibox".to_string(),
            attributes,
        }
    }

    #[test]
    fn test_start_unibox_basic() {
        let config = test_config();
        let shortcode = create_test_shortcode(HashMap::new());
        let templates = MiniJinjaEngine::new();
        let result = handle_start_unibox_shortcode(&shortcode, &config, &templates).unwrap();

        // Should contain a unique box ID
        assert!(result.contains("unibox_"));

        // Should contain the default search URL (JSON-escaped version)
        assert!(result.contains("https://duckduckgo.com?q=\\u003cQUERY\\u003e"));

        // Should contain input element
        assert!(result.contains("<input"));

        // Should contain default placeholder
        assert!(result.contains("Enter a URL or search term..."));

        // Should contain JavaScript
        assert!(result.contains("<script>"));

        // Should default to same tab (not new tab)
        assert!(result.contains("openInNewTab = false"));
    }

    #[test]
    fn test_start_unibox_custom_label() {
        let config = test_config();
        let mut attrs = HashMap::new();
        attrs.insert("label".to_string(), "My custom search".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_start_unibox_shortcode(&shortcode, &config, &templates).unwrap();

        // Should contain the custom label
        assert!(result.contains("My custom search"));
        assert!(!result.contains("Enter a URL or search term..."));
    }

    #[test]
    fn test_start_unibox_custom_search_url() {
        let config = test_config();
        let mut attrs = HashMap::new();
        attrs.insert(
            "search".to_string(),
            "https://google.com/search?q=<QUERY>".to_string(),
        );

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_start_unibox_shortcode(&shortcode, &config, &templates).unwrap();

        // Should contain the custom search URL (JSON-escaped)
        assert!(result.contains("https://google.com/search?q=\\u003cQUERY\\u003e"));
        // Should not contain the default search URL
        assert!(!result.contains("https://duckduckgo.com?q=\\u003cQUERY\\u003e"));
    }

    #[test]
    fn test_start_unibox_blank_attribute() {
        let config = test_config();
        let mut attrs = HashMap::new();
        attrs.insert("blank".to_string(), "".to_string()); // Present by name

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_start_unibox_shortcode(&shortcode, &config, &templates).unwrap();

        // Should open in new tab when blank attribute is present
        assert!(result.contains("openInNewTab = true"));
    }

    #[test]
    fn test_start_unibox_all_attributes() {
        let config = test_config();
        let mut attrs = HashMap::new();
        attrs.insert("label".to_string(), "Search or go".to_string());
        attrs.insert(
            "search".to_string(),
            "https://bing.com/search?q=<QUERY>".to_string(),
        );
        attrs.insert("blank".to_string(), "".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_start_unibox_shortcode(&shortcode, &config, &templates).unwrap();

        // Should contain custom label
        assert!(result.contains("Search or go"));
        // Should contain custom search URL (JSON-escaped)
        assert!(result.contains("https://bing.com/search?q=\\u003cQUERY\\u003e"));
        // Should open in new tab
        assert!(result.contains("openInNewTab = true"));
    }

    #[test]
    fn test_start_unibox_invalid_search_url_no_query() {
        let config = test_config();
        let mut attrs = HashMap::new();
        attrs.insert(
            "search".to_string(),
            "https://google.com/search".to_string(),
        );

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_start_unibox_shortcode(&shortcode, &config, &templates);

        // Should return error for missing <QUERY> placeholder
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("must contain '<QUERY>' placeholder")
        );
    }

    #[test]
    fn test_start_unibox_invalid_search_url_not_http() {
        let config = test_config();
        let mut attrs = HashMap::new();
        attrs.insert(
            "search".to_string(),
            "ftp://example.com?q=<QUERY>".to_string(),
        );

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_start_unibox_shortcode(&shortcode, &config, &templates);

        // Should return error for non-http(s) URL
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("must be a fully qualified URL starting with http")
        );
    }
}
