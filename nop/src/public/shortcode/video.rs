// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::Shortcode;
use crate::templates::{TemplateEngine, render_minijinja_template};
use minijinja::context;

/// Video shortcode handler that generates HTML5 video elements
///
/// Supports attributes:
/// - src (required): Video file path
/// - width (optional): Video width in pixels
/// - height (optional): Video height in pixels
/// - controls (optional): Show video controls. Defaults to true. Set to "false" to disable.
///
/// Example usage:
/// ```text
/// ((video src="demo.mp4" width="800" height="600"))
/// ((video src="demo.mp4" controls="true"))
/// ((video src="demo.mp4" controls="false"))
/// ```
///
/// Generated HTML:
/// ```html
/// <video src="demo.mp4" width="800" height="600" controls>
///   Your browser does not support the video tag.
/// </video>
/// ```
pub fn handle_video_shortcode(
    shortcode: &Shortcode,
    template_engine: &dyn TemplateEngine,
) -> Result<String, String> {
    let src = shortcode
        .attributes
        .get("src")
        .map(|s| s.as_str())
        .unwrap_or("");

    // Check if src is missing and return error
    if src.is_empty() {
        return Err("Video shortcode missing src attribute".to_string());
    }

    // Get optional width and height attributes
    let width = shortcode.attributes.get("width").map(|s| s.as_str());
    let height = shortcode.attributes.get("height").map(|s| s.as_str());

    // Determine if controls should be shown (default: true, disable with "false")
    let controls = !matches!(
        shortcode.attributes.get("controls").map(|s| s.as_str()),
        Some("false")
    );

    // Render the video template with minijinja (attributes are automatically HTML-escaped)
    let context = context! {
        src => src,
        width => width,
        height => height,
        controls => controls
    };

    match render_minijinja_template(template_engine, "public/shortcode/video.html", context) {
        Ok(html) => Ok(html),
        Err(e) => {
            log::error!("Failed to render video shortcode template: {}", e);
            Err(format!("Failed to render video shortcode: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::MiniJinjaEngine;
    use std::collections::HashMap;

    fn create_test_shortcode(attributes: HashMap<String, String>) -> Shortcode {
        Shortcode {
            name: "video".to_string(),
            attributes,
        }
    }

    #[test]
    fn test_video_with_all_attributes() {
        let mut attrs = HashMap::new();
        attrs.insert("src".to_string(), "test.mp4".to_string());
        attrs.insert("width".to_string(), "800".to_string());
        attrs.insert("height".to_string(), "600".to_string());
        attrs.insert("controls".to_string(), "true".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_video_shortcode(&shortcode, &templates).unwrap();

        assert!(result.contains(r#"src="test.mp4""#));
        assert!(result.contains(r#"width="800""#));
        assert!(result.contains(r#"height="600""#));
        assert!(result.contains("controls"));
    }

    #[test]
    fn test_video_missing_src() {
        let mut attrs = HashMap::new();
        attrs.insert("width".to_string(), "800".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_video_shortcode(&shortcode, &templates);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing src attribute"));
    }

    #[test]
    fn test_video_minimal() {
        let mut attrs = HashMap::new();
        attrs.insert("src".to_string(), "minimal.mp4".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_video_shortcode(&shortcode, &templates).unwrap();

        assert!(result.contains(r#"src="minimal.mp4""#));
        assert!(result.contains("controls")); // Default controls
        assert!(!result.contains("width=")); // No width specified
        assert!(!result.contains("height=")); // No height specified
    }

    #[test]
    fn test_video_controls_false() {
        let mut attrs = HashMap::new();
        attrs.insert("src".to_string(), "no-controls.mp4".to_string());
        attrs.insert("controls".to_string(), "false".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_video_shortcode(&shortcode, &templates).unwrap();

        assert!(result.contains(r#"src="no-controls.mp4""#));
        assert!(!result.contains(" controls"));
    }

    #[test]
    fn test_video_controls_true() {
        let mut attrs = HashMap::new();
        attrs.insert("src".to_string(), "with-controls.mp4".to_string());
        attrs.insert("controls".to_string(), "true".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_video_shortcode(&shortcode, &templates).unwrap();

        assert!(result.contains(r#"src="with-controls.mp4""#));
        assert!(result.contains(" controls"));
    }

    #[test]
    fn test_video_controls_debug() {
        let mut attrs = HashMap::new();
        attrs.insert("src".to_string(), "debug.mp4".to_string());

        let shortcode = create_test_shortcode(attrs);
        let templates = MiniJinjaEngine::new();
        let result = handle_video_shortcode(&shortcode, &templates).unwrap();

        println!("Raw video shortcode output: '{}'", result);
        assert!(result.contains(r#"src="debug.mp4""#));
        assert!(result.contains(" controls"));
        assert!(!result.contains(r#"controls="""#));
        assert!(!result.contains(r#"controls="true""#));
        assert!(!result.contains(r#"controls="false""#));
    }
}
