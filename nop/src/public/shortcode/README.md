# Shortcode System

> **Note:** The canonical documentation now lives in `docs/public/shortcodes.md`. Keep this README for quick component-level review.

This module implements a lightweight shortcode system for embedding dynamic content in markdown files. Shortcodes provide a way to include rich media and interactive elements while maintaining clean, readable markdown.

## Table of Contents

- [Shortcode Format](#shortcode-format)
- [Built-in Shortcodes](#built-in-shortcodes)
- [Processing Flow](#processing-flow)
- [Template System](#template-system)
- [Error Handling](#error-handling)
- [Adding New Shortcodes](#adding-new-shortcodes)
- [Security Considerations](#security-considerations)

## Shortcode Format

Shortcodes use double parentheses syntax: `((shortcode-name attribute="value"))`

### Basic Syntax

```markdown
((shortcode-name))
((shortcode-name attribute="value"))
((shortcode-name attr1="value1" attr2="value2"))
```

### Attribute Formats

- **Quoted values**: `title="My Title"` - Use for values with spaces or special characters
- **Unquoted values**: `width=640` - Use for simple values without spaces
- **Boolean flags**: `noblank` - Attribute present by name only (value will be empty string)

### Examples

```markdown
((video src="demo.mp4" width="800" height="600"))
((link-card title="GitHub" link="https://github.com" noblank))
((video src=simple.mp4 controls=false))
```

## Built-in Shortcodes

### Dynamic flag

- The registry stores a `dynamic` flag per shortcode so future caching layers can detect handlers that depend on external, runtime-changing data.
- Only mark a handler as dynamic when it relies on something outside Markdown and configuration that was loaded during startup (e.g., databases, external APIs, clocks).
- If the output is fully determined by the shortcode markup and the startup configuration, the handler remains static.
- The flag does not alter the current render or caching behaviour; it is metadata for upcoming features.

### Video Shortcode

Embeds HTML5 video elements with automatic HTML escaping for security.

**Syntax**: `((video src="path" [width="pixels"] [height="pixels"] [controls="true|false"]))`

**Attributes**:
- `src` (required): Video file path
- `width` (optional): Video width in pixels
- `height` (optional): Video height in pixels  
- `controls` (optional): Show video controls. Defaults to `true`. Set to `"false"` to disable.

**Examples**:
```markdown
((video src="demo.mp4"))
((video src="demo.mp4" width="800" height="600"))
((video src="demo.mp4" controls="false"))
```

### Link Card Shortcode

Creates styled link cards with automatic color generation and responsive design.

**Syntax**: `((link-card title="text" link="url" [noblank]))`

**Attributes**:
- `title` (required): Display title for the link
- `link` (required): Target URL (can include javascript: URLs for trusted operator use)
- `noblank` (optional): Prevent opening in new tab. By default, links open in `_blank`

**Examples**:
```markdown
((link-card title="Example Site" link="https://example.com"))
((link-card title="Internal Link" link="/page" noblank))
```

**Current classification:** `video`, `link-card`, and `start-unibox` are registered as static handlers.

## Processing Flow

Shortcode processing is integrated into the markdown rendering pipeline to provide secure, efficient content transformation.

### Overview

```
Markdown File → Parse → Process Events → Generate HTML → Sanitize → Final Output
     ↓              ↓            ↓              ↓           ↓
((shortcodes))  Plain Text  Shortcode Scan  Hash Replace  HTML Restore
```

### Detailed Processing Pipeline

#### 1. **Markdown Parsing** (`src/public/markdown.rs`)

```rust
pub fn generate_html(
    result: &gray_matter::ParsedEntity,
    shortcode_registry: &ShortcodeRegistry,
    options: &Options,
    config: &ValidatedConfig,
    md_path: &str,
) -> String
```

The markdown file is first parsed using `pulldown_cmark` to generate a stream of markdown events.

#### 2. **Event Processing Loop**

For each markdown event:
- **Text events**: Scanned for shortcode syntax `((name attrs))`
- **Link/Image events**: Processed for relative path resolution
- **Other events**: Passed through unchanged

#### 3. **Shortcode Processing** (`process_text_with_shortcodes`)

When shortcodes are found in text:

```rust
// 1. Parse shortcode syntax
let (shortcode, consumed) = parse_shortcode(&text[position..])?;

// 2. Execute handler
let result = registry.process(&shortcode)?;

// 3. Handle result
match result {
    Some(Ok(html)) => {
        // Success: Replace with hash placeholder
        let hash = generate_shortcode_hash(shortcode_text);
        hash_to_html_map.insert(hash.clone(), html);
        processed_text.push_str(&hash);
    }
    Some(Err(_)) => {
        // Error: Keep original shortcode text
        processed_text.push_str(shortcode_text);
    }
    None => {
        // Unknown shortcode: Keep original text
        processed_text.push_str("((");
    }
}
```

#### 4. **HTML Generation**

The processed markdown (with hash placeholders) is converted to HTML:

```rust
let mut html = String::new();
pulldown_cmark::html::push_html(&mut html, processed_events.into_iter());
```

At this point:
- User markdown content is converted to HTML
- Shortcodes are represented as hash placeholders like `SHORTCODE_HASH_a1b2c3d4...`

#### 5. **Hash Replacement** (`replace_shortcode_placeholders`)

Hash placeholders are replaced with actual shortcode HTML:

```rust
for (hash_placeholder, html) in hash_to_html_map {
    result = result.replace(hash_placeholder, html);
}
```

#### 6. **HTML Sanitization** (External to shortcode system)

The final HTML goes through `ammonia` sanitization:
- **User content**: Fully sanitized (removes `<script>`, dangerous attributes, etc.)
- **Shortcode HTML**: Already integrated, so it's preserved as-is
- This provides security while maintaining shortcode functionality

### Integration Points

#### In `src/public/markdown.rs`:

```rust
use crate::public::shortcode::{process_text_with_shortcodes, replace_shortcode_placeholders};

fn generate_html(...) -> String {
    // 1. Process markdown events
    for event in parser {
        match event {
            Event::Text(text) => {
                // Process shortcodes in text content
                let (processed_text, hash_map) = 
                    process_text_with_shortcodes(&text, shortcode_registry);
                processed_events.push(Event::Text(processed_text.into()));
                hash_to_html_map.extend(hash_map);
            }
            // ... other events
        }
    }
    
    // 2. Generate HTML from processed events
    let mut html = String::new();
    pulldown_cmark::html::push_html(&mut html, processed_events.into_iter());
    
    // 3. Replace hash placeholders with shortcode HTML
    html = replace_shortcode_placeholders(&html, &hash_to_html_map);
    
    // 4. Post-process and sanitize (external to shortcodes)
    post_process_html(html, content_dir, md_path)
}
```

### Caching Behavior

**Within a single page**:
- Identical shortcodes share the same hash
- HTML is generated once and reused
- Cache key: complete shortcode text including attributes

```rust
// This appears twice in markdown:
// ((video src="demo.mp4" width="800"))
// ((video src="demo.mp4" width="800"))

// Results in:
// hash_to_html_map = {
//     "SHORTCODE_HASH_abc123": "<video src=\"demo.mp4\" width=\"800\">...</video>"
// }
// Both instances use the same hash
```

### Error Isolation

**Error boundaries**:
- Individual shortcode failures don't affect other shortcodes
- Markdown processing continues even with shortcode errors
- Failed shortcodes preserve original syntax for debugging

**Example behavior**:
```markdown
Working shortcode: ((video src="good.mp4"))
Broken shortcode: ((video))  <!-- Missing src, stays as-is -->
Another working: ((link-card title="Test" link="https://example.com"))
```

Results in:
```html
<p>Working shortcode: <video src="good.mp4" controls>...</video></p>
<p>Broken shortcode: ((video))</p>
<p>Another working: <a href="https://example.com" class="link-card-abc123">...</a></p>
```

### Performance Characteristics

- **Single-pass parsing**: Shortcodes processed during event iteration
- **Hash-based replacement**: O(1) lookup for shortcode HTML
- **Regex-free**: Uses `nom` parser for efficient shortcode syntax parsing
- **Memory efficient**: Hash map only stores unique shortcode renderings

## Template System

Shortcodes use **minijinja** templates for rendering. This provides automatic HTML escaping and clean separation of logic from presentation.

### Template Requirements

All shortcode handlers **MUST**:

1. Use `render_minijinja_template()` for rendering with the injected template engine
2. Return `Result<String, String>` where:
   - `Ok(html)` = successful rendering
   - `Err(message)` = error (original shortcode will be preserved)
3. Provide fallback HTML generation if template loading fails

### Template Usage Example

```rust
use crate::templates::{TemplateEngine, render_minijinja_template};
use minijinja::context;

pub fn handle_my_shortcode(
    shortcode: &Shortcode,
    template_engine: &dyn TemplateEngine,
) -> Result<String, String> {
    let title = shortcode.attributes.get("title").unwrap_or("");
    
    if title.is_empty() {
        return Err("Title attribute is required".to_string());
    }
    
    let context = context! {
        title => title,  // Automatically HTML-escaped
        safe_html => minijinja::Value::from_safe_string("<em>trusted</em>".to_string())
    };
    
    Ok(render_minijinja_template(template_engine, "my_shortcode.html", context)
        .unwrap_or_else(|_| {
            // Fallback if template fails
            format!(r#"<h2>{}</h2>"#, html_escape::encode_text(title))
        }))
}
```

### Template Security

- **Automatic HTML escaping**: All template variables are HTML-escaped by default
- **Safe values**: Use `minijinja::Value::from_safe_string()` only for trusted content
- **Manual escaping**: Use `html_escape::encode_text()` in fallback code

## Error Handling

The shortcode system uses a **graceful degradation** approach:

### Error Behavior

1. **Successful rendering**: Shortcode is replaced with generated HTML
2. **Handler error**: Original shortcode text is preserved in output
3. **Unknown shortcode**: Original shortcode text is preserved in output
4. **Template error**: Fallback HTML generation is used

### Error Return Pattern

```rust
// ✅ Success - shortcode becomes HTML
Ok("<video src=\"demo.mp4\"></video>".to_string())

// ❌ Error - shortcode stays as ((video width="800"))
Err("Video shortcode missing src attribute".to_string())
```

### Why This Approach?

- **User-friendly**: Operators can see exactly which shortcodes need fixing
- **Non-breaking**: Invalid shortcodes don't break page rendering
- **Debuggable**: Original shortcode syntax is preserved for troubleshooting
- **Clean**: No error HTML mixed into content

## Adding New Shortcodes

### 1. Create Handler Function

```rust
pub fn handle_my_shortcode(
    shortcode: &Shortcode,
    template_engine: &dyn TemplateEngine,
) -> Result<String, String> {
    // Validate required attributes
    let required_attr = shortcode.attributes.get("required")
        .ok_or("Missing required attribute")?;
    
    // Optional attributes with defaults
    let optional_attr = shortcode.attributes.get("optional")
        .unwrap_or("default_value");
    
    // Create template context
    let context = context! {
        required_attr => required_attr,
        optional_attr => optional_attr
    };
    
    // Render with fallback
    Ok(render_minijinja_template(template_engine, "shortcode/my_shortcode.html", context)
        .unwrap_or_else(|_| {
            format!(r#"<div>{}</div>"#, html_escape::encode_text(required_attr))
        }))
}
```

### 2. Create Template

Create `src/shortcode/templates/my_shortcode.html`:

```html
<div class="my-shortcode">
    <h3>{{ required_attr }}</h3>
    <p>{{ optional_attr }}</p>
</div>
```

### 3. Register Template

Add to `src/templates.rs`:

```rust
"shortcode/my_shortcode.html" => {
    Some(include_str!("shortcode/templates/my_shortcode.html"))
}
```

### 4. Register Handler

Add to `src/public/shortcode/mod.rs`:

```rust
pub mod my_shortcode;

pub fn create_default_registry(template_engine: Arc<dyn TemplateEngine>) -> ShortcodeRegistry {
    let mut registry = ShortcodeRegistry::new();
    registry.register(
        "my-shortcode",
        move |shortcode| my_shortcode::handle_my_shortcode(shortcode, template_engine.as_ref()),
        false,
    );
    // ... other registrations
    registry
}
```

### 5. Add Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_shortcode_success() {
        let mut attrs = HashMap::new();
        attrs.insert("required".to_string(), "test".to_string());
        
        let shortcode = Shortcode {
            name: "my-shortcode".to_string(),
            attributes: attrs,
        };
        
        let result = handle_my_shortcode(&shortcode).unwrap();
        assert!(result.contains("test"));
    }
    
    #[test]
    fn test_my_shortcode_error() {
        let shortcode = Shortcode {
            name: "my-shortcode".to_string(),
            attributes: HashMap::new(),
        };
        
        let result = handle_my_shortcode(&shortcode);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing required attribute"));
    }
}
```

## Security Considerations

### HTML Escaping

- **Always use minijinja templates** - provides automatic HTML escaping
- **Mark trusted content as safe** - use `Value::from_safe_string()` sparingly
- **Validate inputs** - check attribute values before processing

### Link Safety

The link-card shortcode allows javascript: URLs and other schemes for trusted operator use. This is intentional but requires careful consideration:

```rust
// SECURITY NOTE: The 'link' attribute is marked as 'safe' to prevent HTML escaping.
// This allows the website operator to use javascript: URLs if needed.
// Since this is from trusted operator input, not user-generated content, this is acceptable.
// Future developers: Be careful if this shortcode is ever exposed to untrusted input!
link => minijinja::Value::from_safe_string(link.to_string()),
```

### Content Security Policy

Consider CSP implications when allowing javascript: URLs or inline styles in shortcodes.

### Caching Behavior

- Identical shortcodes are cached and reused within the same page
- Cache keys are based on the complete shortcode text
- Successful renders are cached; errors are not cached

## File Structure

```
src/public/shortcode/
├── README.md              # This documentation
├── mod.rs                 # Main shortcode processing logic
├── video.rs               # Video shortcode handler
├── link_card.rs          # Link card shortcode handler
└── templates/
    ├── video.html         # Video template
    └── link_card.html     # Link card template
```

## Performance Notes

- **Compile-time templates**: Templates embedded using `include_str!` for zero runtime I/O
- **Efficient parsing**: Uses `nom` parser for shortcode syntax (no regex)
- **Hash-based caching**: Identical shortcodes within a page share the same hash and HTML
- **Single-pass processing**: Shortcodes processed during markdown event iteration
- **Graceful degradation**: Failed shortcodes don't impact page rendering performance
- **Memory efficiency**: Hash map only stores unique shortcode renderings per page 

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
