# Shortcode System

Status: Developed

## Objectives

- Define shortcode syntax, parsing, and rendering behavior.
- Document built-in handlers and extension workflow.
- Specify updated requirements for tag-based listing shortcodes.

## Technical Details

### Syntax and Parsing

- Delimiter: double parentheses `(( ... ))`.
- Names accept alphanumeric, `_`, and `-` characters. Example: `((video))`, `((link-card))`.
- Attributes:
  - Key/value (`width=640`, `label="Search here"`).
  - Boolean flags with no value (`blank`).
- Parser lives in `public/shortcode/mod.rs` using `nom`. `parse_shortcode` returns the consumed byte count so the renderer can continue scanning the string.
- During rendering:
  1. `process_text_with_shortcodes` scans Markdown text, parsing any shortcodes.
  2. Rendered HTML is cached against a SHA-512 placeholder (`SHORTCODE_HASH_*`) to avoid double rendering.
  3. Markdown conversion proceeds as normal; placeholders survive sanitization.
  4. `replace_shortcode_placeholders` swaps hashes back to HTML in the final string.
- Unknown shortcodes remain unchanged so editors can spot typos. Handler errors leave the original shortcode intact and log a debug message.
- Identical shortcodes within the same document share the same placeholder hash so HTML is rendered once and reused.

### Built-in Shortcodes

Handlers register in `create_default_registry_with_config`; they must be thread-safe closures returning `Result<String, String>`.

#### Dynamic vs. static registration

- Each registration records a `dynamic` flag so future cache/version tracking can spot handlers that rely on changing external data.
- Mark a shortcode as dynamic only when it depends on information beyond Markdown and configuration that was loaded at startup (for example, it uses content metadata at render time).
- Handlers whose output is determined entirely by Markdown plus startup-time configuration are static.
- The flag is metadata only; current render behavior and within-page caching are unchanged.

#### `start-unibox`

- Config-aware handler (`unibox::handle_start_unibox_shortcode`) that renders a universal search or URL box.
- Attributes:
  - `label`: placeholder text (defaults to `"Enter a URL or search term..."`).
  - `search`: custom search URL containing `<QUERY>` (falls back to `config.shortcodes.start_unibox`).
  - `blank`: flag to open results in a new tab.
- Uses MiniJinja template `public/shortcode/start_unibox.html` and injects a unique element ID for JS bindings.

#### `video`

- Renders an HTML5 `<video>` tag with optional width/height/controls.
- Requires `src`. Optional attributes: `width`, `height`, `controls` (default `true`; set to `"false"` to hide controls).
- Sanitizes attributes and refuses to render when required fields are missing.

#### `link-card`

- Produces a Bulma-styled card linking to an external or internal URL.
- Attributes:
  - `title` (required).
  - `link` (required).
  - `noblank` (optional flag; default opens `_blank`).
- Auto-generates background gradients using helpers in `util::color_hsv`.

**Current classification:** `start-unibox`, `video`, and `link-card` are all registered as static.

### Tag List Shortcode

Introduce a `tag-list` shortcode that renders an HTML list of pages matching tag criteria. This replaces directory-based listings for tag-driven pages.

- Name: `tag-list`.
- Syntax: `((tag-list ...))`.
- Attributes:
  - Exactly one of `tags`, `or`, or `and` must be provided.
  - `tags` and `or` are OR lists (synonyms).
  - `and` is an AND list.
  - `limit` is optional; when absent, render all matches.
- List parsing:
  - Lists are comma-separated.
  - Whitespace is ignored around commas.
  - Tag IDs must use the tag ID charset rules (lowercase letters, numbers, dashes, underscores, slashes).

Examples:

```
((tag-list tags="docs,getting-started" limit=20))
((tag-list or="news,blog"))
((tag-list and="internal,private" limit=10))
```

Rendering rules:

- The shortcode must use the existing HTML listing style (reuse listing generation helpers).
- Matches are filtered by access rules before rendering.
- Register this shortcode as dynamic because it depends on content metadata.

### Templating and Assets

- Shortcode templates live in `public/shortcode/templates/`.
- Rendering uses `templates::render_minijinja_template`, which enforces escaping before HTML insertion.
- Any static JS/CSS needed by shortcodes must be packaged in `nop/builtin/` so release builds embed them automatically.

### Extension Workflow

1. Implement a handler returning `Result<String, String>`; keep logic deterministic and side-effect free.
2. If the shortcode needs repository configuration, capture `ValidatedConfig` via a closure when registering (see `start-unibox` example).
3. Add any templates under `public/shortcode/templates/` and load them via MiniJinja in the handler.
4. Register the handler in `create_default_registry_with_config`.
5. Write parser and handler tests in `shortcode/mod.rs` or the new module. Existing tests cover parsing, caching, and error propagation.
6. Update docs to describe usage so authors know the supported attributes.

### Safety Considerations

- Sanitization: Markdown output is cleaned by `ammonia` before placeholders are reinserted, so shortcode HTML must already be safe. Prefer MiniJinja with auto-escaping.
- Error handling: returning `Err(String)` logs context while leaving source Markdown unchanged - no panic paths.
- Configuration: Validate URLs and required attributes (for example, `start-unibox` enforces `<QUERY>` placeholder and `http(s)://` schemes).
- Performance: Hash caching prevents duplicate parse/execute cycles for repeated identical shortcodes within one document.
- Debugging: because failed or unknown shortcodes render verbatim, editors can immediately locate and correct the offending markup.
- See also `nop/src/public/shortcode/README.md` for module-local examples and handler templates.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
