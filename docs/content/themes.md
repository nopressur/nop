# Themes

Status: Developed

## Objectives

- Move public theming to variable-only theme files with a built-in preset stylesheet.
- Keep theme files simple (one key/value per line) while preserving light/dark palettes.
- Provide a single, canonical reference for the theme format, variables, and built-in palettes.

## Technical Details

### Theme Storage and Selection

- Theme files live under `<runtime-root>/themes/` with the `.theme` extension.
- `theme` in the content sidecar selects `<runtime-root>/themes/<theme>.theme`.
- An empty or missing `theme` selects `default.theme`.
- Theme loading enforces canonical path checks and falls back to `default.theme`, then to a minimal inline fallback if the default is unavailable.

### Theme File Format (`.theme`)

- Each non-empty, non-comment line is: `key value`.
- Comments start with `#` (leading whitespace allowed). Inline `#` is treated as part of the value.
- Values may contain spaces; the first whitespace separates the key from the value.
- Keys must match `[A-Za-z0-9_-]+` or the line is ignored with a warning.
- The file is not HTML; the loader wraps it into a `:root { --key: value; }` style block.

### Theme Rendering Pipeline

- `public::markdown::theme::load_theme_content` reads the `.theme` file and emits:
  - `<link rel="stylesheet" href="/builtin/theme-preset.css?v=<release>">`
  - `<style>:root { --<key>: <value>; }</style>`
- The rendered HTML snippet is injected into `public/templates/main_layout.html` via `{theme_content}`.
- Admin theme endpoints read and write `.theme` files for list, create, customize, and delete.
- Only the public renderer loads theme files for rendering responses.
- The built-in preset stylesheet (generated into `nop/builtin/theme-preset.css` from
  `nop/ts/site/theme-preset.css`) contains all structural CSS and references the variables.

### Navigation Rendering

- Parent items with children render a single navbar item containing a clickable primary link plus a dedicated
  dropdown toggle button (for touch/keyboard). The wrapper is hoverable so both controls highlight together;
  hovering the parent opens the dropdown, and it remains open while hovering the dropdown.

### Variable Catalog

These are the authoritative variable keys expected by the preset stylesheet. Values are provided by the `.theme` file.

Base palette (light):
- `color-background-primary-light`
- `color-background-secondary-light`
- `color-content-background-light`
- `color-text-primary-light`
- `color-text-secondary-light`
- `color-navbar-background-light`
- `color-footer-background-light`
- `color-border-light`
- `color-shadow-light`
- `color-code-background-light`
- `color-blockquote-background-light`
- `color-table-border-light`
- `color-table-header-background-light`

Base palette (dark):
- `color-background-primary-dark`
- `color-background-secondary-dark`
- `color-content-background-dark`
- `color-text-primary-dark`
- `color-text-secondary-dark`
- `color-navbar-background-dark`
- `color-footer-background-dark`
- `color-border-dark`
- `color-shadow-dark`
- `color-code-background-dark`
- `color-blockquote-background-dark`
- `color-table-border-dark`
- `color-table-header-background-dark`

Accent and UI colors (do not merge even if values match):
- `color-content-link-light`
- `color-content-link-dark`
- `color-breadcrumb-link-dark`
- `color-content-blockquote-border-light`
- `color-navbar-dropdown-arrow-light`
- `color-navbar-dropdown-border-top-light`
- `color-navbar-dropdown-item-hover-background-light`
- `color-navbar-dropdown-background-dark`
- `color-navbar-dropdown-border-dark`
- `color-navbar-dropdown-shadow-dark`
- `color-navbar-dropdown-item-hover-background-dark`
- `color-navbar-link-hover-background-dark`
- `color-navbar-dropdown-link-hover-background-dark`
- `color-notification-warning-background-dark`
- `color-notification-warning-text-dark`

Typography:
- `font-body-family`
- `font-heading-family`
- `font-mono-family`
- `font-body-size`
- `font-body-line-height`

Notes:
- `color-content-background-*`, `color-navbar-background-*`, `color-footer-background-*`, and
  `color-shadow-*` are reserved palette entries. They are defined in themes but not yet consumed
  by the preset stylesheet.

### Built-in Theme Palettes

- Bootstrap uses `nop/src/bootstrap/themes/red.theme` to create `themes/default.theme` when missing.

### Testing Scope

- `nop/tests/admin_themes.rs` validates create/save/delete with `.theme` files.
- `nop/src/public/markdown/parser.rs` asserts theme injection includes the preset link and variables.
- `tests/playwright/utils/seed.ts` seeds `default.theme` for E2E coverage.
