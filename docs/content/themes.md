# Themes

Status: Developed

## Objectives

- Move public theming to variable-only theme files with a built-in preset stylesheet.
- Keep theme files simple (one key/value per line) while preserving light/dark palettes.
- Provide a single, canonical reference for the theme format, variables, and built-in palettes.
- Extend themes with structured font-face support backed by uploaded same-origin font files.
- Expand theme settings beyond the base palette while preserving the existing one-line key/value
  pattern and built-in preset ownership of structural CSS.

## Action Plan

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
- Reserved structured directive prefixes may receive dedicated parser behavior. Normal unknown keys
  remain CSS variables for forward-compatible preset use.

### Font Faces and Deeper Theme Settings

- Theme files continue to use one key/value entry per line. Structured settings use reserved key
  prefixes rather than nested syntax.
- Font faces are declared with grouped directives:

```text
font-face-body-family Inter
font-face-body-src /fonts/inter.woff2
font-face-body-weight 100 900
font-face-body-style normal
font-face-body-display swap
font-body-family "Inter", system-ui, sans-serif
```

- `font-face-<slot>-family` and `font-face-<slot>-src` are required for a font-face group.
- `font-face-<slot>-weight`, `font-face-<slot>-style`, `font-face-<slot>-display`, and
  `font-face-<slot>-unicode-range` are optional.
- `<slot>` is an internal grouping name and must use the same character set as theme variable keys.
- Font source paths must be same-origin absolute public paths. Theme rendering rejects external
  URLs, protocol-relative URLs, data URLs, dot segments, backslashes, control characters, and paths
  outside public content routing. Query strings are allowed, fragments are rejected, and the
  renderer appends its own release query parameter.
- The renderer emits font-face rules before the `:root` variable block and appends the current
  release value to font URLs.
- Invalid font-face groups are skipped with a warning; valid CSS variables and valid font-face
  groups continue to render.
- Deeper settings remain CSS variables consumed by `theme-preset.css`. Missing values are optional
  and must use preset CSS fallbacks.

### Theme Rendering Pipeline

- `public::markdown::theme::load_theme_content` reads the `.theme` file and emits:
  - `<link rel="stylesheet" href="/builtin/theme-preset.css?v=<release>">`
  - zero or more validated `@font-face` rules for structured font-face directives
  - `<style>:root { --<key>: <value>; }</style>`
- The rendered HTML snippet is injected into `public/templates/main_layout.html` via `{theme_content}`.
- Admin theme endpoints read and write `.theme` files for list, create, customize, and delete.
- Only the public renderer loads theme files for rendering responses.
- The built-in preset stylesheet (generated into `nop/builtin/theme-preset.css` from
  `nop/ts/site/theme-preset.css`) contains all structural CSS and references the variables.
- Public text colors are applied both directly on NoPressure layout/content selectors and through
  Bulma semantic variables used by public content components (`title`, `subtitle`, and content
  table/header text). This keeps theme text variables authoritative when Bulma classes are present.

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
- `font-body-weight`
- `font-heading-weight`
- `font-heading-line-height`
- `font-nav-family`
- `font-nav-weight`
- `font-control-family`
- `font-code-size`
- `font-code-line-height`

Layout and component sizing:
- `size-content-padding`
- `size-content-margin-y`
- `size-content-measure` (font-relative content width, default `75ch`; yields roughly 66 text
  characters after content padding and tracks theme body font size automatically)
- `size-navbar-min-height`
- `size-search-panel-radius`
- `size-control-radius`
- `size-code-radius`
- `size-table-cell-padding`
- `size-blockquote-padding`
- `size-doc-structure-width` (panel maximum width, default `24rem`)
- `size-doc-structure-gap` (symmetric panel margin on both sides, default `2rem`)
- `size-doc-structure-top` (sticky top offset, defaults to below the navbar)

Visual treatment:
- `shadow-search-panel`
- `shadow-content-media`
- `border-width-control`
- `border-width-table`
- `opacity-search-backdrop-light`
- `opacity-search-backdrop-dark`

Structured font-face directives:
- `font-face-<slot>-family`
- `font-face-<slot>-src`
- `font-face-<slot>-weight`
- `font-face-<slot>-style`
- `font-face-<slot>-display`
- `font-face-<slot>-unicode-range`

Hero image shortcode:
- `sc-hero-img-size-height-sm`
- `sc-hero-img-size-height-md`
- `sc-hero-img-size-height-lg`
- `sc-hero-img-font-title-family`
- `sc-hero-img-font-title-size`
- `sc-hero-img-font-subtitle-family`
- `sc-hero-img-font-subtitle-size`
- `sc-hero-img-size-title-subtitle-margin`
- `sc-hero-img-color-text-light`
- `sc-hero-img-color-text-dark`
- `sc-hero-img-filter-lightify`
- `sc-hero-img-filter-darkify`
- `sc-hero-img-shadow-light`
- `sc-hero-img-shadow-dark`

### Built-in Theme Palettes

- Bootstrap uses `nop/crates/nop-rt-bootstrap/src/themes/red.theme` to create
  `themes/default.theme` when missing.

### Testing Scope

- `nop/tests/admin_themes.rs` validates create/save/delete with `.theme` files.
- `nop/crates/nop-public/src/markdown/theme.rs` validates variable parsing, font-face grouping,
  font-source rejection, and theme snippet ordering.
- `nop/crates/nop-public/src/markdown/parser.rs` asserts theme injection includes the preset link,
  font-face rules, and variables.
- `tests/playwright/utils/seed.ts` seeds `default.theme`, a full theme variable fixture, and a
  same-origin font fixture for E2E coverage.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
