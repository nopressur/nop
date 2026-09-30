# Theming

NoPressure public pages use theme files stored in the runtime root under `themes/`.
A theme file has the `.theme` extension and contains one variable per line:

```text
color-background-primary-light #fdf2f2
font-body-size 16px
```

The first whitespace separates the variable name from the value. Empty lines and lines
starting with `#` are ignored. Values are emitted directly into CSS variables, so use
valid CSS values for the expected property type.

## Theme Selection

| Option | Default | Range | Notes |
| --- | --- | --- | --- |
| Theme file location | `<runtime-root>/themes/default.theme` | Files ending in `.theme` under `<runtime-root>/themes/` | Hidden files and non-`.theme` files are not listed in the admin theme library. |
| Page theme value | Empty / not set | Theme file name without `.theme` | Empty or missing values select `default.theme`. |
| New theme name | None | 1-128 characters: lowercase ASCII letters, numbers, `-`, `_`; no dots | The `.theme` extension is added automatically. |
| Theme variable key | None | ASCII letters, numbers, `-`, `_` | Invalid keys and lines without values are ignored when rendering. |
| Theme variable value | None | Any valid CSS value for the variable's expected property | Values are not type-validated by NoPressure. Invalid CSS is ignored by the browser for affected declarations. |
| Missing requested theme | `default.theme` | Any valid page theme value | If the selected file cannot be loaded, the renderer falls back to `default.theme`. |
| Missing default theme | Inline fallback | Built in | The inline fallback only covers a minimal body, page background, content, and navbar style. |

New runtime roots create `themes/default.theme` from the embedded red theme. The
repository also ships palette files under `assets/themes/`: `blue`, `default`,
`green`, `grey`, `orange`, `pink`, `purple`, `red`, `teal`, and `yellow`.

## Base Palette

These variables control the main light and dark colour scheme. Defaults are the
values used by the embedded red theme that bootstraps new runtime roots.

| Variable | Default | Range | Used for |
| --- | --- | --- | --- |
| `color-background-primary-light` | `#fdf2f2` | Valid CSS color | Light body background and gradient start. |
| `color-background-secondary-light` | `#f8b4b4` | Valid CSS color | Light page gradient end and search result hover background. |
| `color-content-background-light` | `#ffffff` | Valid CSS color | Light search panel, search results, copy button, close button backgrounds. |
| `color-text-primary-light` | `#7f1d1d` | Valid CSS color | Light body text, headings, strong text, navbar brand, code text, table headings. |
| `color-text-secondary-light` | `#991b1b` | Valid CSS color | Light paragraph/list/table body text, subtitles, secondary controls. |
| `color-navbar-background-light` | `rgba(255, 255, 255, 0.95)` | Valid CSS color | Reserved palette entry; defined in themes but not consumed by the preset stylesheet. |
| `color-footer-background-light` | `rgba(255, 255, 255, 0.95)` | Valid CSS color | Reserved palette entry; defined in themes but not consumed by the preset stylesheet. |
| `color-border-light` | `rgba(220, 38, 38, 0.2)` | Valid CSS color | Light borders for code blocks, search UI, copy buttons, and result rows. |
| `color-shadow-light` | `rgba(220, 38, 38, 0.1)` | Valid CSS color | Light search panel shadow colour. |
| `color-code-background-light` | `#fee2e2` | Valid CSS color | Light inline code and code block background. |
| `color-blockquote-background-light` | `#fee2e2` | Valid CSS color | Light blockquote background. |
| `color-table-border-light` | `#fca5a5` | Valid CSS color | Light content table borders. |
| `color-table-header-background-light` | `#fee2e2` | Valid CSS color | Light content table header background. |
| `color-background-primary-dark` | `#450a0a` | Valid CSS color | Dark body background and gradient start. |
| `color-background-secondary-dark` | `#7f1d1d` | Valid CSS color | Dark page gradient end, search input background, search result hover background. |
| `color-content-background-dark` | `#7f1d1d` | Valid CSS color | Dark search panel, search results, copy button, close button backgrounds. |
| `color-text-primary-dark` | `#fecaca` | Valid CSS color | Dark body text, headings, strong text, navbar brand, code text, table headings. |
| `color-text-secondary-dark` | `#f87171` | Valid CSS color | Dark paragraph/list/table body text, subtitles, secondary controls, navbar links. |
| `color-navbar-background-dark` | `rgba(127, 29, 29, 0.95)` | Valid CSS color | Reserved palette entry; defined in themes but not consumed by the preset stylesheet. |
| `color-footer-background-dark` | `rgba(127, 29, 29, 0.95)` | Valid CSS color | Reserved palette entry; defined in themes but not consumed by the preset stylesheet. |
| `color-border-dark` | `rgba(248, 113, 113, 0.3)` | Valid CSS color | Dark borders for code blocks, search UI, copy buttons, and result rows. |
| `color-shadow-dark` | `rgba(0, 0, 0, 0.4)` | Valid CSS color | Dark search panel shadow colour. |
| `color-code-background-dark` | `#991b1b` | Valid CSS color | Dark inline code and code block background. |
| `color-blockquote-background-dark` | `#991b1b` | Valid CSS color | Dark blockquote background. |
| `color-table-border-dark` | `#dc2626` | Valid CSS color | Dark content table borders. |
| `color-table-header-background-dark` | `#991b1b` | Valid CSS color | Dark content table header background. |

## Accent And Navigation

| Variable | Default | Range | Used for |
| --- | --- | --- | --- |
| `color-content-link-light` | `#dc2626` | Valid CSS color | Light content links and focus outlines. |
| `color-content-link-dark` | `#f87171` | Valid CSS color | Dark content links and focus outlines. |
| `color-breadcrumb-link-dark` | `#f87171` | Valid CSS color | Dark breadcrumb links. |
| `color-content-blockquote-border-light` | `#dc2626` | Valid CSS color | Light blockquote left border. |
| `color-navbar-dropdown-arrow-light` | `#b91c1c` | Valid CSS color | Light nested dropdown arrow hover colour. |
| `color-navbar-dropdown-border-top-light` | `rgba(220, 38, 38, 0.2)` | Valid CSS color | Light mobile dropdown top border. |
| `color-navbar-dropdown-item-hover-background-light` | `#fee2e2` | Valid CSS color | Light dropdown item hover background. |
| `color-navbar-dropdown-background-dark` | `#450a0a` | Valid CSS color | Dark navbar dropdown background. |
| `color-navbar-dropdown-border-dark` | `rgba(248, 113, 113, 0.3)` | Valid CSS color | Dark navbar dropdown border. |
| `color-navbar-dropdown-shadow-dark` | `rgba(0, 0, 0, 0.4)` | Valid CSS color | Dark navbar dropdown shadow colour. |
| `color-navbar-dropdown-item-hover-background-dark` | `#991b1b` | Valid CSS color | Dark dropdown item hover background. |
| `color-navbar-link-hover-background-dark` | `#991b1b` | Valid CSS color | Dark navbar link hover background. |
| `color-navbar-dropdown-link-hover-background-dark` | `#991b1b` | Valid CSS color | Dark nested dropdown link hover background. |
| `color-notification-warning-background-dark` | `#dc2626` | Valid CSS color | Dark warning notification background. |
| `color-notification-warning-text-dark` | `#fef2f2` | Valid CSS color | Dark warning notification text. |

## Typography

| Variable | Default | Range | Used for |
| --- | --- | --- | --- |
| `font-body-family` | `'Segoe UI', Tahoma, Geneva, Verdana, sans-serif` | Valid CSS `font-family` list | Body text, controls, search UI, and hero fallback fonts. |
| `font-heading-family` | `'Segoe UI', Tahoma, Geneva, Verdana, sans-serif` | Valid CSS `font-family` list | Markdown headings. |
| `font-mono-family` | `monospace` | Valid CSS `font-family` list | Inline code and code blocks. |
| `font-body-size` | `16px` | Valid CSS `font-size` value | Body font size. |
| `font-body-line-height` | `normal` | Valid CSS `line-height` value: number, length, percentage, or `normal` | Body line height. |
| `font-body-weight` | `400` | Valid CSS `font-weight` value | Body font weight. |
| `font-heading-weight` | `700` | Valid CSS `font-weight` value | Markdown heading font weight. |
| `font-heading-line-height` | `1.2` | Valid CSS `line-height` value | Markdown heading line height. |
| `font-nav-family` | `var(--font-body-family)` | Valid CSS `font-family` list | Navbar and search trigger text. |
| `font-nav-weight` | `400` | Valid CSS `font-weight` value | Navbar item weight. |
| `font-control-family` | `var(--font-body-family)` | Valid CSS `font-family` list | Search fields, buttons, and other public controls. |
| `font-code-size` | `0.95em` | Valid CSS `font-size` value | Inline code and code block font size. |
| `font-code-line-height` | `1.5` | Valid CSS `line-height` value | Code block line height. |

## Uploaded Fonts

Upload font files through the admin content upload flow. Font files default to
the `fonts/` alias prefix, so a file named `Inter Variable.woff2` becomes
`fonts/inter-variable.woff2` unless you edit the alias.

Supported font upload extensions are included in the default upload
configuration: `woff`, `woff2`, `ttf`, `otf`, `eot`, and `ttc`. If your
`config.yaml` explicitly sets `upload.allowed_extensions`, add the font
extensions you want to allow.

Use `font-face-<slot>-...` lines to define web fonts. The `<slot>` only groups
one `@font-face` rule; it does not become part of the CSS family name.

```text
font-face-body-family Inter
font-face-body-src /fonts/inter-variable.woff2
font-face-body-weight 100 900
font-face-body-style normal
font-face-body-display swap
font-body-family "Inter", system-ui, sans-serif
```

Required fields:

| Variable | Range | Notes |
| --- | --- | --- |
| `font-face-<slot>-family` | CSS font family name | Rendered as the `font-family` descriptor in `@font-face`. |
| `font-face-<slot>-src` | Same-origin absolute public path | Use paths like `/fonts/inter.woff2` or `/id/<hex>`. External URLs, `data:` URLs, protocol-relative URLs, fragments, backslashes, control characters, and `.`/`..` path segments are rejected. |

Optional fields:

| Variable | Range | Notes |
| --- | --- | --- |
| `font-face-<slot>-weight` | CSS font weight or range | Use `400`, `700`, or ranges such as `100 900` for variable fonts. |
| `font-face-<slot>-style` | CSS font style | Common values are `normal` and `italic`. |
| `font-face-<slot>-display` | CSS font display | Common values are `swap`, `fallback`, and `optional`. |
| `font-face-<slot>-unicode-range` | CSS unicode range list | Optional subset descriptor, for example `U+000-5FF`. |

For multiple files in one family, define multiple slots with the same family:

```text
font-face-inter-regular-family Inter
font-face-inter-regular-src /fonts/inter-regular.woff2
font-face-inter-regular-weight 400
font-face-inter-regular-style normal
font-face-inter-regular-display swap

font-face-inter-bold-family Inter
font-face-inter-bold-src /fonts/inter-bold.woff2
font-face-inter-bold-weight 700
font-face-inter-bold-style normal
font-face-inter-bold-display swap

font-face-inter-italic-family Inter
font-face-inter-italic-src /fonts/inter-italic.woff2
font-face-inter-italic-weight 400
font-face-inter-italic-style italic
font-face-inter-italic-display swap

font-body-family "Inter", system-ui, sans-serif
```

NoPressure appends the current public release value to font URLs when rendering
the theme. Re-uploading a font with the same alias creates a new content version
and refreshes the URL used by the browser.

## Layout And Components

| Variable | Default | Range | Used for |
| --- | --- | --- | --- |
| `size-content-padding` | `2rem` | Valid CSS spacing value | Main content padding. |
| `size-content-margin-y` | `1rem` | Valid CSS spacing value | Main content vertical margin. |
| `size-content-measure` | `75ch` | Valid CSS length | Font-relative content width. |
| `size-navbar-min-height` | `3.25rem` | Valid CSS length | Navbar and search trigger minimum height. |
| `size-search-panel-radius` | `12px` | Valid CSS radius | Search overlay panel radius. |
| `size-control-radius` | `8px` | Valid CSS radius | Public controls such as copy/search buttons and search fields. |
| `size-code-radius` | `5px` | Valid CSS radius | Code block and inline code radius. |
| `size-table-cell-padding` | `0.75rem` | Valid CSS spacing value | Content table cell padding. |
| `size-blockquote-padding` | `1rem` | Valid CSS spacing value | Blockquote padding. |
| `size-doc-structure-width` | `24rem` | Valid CSS length | Document structure panel maximum width on desktop. |
| `size-doc-structure-gap` | `2rem` | Valid CSS length | Symmetric margin on both sides of the structure panel. |
| `size-doc-structure-top` | Navbar height plus `1rem` | Valid CSS length | Sticky top offset of the structure panel. |

## Visual Treatment

| Variable | Default | Range | Used for |
| --- | --- | --- | --- |
| `shadow-search-panel` | `0 18px 48px var(--color-shadow-light)` | Valid CSS box-shadow | Light search overlay panel shadow. |
| `shadow-content-media` | `none` | Valid CSS box-shadow | Images and videos inside Markdown content. |
| `border-width-control` | `1px` | Valid CSS border width | Public controls and search UI borders. |
| `border-width-table` | `1px` | Valid CSS border width | Content table borders. |
| `opacity-search-backdrop-light` | `0.65` | Number from `0` to `1` | Light search backdrop opacity. |
| `opacity-search-backdrop-dark` | `0.75` | Number from `0` to `1` | Dark search backdrop opacity. |

## Hero Image Shortcode

The `hero-img` shortcode has additional theme variables. Unlike the main palette,
these variables have CSS fallbacks in the preset stylesheet, so they do not need to
be present in a theme file unless you want to override them.

| Variable | Default | Range | Used for |
| --- | --- | --- | --- |
| `sc-hero-img-size-height-sm` | `45vh` | Valid CSS length or viewport-based size | Hero wrapper height below the medium breakpoint. |
| `sc-hero-img-size-height-md` | `45vh` | Valid CSS length or viewport-based size | Hero wrapper height from the medium breakpoint until large. |
| `sc-hero-img-size-height-lg` | `65vh` | Valid CSS length or viewport-based size | Hero wrapper height from the large breakpoint upward. |
| `sc-hero-img-font-title-family` | `var(--font-body-family)` | Valid CSS `font-family` list | Hero title font family. |
| `sc-hero-img-font-title-size` | `3rem` | Valid CSS `font-size` value | Hero title font size. |
| `sc-hero-img-font-subtitle-family` | `var(--font-body-family)` | Valid CSS `font-family` list | Hero subtitle font family. |
| `sc-hero-img-font-subtitle-size` | `1.25rem` | Valid CSS `font-size` value | Hero subtitle font size. |
| `sc-hero-img-size-title-subtitle-margin` | `0.5rem` | Valid CSS length | Top margin between hero title and subtitle when both are present. |
| `sc-hero-img-color-text-light` | `var(--color-text-primary-light)` | Valid CSS color | Hero title and subtitle colour in light mode. |
| `sc-hero-img-color-text-dark` | `var(--color-text-primary-dark)` | Valid CSS color | Hero title and subtitle colour in dark mode. |
| `sc-hero-img-filter-lightify` | `brightness(1.15)` | Valid CSS `filter` value | Image filter when the shortcode has `lightify`, in light mode. |
| `sc-hero-img-filter-darkify` | `brightness(0.7)` | Valid CSS `filter` value | Image filter when the shortcode has `darkify`, in dark mode. |
| `sc-hero-img-shadow-light` | `0 0 12px rgba(255, 255, 255, 0.6)` | Valid CSS `text-shadow` value | Text halo when the shortcode has `light-shadow`, in light mode. |
| `sc-hero-img-shadow-dark` | `0 0 12px rgba(0, 0, 0, 0.6)` | Valid CSS `text-shadow` value | Text halo when the shortcode has `dark-shadow`, in dark mode. |

## Example

```text
# Runtime default is created as themes/default.theme
color-background-primary-light #fdf2f2
color-background-secondary-light #f8b4b4
color-text-primary-light #7f1d1d
color-content-link-light #dc2626
font-body-family 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif
font-body-size 16px
font-body-line-height normal
sc-hero-img-size-height-sm 45vh
sc-hero-img-size-height-md 45vh
sc-hero-img-size-height-lg 65vh
sc-hero-img-size-title-subtitle-margin 0.5rem
```

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
