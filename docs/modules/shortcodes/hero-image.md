# Hero Image Shortcode

Status: Developed

## Objectives

- Provide a `hero-img` shortcode that renders a full-viewport-width hero block carrying an image and optional title/subtitle text.
- The image is centred and fitted via cover semantics — it always fills the block, is never stretched, and the image's centre stays at the centre of the block.
- The block is full viewport width and 45% of viewport height (`45vh`) by default; height is theme-overridable via `sc-hero-img-size-height`.
- Title and subtitle render centred horizontally and vertically over the image, inside a single caption block whose maximum width matches the layout's wide content width.
- Typography (font family, font size) and text colour for title and subtitle are theme-driven via dedicated theme variables.
- A separate dark-mode image can be supplied; when omitted, the base image is used in both modes.
- Two boolean shortcode attributes control colour-scheme image filters: `lightify` (apply a "make lighter" CSS filter in light mode) and `darkify` (apply a "make darker" CSS filter in dark mode). Strengths come from theme variables with hard-coded fallbacks.
- Two boolean shortcode attributes control text legibility: `light-shadow` (subtle light halo around the letters in light mode, giving dark text contrast on bright/busy images) and `dark-shadow` (gentle dark halo around the letters in dark mode, giving light text contrast on dark/busy images). The effects are implemented as zero-offset `text-shadow` blurs (haloes), not as drop shadows. Strengths come from theme variables with hard-coded fallbacks.
- Quoted shortcode attribute values support backslash escapes (`\"`, `\\`, lenient `\X`→`X`) so titles like `She said "hi"` can be written verbatim. Documented at the parser level in `docs/modules/shortcodes.md`.
- The admin content editor's Insert modal offers a "Hero" mode whenever the picked content item is `image/*`, with inputs for title and subtitle and checkboxes for the four flags. The inserted snippet is built with `JSON.stringify` for every quoted attribute, matching the parser's escape grammar.

See `docs/modules/shortcodes.md` for the parser, registry, render-pipeline hooks, theme variable naming convention, and substitution mechanism that all shortcodes share.

## Technical Details

### Naming and registration

- Shortcode name: `hero-img`.
- Registration: `ShortcodeType { dynamic: false, container_escape: true }`.
- Handler: `nop/crates/nop-public/src/shortcode/hero_img.rs::handle_hero_img_shortcode`.
- Template: `public/shortcode/hero_img.html` (MiniJinja).

### Attributes

| Name | Required | Type | Purpose |
| --- | --- | --- | --- |
| `src` | Yes | string | Image to display. Local path or `http(s)://` URL. |
| `src-dark` | No | string | Image to display in dark mode. When omitted, `src` is used in both modes. |
| `title` | No | string | Heading text rendered centred over the image. |
| `subtitle` | No | string | Sub-heading text rendered centred directly under the title. |
| `lightify` | No | flag | Apply the lightify image filter in light mode. |
| `darkify` | No | flag | Apply the darkify image filter in dark mode. |
| `light-shadow` | No | flag | Apply a soft dark halo around the title/subtitle text in light mode. |
| `dark-shadow` | No | flag | Apply a soft bright halo around the title/subtitle text in dark mode. |

Examples:

```markdown
((hero-img src="hero.png" title="Welcome" subtitle="Built for nopressure"))
((hero-img src="hero-light.png" src-dark="hero-dark.png" title="Welcome"))
((hero-img src="hero.png" lightify darkify light-shadow dark-shadow))
```

### Layout

The hero is structured as a relatively-positioned wrapper with the image as an absolutely-positioned background-equivalent and the caption as the centred foreground.

- **Wrapper** (`<div class="sc-hero-img">`): `width: 100vw; height: var(--sc-hero-img-size-height, 45vh); position: relative; display: flex; align-items: center; justify-content: center;` plus a minimum `padding` so the caption never touches the wrapper edges. The wrapper sits between the layout's `escape_container()` and `return_to_container()` fragments — produced by the substitution step because the shortcode is registered with `container_escape: true` — so it spans the full viewport regardless of the surrounding `.content` container.
- **Image** (`<picture>` with optional dark `<source>` and a fallback `<img>`): `position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; object-position: center;`. If the image is wider than the wrapper, its left/right edges are cropped equally; if taller, top/bottom edges are cropped equally. The image is never stretched.
- **Caption block** (`<div class="sc-hero-img__caption">`): `position: relative; z-index: 1; max-width: 1152px; margin: 0 auto; text-align: center;` containing the optional title (`<h2 class="sc-hero-img__title">`) and subtitle (`<p class="sc-hero-img__subtitle">`), both inheriting `text-align: center`. Vertical centring of the caption block within the wrapper is handled by the wrapper's flex `align-items: center`. Width is bounded by `max-width` and constrained by the wrapper's padding (the "minimum margins"). The block grows vertically with its contents — title-only is centred; title + subtitle are centred as a single block. The caption block is omitted entirely when both `title` and `subtitle` are absent.

### Theme variables

All variables follow the `sc-<shortcode-name>-<category>-<rest>` convention defined in `docs/modules/shortcodes.md`. The shortcode ships its own defaults inline in the preset stylesheet (`nop/ts/site/theme-preset.css` → `nop/builtin/theme-preset.css`): every rule references the variable as `var(--name, <fallback>)`, where `<fallback>` is the value in the table below. The active `.theme` file's `<style>:root { … }</style>` injection sets the variable when the theme defines it, which the `var()` call picks up; when the theme does not define it, the inline fallback applies. Themes therefore never need to know about a shortcode's variables for the shortcode to render — they only opt in when they want to override.

| Variable | Purpose | Fallback |
| --- | --- | --- |
| `sc-hero-img-font-title-family` | Title font family | `var(--font-body-family)` |
| `sc-hero-img-font-title-size` | Title font size | `3rem` |
| `sc-hero-img-font-subtitle-family` | Subtitle font family | `var(--font-body-family)` |
| `sc-hero-img-font-subtitle-size` | Subtitle font size | `1.25rem` |
| `sc-hero-img-color-text-light` | Title/subtitle colour in light mode | `var(--color-text-primary-light)` |
| `sc-hero-img-color-text-dark` | Title/subtitle colour in dark mode | `var(--color-text-primary-dark)` |
| `sc-hero-img-filter-lightify` | CSS `filter` value applied to the image when `lightify` is set, in light mode | `brightness(1.15)` |
| `sc-hero-img-filter-darkify` | CSS `filter` value applied to the image when `darkify` is set, in dark mode | `brightness(0.7)` |
| `sc-hero-img-shadow-light` | CSS `text-shadow` value applied to title/subtitle when `light-shadow` is set, in light mode (light halo for contrast against dark text) | `0 0 12px rgba(255, 255, 255, 0.6)` |
| `sc-hero-img-shadow-dark` | CSS `text-shadow` value applied to title/subtitle when `dark-shadow` is set, in dark mode (dark halo for contrast against light text) | `0 0 12px rgba(0, 0, 0, 0.6)` |
| `sc-hero-img-size-height` | Wrapper height (any valid CSS length, typically a `vh` value) | `45vh` |

The shadow values are zero-offset blurs (haloes) rather than drop shadows: a soft *brightening* around the letters when `light-shadow` is active in light mode (so dark text gains contrast against a bright image area), and a gentle *darkening* around the letters when `dark-shadow` is active in dark mode (so light text gains contrast against a dark image area). Themes can stack multiple shadow layers in the variable value (e.g. `0 0 2px rgba(255,255,255,0.7), 0 0 6px rgba(255,255,255,0.4)`) without changing the shortcode CSS.

### Image source resolution

- `src` and `src-dark` accept exactly two forms: a local relative content path, or an `http(s)://` URL. No other URL schemes are supported.
- The handler asks the context: `ctx.resolve_image_source(url)`. The context owns the cache and the current markdown path; the handler does not see either. Outcomes:
  - `Ok(ResolvedImage::External(url))` — `http(s)://` URL passed through unchanged. The handler HTML-attribute-escapes it before insertion (`&` → `&amp;`, etc.). The escape is required so the URL cannot break out of the attribute and inject HTML; it does not change the URL the browser fetches.
  - `Ok(ResolvedImage::Local(versioned_path))` — local path that resolved to a known image asset, returned with the per-asset `?v=<version>` cache-busting suffix appended. The handler HTML-attribute-escapes it before insertion.
  - `Err(_)` — one of `Empty`, `PathTraversal`, `ReservedImgPath` (the `/img` reservation), `AliasNotFound`, or `NotImage` (alias resolved but its MIME does not start with `image/`). The handler returns `Err(...)`, leaving the source `((hero-img …))` visible.
- The resolver consolidates the existing path-traversal, `/img`, alias-lookup, and MIME validation that today live inline in `markdown/parser.rs::process_event` for `Tag::Image`; that branch is refactored to call the same resolver as part of this change.

### Failure and edge cases

- `src` missing → handler returns `Err`. The original `((hero-img …))` source is left visible in the output, per the existing graceful-degradation rule. No HTML is emitted.
- `src` or `src-dark` is a local path that fails resolution (path traversal, `/img`, missing alias, non-image MIME) → handler returns `Err`. Original source preserved.
- `title` and `subtitle` both absent → the hero renders with image only; the caption block is omitted.
- Inline placement (`((hero-img …))` mid-paragraph, surrounded by other text) — the substitution step keeps the surrounding `<p>` and substitutes the rendered HTML literally inside it. The hero does not break out of the content container from inline position, by construction of the paragraph-aware substitution; the editor decides where to place placeholders.
- Multiple `hero-img` placeholders alone in one paragraph — each renders sequentially as its own breakout block (the substitution step strips the surrounding `<p>` for hash-only paragraphs and wraps each `container_escape` placeholder individually with `escape_container(ctx)` / `return_to_container(ctx)`).

### Quoted-value escapes

Quoted shortcode attribute values support backslash escapes inside the quoted region so `"` and `\` can appear in the value. The escape rules are documented at the parser level in `docs/modules/shortcodes.md`; the relevant points for `hero-img` titles and subtitles:

- `\"` decodes to a literal `"`.
- `\\` decodes to a literal `\`.
- Any other `\X` decodes to the literal character `X` (lenient).

`normalize_shortcode` re-escapes `\` and `"` on the canonical-hash path, so two source forms that decode to the same `Shortcode` produce the same `SHORTCODE_HASH_…` placeholder.

The admin Insert modal builds quoted attribute values via `JSON.stringify`, which produces both the surrounding `"…"` and the proper inner escapes — a single library call covers everything the parser accepts. No custom escape helper is needed on the JS side.

### Admin Insert: Hero mode

The editor's Insert modal exposes a "Hero" option alongside the existing Image, Video, and Link modes.

**Mode list.** `InsertContentModal.svelte`'s `modesForItem(item)` returns `["image", "hero", "link"]` for `image/*` items. Image stays first so existing default behaviour is preserved.

**Hero options panel.** Visible only when `mode === "hero"`. Inputs:

- `title` (single-line `<input type="text">`, max 200 chars).
- `subtitle` (single-line `<input type="text">`, max 200 chars).
- Four `<input type="checkbox">`: Lightify, Darkify, Light shadow, Dark shadow.

State resets on modal open, on item change, and on mode change away from `hero`.

**Dispatch payload.** The `insert` event payload is a discriminated union:

```ts
type InsertPayload =
  | { item: ContentListItem; mode: "link" | "image" | "video" }
  | { item: ContentListItem; mode: "hero"; hero: HeroOptions };

type HeroOptions = {
  title: string;
  subtitle: string;
  lightify: boolean;
  darkify: boolean;
  lightShadow: boolean;
  darkShadow: boolean;
};
```

**Snippet builder.** `nop/ts/admin/src/services/insertSnippet.ts::buildModalInsertSnippet` is the canonical builder shared by `InsertContentModal` and `ContentEditorView`. The `hero` branch uses `JSON.stringify` for every quoted attribute value (so `"` and `\` are escaped per the parser's grammar) and appends the boolean-flag tokens. Empty title and empty subtitle are omitted from the snippet.

**Out of scope (this change):** picking a `src-dark` image from the modal. Authors who want a dark variant edit the inserted snippet by hand and add `src-dark="…"`. A future iteration can add a "Pick dark image…" sub-flow.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
