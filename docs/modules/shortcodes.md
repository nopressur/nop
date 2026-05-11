# Shortcode System

Status: Developed

## Objectives

- Define shortcode syntax, parsing, and rendering behavior.
- Document built-in handlers and extension workflow.
- Provide a `RenderPipelineSupportHooks` interface so shortcodes that need to escape the page's content container can have the layout layer supply the close/reopen HTML fragments.
- Replace shortcode placeholders in a paragraph-aware way so block-level shortcodes do not sit inside an implicit `<p>` they did not ask for. A paragraph whose non-whitespace content is only placeholders has the surrounding `<p>` stripped, regardless of how many placeholders it contains.

## Technical Details

### Syntax and Parsing

- Delimiter: double parentheses `(( ... ))`.
- Names accept alphanumeric, `_`, and `-` characters. Example: `((video))`, `((link-card))`.
- Attributes:
  - Key/value (`width=640`, `label="Search here"`).
  - Boolean flags with no value (`blank`).
- Quoted attribute values (`"…"`) support backslash escapes inside the quoted region: `\"` decodes to a literal `"`, `\\` decodes to a literal `\`, and any other `\X` decodes to the literal character `X` (lenient — forward-compatible with frontends that emit JSON-style escapes such as `\n`, `\t`, `\uXXXX`). Unquoted values do not have escape sequences; they accept any non-whitespace, non-`)` byte verbatim. The canonical-hash form re-escapes `\` and `"` so two source forms that decode to the same `Shortcode` produce the same `SHORTCODE_HASH_…` placeholder.
- Parser lives in `public/shortcode/mod.rs` using `nom`. `parse_shortcode` returns the consumed byte count so the renderer can continue scanning the string.
- During rendering:
  1. `process_text_with_shortcodes` scans Markdown text, parsing any shortcodes.
  2. Rendered HTML is cached against a SHA-512 placeholder (`SHORTCODE_HASH_*`) to avoid double rendering.
  3. Markdown conversion proceeds as normal; placeholders survive sanitization.
  4. `replace_shortcode_placeholders` substitutes placeholders for HTML in a paragraph-aware way (see "Paragraph-aware substitution" below).
- Unknown shortcodes remain unchanged so editors can spot typos. Handler errors leave the original shortcode intact and log a debug message.
- Identical shortcodes within the same document share the same placeholder hash so HTML is rendered once and reused.

### Built-in Shortcodes

Handlers register in `create_default_registry_with_config`; they must be thread-safe closures returning `Result<String, String>`.

Per-shortcode reference docs live in `docs/modules/shortcodes/`:

- `docs/modules/shortcodes/navigation.md` — `link-card`, `start-unibox`.
- `docs/modules/shortcodes/media.md` — `video`.
- `docs/modules/shortcodes/listings.md` — `tag-list`.

This document covers only the mechanism (parser, registry, substitution, hooks, safety).

#### Shortcode type

- Each registration records a `ShortcodeType` value describing the special treatment a handler requires. The struct currently exposes two boolean fields:
  - `dynamic`: Mark a shortcode as dynamic when it depends on information beyond Markdown and configuration that was loaded at startup (for example, it uses content metadata at render time). Handlers whose output is determined entirely by Markdown plus startup-time configuration are static. The flag has two effects today:
    - Within-page render caching is bypassed: identical occurrences of a dynamic shortcode in the same page each invoke the handler, instead of reusing the first render via the normalised-form cache.
    - The page's HTML response is served with `Cache-Control: no-store` and no ETag. The flag is propagated through `RenderedMarkdown::contains_dynamic_shortcodes` into `HtmlCacheEnvelope::contains_dynamic_content`, which switches `finalize_html_response` (`nop-public/src/cache.rs`) to the no-store directive.
  - `container_escape`: Declares that the shortcode's output is intended to escape the page's content container. When the placeholder is the sole content of its paragraph, the substitution step wraps the rendered HTML with `RenderPipelineSupportHooks::escape_container` and `return_to_container` fragments instead of emitting it inside the surrounding `<p>`. Inline-position container-escape placeholders cannot break out and are substituted literally with a debug log.
- `ShortcodeType::default()` produces both fields set to `false`.

### Shortcode Context

`ShortcodeContext` is the only data-access surface a shortcode handler sees at render time. It is passed as the second argument to every registered handler and exposes:

- `user: Option<&User>` — the requesting user, when authenticated.
- A small set of capability methods (`resolve_image_source`, `list_accessible_pages_by_tags`, …) covering what handlers legitimately need to ask of the system.

Handlers do **not** receive the page-meta cache, the markdown path being rendered, or any other infrastructure handle. Those live as private fields inside the context and are reached only through the method API. This keeps shortcodes decoupled from the storage layer and from page-routing details: each method is a deliberate, narrow capability with a specific shortcode use case behind it.

Adding a new method to `ShortcodeContext` requires a clear shortcode use case for it, and the method's signature should expose only the data shape that use case needs — not raw repository types. Re-export shared input types (e.g. `TagMatch`) from the shortcode module so handlers do not have to reach into other crates for arguments. When in doubt, prefer a smaller method surface; broaden later if a second use case justifies it.

Existing methods:

- `list_accessible_pages_by_tags(tags: &[String], rule: TagMatch) -> Vec<PageSummary>` — returns markdown pages matching the tag criteria, already filtered for `user`'s access. Used by `tag-list`.
- `resolve_image_source(url: &str) -> Result<ResolvedImage, ImageSourceError>` — resolves a local relative path or `http(s)://` URL into the URL the shortcode emits, with cache-busting versioning applied to local paths and the same path-traversal / `/img` / MIME validation that markdown image links use. Used by `hero-img`. Returned URLs are not pre-escaped — handlers must let MiniJinja's HTML attribute escaping run before insertion (or escape manually) to prevent attribute breakout via embedded `"`.

### Templating and Assets

- Shortcode templates live in `public/shortcode/templates/`.
- Rendering uses `templates::render_minijinja_template`, which enforces escaping before HTML insertion.
- Any static JS/CSS needed by shortcodes must be packaged in `nop/builtin/` so release builds embed them automatically.

### Theme Variable Naming Convention

Shortcodes that surface visual properties through the theme system use the prefix `sc-<shortcode-name>-<category>-<rest>`:

- `sc-` is the literal namespace marker for shortcode-owned theme variables.
- `<shortcode-name>` is the registered shortcode name with any underscores or other separators replaced by dashes (`hero-img` stays `hero-img`; a hypothetical `tag_list` would map to `tag-list`).
- `<category>` groups variables of the same kind (e.g. `font`, `color`, `filter`, `shadow`). The shortcode author picks a category that describes the property; the convention does not enumerate a fixed list.
- `<rest>` is the property-specific suffix (e.g. `title-family`, `text-light`, `lightify`).

Examples for a `hero-img` shortcode:

```
sc-hero-img-font-title-family
sc-hero-img-font-title-size
sc-hero-img-color-text-light
sc-hero-img-color-text-dark
sc-hero-img-filter-lightify
sc-hero-img-filter-darkify
sc-hero-img-shadow-light
sc-hero-img-shadow-dark
```

Each shortcode ships its own defaults via fallback values inside its preset CSS rules (`var(--name, <fallback>)`). The shortcode renders correctly out of the box even with a theme that defines none of the shortcode's variables; themes override any variable they want without changing the shortcode.

### Extension Workflow

1. Implement a handler returning `Result<String, String>`; keep logic deterministic and side-effect free.
2. If the shortcode needs repository configuration, capture `ValidatedConfig` via a closure when registering (see `start-unibox` example).
3. Add any templates under `public/shortcode/templates/` and load them via MiniJinja in the handler.
4. Register the handler in `create_default_registry_with_config`.
5. If the shortcode exposes theme-tunable properties, name the variables per the convention above and reference them in the preset stylesheet (`nop/ts/site/theme-preset.css`) as `var(--name, <fallback>)`. The fallback is the shortcode's own default — themes do not need to define the variable for the shortcode to render correctly.
6. Write parser and handler tests in `shortcode/mod.rs` or the new module. Existing tests cover parsing, caching, and error propagation.
7. Update docs to describe usage so authors know the supported attributes.

### Safety Considerations

- Sanitization: Markdown output is cleaned by `ammonia` before placeholders are reinserted, so shortcode HTML must already be safe. Prefer MiniJinja with auto-escaping.
- Error handling: returning `Err(String)` logs context while leaving source Markdown unchanged - no panic paths.
- Configuration: Validate URLs and required attributes (for example, `start-unibox` enforces `<QUERY>` placeholder and `http(s)://` schemes).
- Performance: Hash caching prevents duplicate parse/execute cycles for repeated identical shortcodes within one document.
- Debugging: because failed or unknown shortcodes render verbatim, editors can immediately locate and correct the offending markup.
- See also `nop/crates/nop-public/src/shortcode/README.md` for module-local examples and handler templates.

### Render Pipeline Support Hooks

The render pipeline exposes an interface, `RenderPipelineSupportHooks`, that lets the layout layer hand the markdown renderer two functions used by shortcodes whose output must escape the page's content container.

**Trait shape** (`nop/crates/nop-public/src/markdown/render_pipeline_support_hooks.rs`):

```rust
pub struct PageRenderHookContext {
    /// Set when the surrounding page is using the compact (960px) content width.
    /// Hook implementations consult this so the reopened container matches the
    /// page's actual width variant. Future fields (theme, page kind, …) extend
    /// the struct without changing the trait shape.
    pub use_compact_width: bool,
}

pub trait RenderPipelineSupportHooks: Send + Sync {
    /// HTML fragment that closes the page's content container.
    /// Emitted immediately before a container-escape shortcode's HTML.
    fn escape_container(&self, ctx: &PageRenderHookContext) -> String;

    /// HTML fragment that reopens the page's content container.
    /// Emitted immediately after a container-escape shortcode's HTML.
    fn return_to_container(&self, ctx: &PageRenderHookContext) -> String;
}

pub struct DefaultRenderPipelineSupportHooks;

impl RenderPipelineSupportHooks for DefaultRenderPipelineSupportHooks {
    fn escape_container(&self, _ctx: &PageRenderHookContext) -> String {
        // closes `.content` then `.container.content-container`
    }
    fn return_to_container(&self, ctx: &PageRenderHookContext) -> String {
        // reopens both with the max-width that matches the current page variant
        // (960px when ctx.use_compact_width, 1152px otherwise)
    }
}
```

**Plumbing.** A reference to a `dyn RenderPipelineSupportHooks` lives on `RenderRequest` (`markdown/parser.rs`). The production caller in `markdown/handlers.rs::serve_markdown_alias` constructs `DefaultRenderPipelineSupportHooks` and passes it through. Test helpers in `markdown/parser.rs` do the same. Implementations carry their own state, so theme-aware or page-kind-aware fragments can be added without changing the call site.

**Context construction.** `should_use_compact_width` runs inside `generate_html` before the substitution step. The substitution step builds a `PageRenderHookContext { use_compact_width: <decided value> }` and hands the same context into both `escape_container` and `return_to_container` for every breakout on that page.

**Contract.** `escape_container(ctx) + content + return_to_container(ctx)` must be well-formed at the close/reopen boundary. Implementations decide the specific tag shape; the markdown layer treats both methods as opaque HTML strings.

**Default impl.** `DefaultRenderPipelineSupportHooks` mirrors `main_layout.html` nesting and reads `ctx.use_compact_width` to choose the matching `max-width` (960px compact, 1152px wide). The outermost `.content-wrapper` is full-viewport-width already and is not escaped or reopened.

### Paragraph-aware substitution

The substitution step turns `SHORTCODE_HASH_<128-hex>` placeholders back into HTML. A `<p>...</p>` whose non-whitespace content is only placeholders is stripped of its `<p>` and `</p>`; everything else gets a literal `hash → html` substitution.

**Detection.** The substitution scans the post-sanitisation HTML for `<p>...</p>` spans. A `consume_hash_token` parser recognises the exact shape `SHORTCODE_HASH_` followed by 128 ASCII hex bytes (the SHA-512 digest length used by `generate_shortcode_hash`). A span qualifies as hash-only when every byte between `<p>` and `</p>` is either whitespace or part of a recognised hash token, and at least one hash is present. CommonMark soft-breaks between consecutive shortcode lines render as plain newlines and count as whitespace for this check.

**Behaviour:**

| Paragraph contents | Outcome |
| --- | --- |
| `<p>HASH</p>` (single placeholder) | strip `<p>` and `</p>`; render the placeholder with type-aware wrapping |
| `<p>HASH HASH HASH</p>` (any number of placeholders, whitespace between, including soft-break newlines) | strip `<p>` and `</p>`; render each placeholder in order with type-aware wrapping; whitespace between placeholders is preserved verbatim |
| `<p>some text HASH some text</p>` (placeholder mixed with real text) | keep `<p>`; literal-replace the hash; paragraph survives |
| `<p>HASH text HASH</p>` (placeholders interspersed with real text) | keep `<p>`; literal-replace each hash |

**Type-aware wrapping.** Inside a hash-only span, each placeholder is rendered as `escape_container(ctx) + html + return_to_container(ctx)` when its `ShortcodeType::container_escape` is `true`, and as plain `html` otherwise. Mixed paragraphs always get plain literal substitution: a `container_escape` shortcode placed inline cannot break out of the surrounding paragraph cleanly, so its output stays inside the `<p>`.

**Pipeline mapping.** The substitution step resolves `hash → ShortcodeType` for the matched span via `ShortcodeProcessingResult::hash_to_type_map`, populated alongside `hash_to_html_map` when each placeholder is created.

**Sanitization order.** Substitution runs after `ammonia::clean`, so injected `</div>…<div>` from the hooks survives sanitisation. Substitution does not alter the link/code-block post-passes.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
