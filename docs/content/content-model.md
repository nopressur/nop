# Public Content Model

Status: Developed

## Objectives

- Define how public requests map to flat, alias- and ID-based content.
- Document sidecar metadata, access control, and caching used by the public pipeline.
- Provide a single canonical reference for public routing, rendering, and navigation.
- Provide a themeable public Markdown document structure panel, narrow top bar with drawers,
  and scroll-reveal navbar behavior.
- Provide icon-led page top and bottom jumps in the document structure surfaces,
  showing the page title next to the top icon when one exists.

## Technical Details

### Canonical Scope

This document is the single source of truth for public content resolution and rendering. On-disk storage rules live in `docs/infrastructure/storage.md`.

### Page Width Mode

- Markdown sidecar metadata may set `content_width` to `auto`, `wide`, or `narrow`.
- Missing `content_width` values default to `auto`.
- `auto` always renders the normal compact width; paragraph length never affects width.
- `wide` forces the wide content container width and is the only way to opt a page into it.
- `narrow` forces the existing compact content container width.
- Container-escape shortcodes reopen content containers using the final selected width mode, so
  `hero-img` and other full-width shortcodes preserve the page's current width decision.

### ID-First Routing

- Public routing must recognize `/id/<hex>` and resolve content by ID for all content types
  (markdown renders, binaries stream).
- Alias-based routing remains only when an alias exists; missing aliases return 404.
- Aliases are optional and must not use reserved paths (see "Alias Resolution" for the canonical
  registry).
- Cache lookups must support direct ID resolution; alias maps remain optional overlays when aliases
  are present.

### Entry Points and Ownership

- `GET /` routes to `handlers::index` and resolves the configured home alias.
- `GET /{path:.*}` routes to `handlers::handle_route` and resolves aliases.
- Root-level special fallback files handled within `handle_route` are defined in
  `docs/content/special-fallback-files.md`.
- Requests whose path starts with the configured admin prefix are routed to the admin module.
- Requests starting with `/login` are routed to the login module.

### Request Lifecycle (`handle_route`)

1. **Security gate**: `security::is_ip_blocked` and `security::route_checks` reject throttled or invalid paths.
2. **Alias canonicalization**: normalize the incoming path to a canonical alias (lowercase, trim slashes, collapse `//`, reject invalid URL characters).
3. **Alias lookup**: consult `PageMetaCache` for the canonical alias.
4. **Access check**: validate the requester against the cache-resolved roles for the object.
5. **Render or stream**:
   - Markdown files render through the Markdown pipeline.
   - Non-Markdown assets stream directly with range support when enabled.
6. **Auth outcomes**: access denial redirects anonymous users to `/login?return_path=...` or serves 404 to authenticated users.
7. **Response headers**:
   - Public content (HTML + assets) is cacheable but always includes `Vary: Cookie` so shared caches
     separate anonymous and authenticated responses.
   - Restricted content (RBAC-required) is served with `Cache-Control: no-store, private` and
     `Vary: Cookie`.
   - Login and profile pages (`/login`, `/login/profile`) are served with
     `Cache-Control: no-store, private` and `Vary: Cookie`.

### Alias Resolution

- Aliases are globally unique, case-insensitive, and canonicalized.
- Canonicalization rejects dot segments, control characters, backslashes, percent-encoded bytes,
  and non-URL-safe characters.
- Aliases that start with reserved prefixes are rejected. Reserved paths are defined in a single
  registry used by alias validation, sitemap exclusion, and robots rules. Initial entries include
  `robots.txt`, `sitemap.xml`, `id/`, `login/`, `builtin/`, `api/`, and the configured admin path
  prefix.
- Trailing slashes are ignored (`docs` and `docs/` are the same alias).
- Non-Markdown assets also resolve by `id/<hex>` for stable download links.
- If no alias is found, respond with 404.
- Alias changes take effect in the live public alias map without restarting the executable. During
  sequential reassignments, `/id/<hex>` remains the stable identity URL while alias routes follow
  the current sidecar metadata.

### Page Metadata Cache

- `PageMetaCache::rebuild_cache` scans sidecar metadata files at startup.
- Cached metadata includes content ID, `alias`, `title`, `tags`, `mime`, `nav_title`, `nav_parent_id`, `nav_order`, `disable_navbar`, `disable_floating_nav`, `content_width`, `original_filename`, and theme when provided.
- Cached metadata includes `last_modified`, derived from the latest modification time between the
  content blob and its sidecar.
- The cache supplies canonical content IDs and navbar parent candidates to management APIs.
- The cache stores resolved access roles per object after tag evaluation.
- Admin changes update the cache via `cache.update_file` or `cache.remove_file`.
- The cache is treated as authoritative; external filesystem edits require a rebuild or restart.

### Sidecar Metadata

The public pipeline reads metadata from RON sidecar files.

- `title` is used for page titles and navigation labels.
- `theme` selects `<runtime-root>/themes/<theme>.theme` and falls back to `default.theme`
  (see `docs/content/themes.md`).
- `disable_navbar` is a page-level boolean. Missing values default to `false`. When `true` for a
  markdown page, the public page layout omits the top navbar entirely for that page. The flag does
  not disable the page-level search overlay or its keyboard/passive typing triggers.
- `disable_floating_nav` is a page-level boolean. Missing values default to `false`. When `true` for
  a markdown page, the public page layout omits the floating document navigation feature for that
  page. This suppresses the desktop left panel. The top navbar never carries document-structure
  heading links. The flag does not affect the top navbar or scroll-reveal navbar behavior.
- `content_width` is a Markdown page width mode. Missing values default to `auto`; valid values are
  `auto`, `wide`, and `narrow`.
- `tags` drive access control and tag-list shortcodes.

### HTML Page Title

- Public HTML page titles use the resolved page title as their base value.
- When `settings.title` is configured, the public `<title>` value is composed as
  `<page title> | <website title>`.
- When the Website Title setting is unset, existing page-title output is preserved.
- Both title components are plain text and must be HTML-escaped before rendering.
- The owning admin, CLI, management protocol, and configuration requirements for Website Identity live
  in `docs/admin/settings.md`.

### Website Identity Settings

- Public user-visible site branding is sourced from `settings.name`, not the legacy top-level
  `app.name`. The public navbar brand and public error pages render this value as escaped text.
- Public HTML page titles use the resolved page title plus `settings.title`:
  `<page title> | <settings.title>`. If `settings.title` is unset, only the resolved page title is
  rendered.
- Public pages render `settings.description` as a head-only
  `<meta name="description" content="...">` tag when a non-empty description is configured.
- The description meta tag is public-page-only. Admin, login, and profile shells do not render it.
- Website identity validation, management actions, CLI commands, admin controls, and compatibility
  rules are owned by `docs/admin/settings.md`.

### Public Page Footer

- Public Markdown pages always include a small backend-rendered footer
  (`[data-site-page-footer]`) with an unobtrusive `reload` link
  (`[data-site-asset-reload]`).
- The site bundle fetches every current `script[src]`, stylesheet, icon, preload, and prefetch URL
  with `cache: 'reload'`, then calls `location.reload()`, so the next document load uses fresh JS
  and CSS even when `/builtin/site.js?v=<release>` is still within its 24-hour cache lifetime.
- When the authenticated request user has the `admin` role, the same footer also shows the running
  NoPressure binary version (`[data-site-admin-version]`) beside the reload link. Anonymous
  requests and authenticated non-admin users receive no version markup.
- Login/profile SPA shells, admin SPA shells, public binary asset responses, and denied/error
  responses do not use this public footer.
- The version value is sourced from the running `nop` package version injected at process startup
  and is HTML-escaped before rendering.

### Access Control and RBAC

- Roles are defined on tags, not on content objects.
- Tag access rules determine the resolved role set for each object (see `docs/content/public-rbac.md`).
- Role storage and validation are defined in `docs/content/role-management.md`.
- If the resolved role set is empty, the object is inaccessible to non-admin users (admins retain access).
- Objects with no tags are public.

### Markdown Rendering

- Markdown content is rendered as-is; front matter is not parsed or stripped.
- `generate_html` configures `pulldown_cmark` with tables, strikethrough, footnotes, and task lists enabled.
- `process_event` enforces security rules:
  - Image sources are validated against traversal attempts and must exist locally.
  - Local links are normalized and checked against cached routes; invalid references render inline warnings.
- Output HTML is sanitized by `ammonia` (`HTML_CLEANER`) and then post-processed:
  - External anchors open in a new tab with safe `rel` attributes.
  - Eligible local file links become download links.
  - Inline `style` attributes are preserved on `img`, `figure`, `figcaption`, `p`, and `h1`-`h6` tags.
    Style properties are not filtered.

### Page Render State

Markdown page rendering must use an extensible render-state bucket rather than adding isolated
layout booleans to function signatures.

The public pipeline owns a struct with this role:

```rust
pub struct PageRenderState {
    pub disable_navbar: bool,
    pub disable_floating_nav: bool,
    pub content_width: ContentWidthMode,
    pub use_compact_width: bool,
    pub suppress_initial_content_container: bool,
    pub suppress_final_content_container: bool,
}
```

Implementation details:

- `serve_markdown_alias` initializes `PageRenderState` from cached page metadata before Markdown
  conversion. `disable_navbar` starts as `object.disable_navbar`, `disable_floating_nav` starts as
  `object.disable_floating_nav`, and `content_width` starts as the cached sidecar width mode.
- Markdown rendering updates the same state with layout facts it discovers, including compact-width
  selection and whether content-container boundaries should be suppressed. `auto` and `narrow`
  set `use_compact_width = true`; only `wide` sets `use_compact_width = false`.
- `RenderedMarkdown` returns the final `PageRenderState` with the rendered HTML and dynamic-shortcode
  flag.
- The page layout renderer consumes the final state and must not receive one-off boolean arguments
  for navbar or content-container decisions.
- Future page-layout switches should extend `PageRenderState` or focused child structs inside it,
  keeping the render pipeline's state transfer explicit and versionable.

### Leading Full-Width Shortcode Layout

Container-escape shortcodes such as `hero-img` close `.content` and `.container.content-container`
before their rendered HTML, then reopen them afterward. When the first rendered markdown block is a
container-escape shortcode, the layout must not emit an empty initial content container before that
shortcode.

Required behavior:

- If the final rendered markdown HTML starts with the exact container escape fragment from
  `RenderPipelineSupportHooks::escape_container`, strip that leading fragment and set
  `PageRenderState.suppress_initial_content_container = true`.
- If the final rendered markdown HTML ends with the exact return fragment from
  `RenderPipelineSupportHooks::return_to_container`, strip that trailing fragment and set
  `PageRenderState.suppress_final_content_container = true`.
- The layout template uses `PageRenderState` to decide whether to emit the initial container open
  fragment and final container close fragment.
- Inline `container_escape` shortcodes remain literal substitutions inside their paragraph and do
  not participate in page-boundary suppression.

#### Code Block Copy Buttons

- Code blocks must render with a server-generated copy button adjacent to the `<pre><code>` content.
- The copy button markup must be generated as part of Markdown rendering in the backend (event-stream transform); it must not be created dynamically by client-side DOM injection.
- The site bundle (`/builtin/site.js`, built from `nop/ts/site`) may attach behavior only to existing markup.

Backend implementation contract (sanitization-safe wrapper injection):

- The backend must not rely on the sanitizer to preserve copy-button markup.
- Instead, the renderer injects placeholder tokens outside the code block HTML structure, then replaces them with trusted wrapper/button HTML after sanitization (same safety model as shortcode placeholder replacement).

Placeholder token contract:

- For every Markdown code block, the HTML stream must include:
  - a wrapper-start placeholder token immediately before the `<pre><code...>` output
  - a wrapper-end placeholder token immediately after the closing `</pre>`
- Tokens must not appear inside `<code>...</code>` content.
- Tokens include a per-render nonce to avoid accidental collisions with user content:
  - `NOP_CODEBLOCK_WRAPPER_START_<nonce>`
  - `NOP_CODEBLOCK_WRAPPER_END_<nonce>`
- The nonce must be cryptographically strong, generated once per `generate_html` render, and reused for all code blocks within that render.
  - Per-block unique nonces are not required; `START` vs `END` is sufficient to keep structure correct, and a per-render nonce is sufficient for collision resistance.
- The replacement pass may count occurrences of the start/end tokens; if both counts are zero, it must skip wrapper replacement work entirely.

Backend markup contract (the trusted HTML inserted during placeholder replacement):

- A wrapper element encloses the rendered `<pre><code>` output:
  - wrapper tag: `figure`
  - required attribute: `data-site-code-block="true"`
- The wrapper includes a toolbar area (caption) containing a copy button:
  - caption tag: `figcaption`
  - button tag: `button`
  - required attributes:
    - `type="button"`
    - `data-site-code-copy="true"`
    - `aria-label="Copy code block"`
  - visible label: `Copy`

Sanitization requirements:

- The sanitizer must remain strict. The copy-button wrapper contract must not require broadening the sanitizer allowlist (the wrapper/button HTML is inserted after sanitization).
- Existing security behavior (script/link/iframe stripping, external link hardening, link validation) remains authoritative.

Site bundle requirements:

- `nop/ts/site` binds a click handler to `[data-site-code-copy]` and copies the associated code text (the sibling/descendant `<pre><code>` within the same `[data-site-code-block]` wrapper).
- The helper must not:
  - inject new copy buttons;
  - rewrite Markdown HTML structure;
  - depend on framework/runtime beyond the existing site bundle patterns.

##### Hover-Reveal Copy Icon

- The copy button shows an icon instead of text: `assets/copy.svg` is copied to `nop/builtin/copy.svg` at build time, embedded in the release binary, served at `/builtin/copy.svg`, and referenced from the server-generated button markup with `<img src="/builtin/copy.svg" alt="">`.
- The normalized SVG uses `fill="currentColor"` and `em`-based sizing so the icon inherits the themed button text color.
- The button is hidden with `opacity: 0` and revealed on `figure:hover` or `figure:focus-within`; touch devices (`@media (hover: none)`) always show it. The `pre` top-padding reservation is removed.
- Copy feedback updates `aria-label` and a visually-hidden status span (`Copied`/`Failed`); the site bundle never replaces button children.

### Floating Document Structure Panel

Public Markdown pages may render a left-side floating structure panel derived from the current
document's headings. The panel is a page-local table of contents for reader orientation; it is not
the same data model as the site navbar and must not use `nav_title`, `nav_parent_id`, `nav_order`,
aliases, or path-derived hierarchy.

#### Markdown-Source Boundary

The document structure is a model of the author's Markdown structure, not a model of the rendered
HTML document tree. Structure extraction must read the Markdown source and Markdown heading events
for author-written `#` through `######` heading syntax. It must not discover headings by scanning
rendered HTML, sanitized HTML, final page HTML, shortcode HTML, or DOM nodes.

Shortcodes may emit arbitrary trusted or sanitized HTML fragments, including elements that look like
headings in the rendered page. Those elements are shortcode presentation, not Markdown document
structure. Literal raw HTML headings in a Markdown file are also HTML content, not Markdown heading
syntax, and must not participate in the structure model.

The implementation must collect structure from the same Markdown parser/event pipeline that renders
the page. It must not run a separate raw-Markdown parse for structure, because shortcode grammar and
placeholder substitution can make a separate parse diverge from the render parser's heading event
sequence. The extraction boundary is before shortcode HTML substitution, before HTML sanitization,
and before any rendered HTML post-processing. Generated anchor IDs may be attached to all emitted
Markdown headings; the structure panel consumes only the subset selected
by the Markdown-derived structure model. Neither the navbar nor the menu drawer carries
structure links outside the dedicated structure surfaces (side panel at `>=1280px`, structure
drawer below).

Shortcode invocations are parser input syntax, not document structure. The parser pipeline must
treat successfully parsed shortcode spans as opaque for structure purposes, so Markdown-looking text
inside shortcode attributes, including newline-prefixed `#` text, cannot create headings or shift
generated heading IDs onto the wrong rendered heading.

The render pipeline records Markdown headings in document order as the same events are emitted:

```rust
struct MarkdownHeading {
    rank: u8,
    label: String,
    anchor_id: String,
}
```

This vector is the authoritative input for the floating document structure. The heading rank is the
Markdown heading level from the parser event. The label is the plain-text heading label collected
from inline heading events such as text, code, and line breaks, with raw HTML and shortcode-rendered
HTML excluded. The anchor ID is the same ID emitted on the rendered Markdown heading event.

The renderer derives `DocumentStructure` after the event traversal by applying the documented
selection rules to the `Vec<MarkdownHeading>`:

- Count heading ranks in the vector.
- Choose the shallowest rank that appears more than once as the first display level.
- Choose the shallowest deeper rank that appears at least once as the optional second display level.
- Omit ranks above the first display level and disable the structure when no rank repeats.
- Map selected vector entries into `DocumentStructureEntry` using the already assigned `anchor_id`.

This keeps anchor assignment and structure extraction aligned by construction: the heading event
that receives an anchor ID is the same heading record used later to build the floater. No positional
mapping between two separate parses is allowed.

#### Heading Selection

The renderer must build the structure from Markdown heading events before sanitized HTML is placed
in the page layout. A Markdown heading means an author-written hash heading in the source, not an
HTML tag that appears in any rendered output.

- Only Markdown headings corresponding to `h1` through `h6` participate. Shortcode-internal headings,
  raw HTML headings, and headings introduced by any post-render processing never participate.
- Heading labels are plain text extracted from the heading's rendered inline content. Markup is
  stripped, entities are decoded by the Markdown pipeline, and labels are HTML-escaped when rendered
  into the panel.
- Each displayed content heading receives a stable, unique same-page anchor ID. Duplicate labels
  receive deterministic numeric suffixes in document order. Generated IDs must not collide with
  existing generated IDs in the same render.
- The panel renders at most two levels. "First two levels" means the first two heading ranks selected
  by the rules below, not an arbitrary two items.

Selection rules:

- The first display level is the shallowest heading rank that appears more than once in the document.
  Heading ranks are evaluated from `h1` through `h6`.
- Headings above the first display level are treated as title or preamble headings and are excluded
  from the panel, even when they appear in the rendered document body.
- If no heading rank appears more than once, the document has no panel-worthy structure and the panel
  is disabled. No panel markup is emitted.
- The second display level is the shallowest heading rank deeper than the first display level that
  appears at least once, when one exists.
- Common cases:
  - One `h1`, several `h2` headings, and some `h3` headings renders an `h2`/`h3` structure.
  - No `h1`, several `h2` headings, and some `h3` headings renders an `h2`/`h3` structure.
  - Several `h1` headings and some `h2` headings renders an `h1`/`h2` structure.
  - One `h1`, one `h2`, and several `h3` headings renders an `h3` structure, with `h1` and `h2`
    treated as title/preamble headings.
- Skipped heading ranks are allowed. For example, one `h1` followed by several `h3` headings and
  some `h4` headings renders `h3` as the first display level and `h4` as the second display level.
- If only one display rank exists after applying the rules, the panel renders a single-level
  structure.
- A second-level heading without a preceding selected first-level heading is rendered as a first-level
  entry rather than being dropped, preserving access to malformed but readable documents.

#### Backend Markup Contract

- The backend renders the panel in `public/templates/main_layout.html` only when
  `disable_floating_nav = false` and the selected structure has at least one entry.
- Desktop panel root:
  `<aside class="site-doc-structure" data-site-doc-structure aria-label="Document structure">`.
- Panel navigation: `<nav class="site-doc-structure__nav">` containing an ordered or unordered list
  that preserves document order.
- The navbar renders no document-structure links. Below `1280px` the menu drawer likewise
  carries no structure links; structure access lives in the side panel (`>=1280px`) and the
  structure drawer (below `1280px`) only.
- Link elements point to the generated same-page heading anchors and expose the escaped heading
  label as their text.
- First-level and second-level entries use distinct classes or `data-site-doc-structure-level`
  attributes so CSS and active-link behavior do not infer levels from list depth alone.
- The panel must be outside `.content` so it is not affected by Bulma content typography selectors,
  but it must sit inside the page root so theme variables and dark-mode rules apply.
- Pages that set `disable_floating_nav = true` must not emit hidden placeholder panel markup.
- The panel must not change the canonical HTML title, public route, sitemap, search indexing, or
  content metadata cache contract.

#### Layout And Theme Contract

The structure panel is a quiet reading aid, not a card-heavy feature surface.

- Desktop layout hugs the panel to the content block instead of the viewport edge. At
  `>=1280px`, `main_layout.html` wraps the panel and the content wrapper in a `<div>`
  grid (`display: grid` with symmetric `1fr` gutters around a middle track capped at the content
  measure, `1152px` for wide pages via `.doc-layout--wide`), so the content column stays centered
  in the viewport while the panel fills the left gutter (track width minus both themeable
  margins, `justify-self: end`) with symmetric themeable margins (left margin equals the right
  hug gap), capped at the panel maximum width, in both compact and wide content modes. The empty
  right gutter balances the left panel, which is what keeps the content centered. Pages without an
  eligible panel render no `<aside>`, so their content keeps centering alone in the middle column.
- The panel is `position: -webkit-sticky` plus `position: sticky` (unprefixed `sticky` needs
  Safari 13) with a below-navbar top offset, a content-top alignment margin (`margin-top` equals
  the content top margin plus the content top padding, so the panel box top matches the content
  padding-box top when the page is at the top; sticky takes over on scroll), `justify-self: end`,
  and margin-based spacing (never
  flex/grid `gap`, which needs Safari 14.1+). It must not overlap readable content.
- The content container width is font-relative: `max-width: min(var(--size-content-measure, 75ch), 100%)`,
  which yields roughly 66 characters of text after the `.content` side padding at the default body
  size and tracks theme `font-body-size` changes and zoom automatically. `is-wide` remains the
  author opt-in for non-prose content (tables, media). Breakpoints stay viewport-px (media queries
  cannot see theme font sizes); they govern only panel and top-bar presentation, never the measure.
- Sizing theme knobs (each with a preset fallback so absent variables keep the default look):
  `size-content-measure` (default `75ch`), `size-doc-structure-width` (panel maximum width,
  default `24rem`), `size-doc-structure-gap` (symmetric panel margin, default `2rem`), and
  `size-doc-structure-top` (default below-navbar offset).
- Container-escape shortcodes (e.g. `hero-img`) break out of the content column at any page
  position through one uniform mechanism: the escape closes `.content`,
  `.container.content-container`, and `.content-wrapper`; the payload renders wrapped in a
  full-width band (`<div class="site-doc-band">`, `grid-column: 1 / -1`); then wrapper, container,
  and content reopen. The pipeline owns the fully balanced stream. A leading escape emits no close
  divs because nothing is open yet: the band comes first, followed by the first wrapper and
  container opening, which is the reopening. A trailing escape leaves no empty segment.
- Any `hero-img` on the page omits only the overlay document-structure aside (wide effect only);
  the structure drawer and topbar button are unchanged, so narrow screens keep full structure
  access.
- Below `1280px` the legacy navbar (including the hamburger) is hidden and replaced by a floating
  top bar with exactly three controls: a left circular `<` button rendered only when document
  structure entries exist, the centered site title, and a right circular `>` button that is always
  present.
- Tapping `>` slides the navigation drawer in right-to-left; its top-left back chevron `<` reverses
  the slide back to content. Tapping `<` slides the structure drawer in left-to-right with a neatly
  aligned link list; its chevron flips to `>` in place and returns to content. Tapping a structure
  link dismisses the drawer leftward first, then jumps to the anchor, and the bundle scrolls the
  target heading just below the floating top bar so it is never obscured. Edge swipes open the
  drawers too (left-to-right for structure, right-to-left for navigation) where the browser
  supports touch events; unsupported browsers get no handlers and no message. While a drawer is
  open, the opposite swipe toward its home edge closes it; a swipe continuing in the open
  direction does nothing. Opening swipes are suppressed where a horizontal swipe already means
  something: pages that scroll sideways, or gestures starting inside a nested horizontal scroller
  (wide tables, code blocks) — there the top-bar buttons are the only path in. Closing swipes are
  never suppressed.
- Both drawer headers center their title with a spacer-balanced back chevron: menu drawer keeps the
  back chevron on the left, structure drawer puts it on the right. The structure drawer list has a
  comfortable left margin with indented second-level entries. All three narrow titles are home links,
  matching the clickable desktop brand, with unchanged visuals.
- The menu drawer order is: inline search field, edit/admin buttons side by side at full control
  size (under the `userMenu.ts` conditions), profile row with chevron expander (authenticated
  only), then navigation with chevron expanders for parents. Thin divider rules separate the
  buttons from the profile row and the profile row from the navigation. Navigation sub-menus expand
  below their parent item, never as a side flyout. Drawers are fixed overlays that never shift
  content; tall drawer content scrolls internally. The drawer back chevron and `Esc` return to
  content with focus restored to the invoking control.
- Every collapsible row (navigation parents, profile row, in drawers and on desktop alike) uses one
  explicit chevron element instead of the Bulma `::after` down-arrow: right-pointing when collapsed,
  down-pointing when open, `aria-expanded` synced, second tap collapses back to right-pointing.
  The profile row chevron sits right-aligned on the right like every other submenu chevron,
  with identical geometry (same right inset, same vertical centering).
  Desktop hover-open behavior is preserved; the chevron follows the JS open-state class.
- The default panel has no shadow.
- The default border color derives from the same border variable used for horizontal rules and other
  public content edges: `var(--color-border-light)` in light mode and `var(--color-border-dark)` in
  dark mode.
- The default border width derives from `var(--border-width-control, 1px)`.
- The default radius uses the closest existing page-control radius. If implementation does not add a
  dedicated card radius token, use `var(--size-control-radius, 8px)` so it matches the existing
  link-card shape by default.
- The default background derives from `var(--color-content-background-light)` and
  `var(--color-content-background-dark)`.
- Text derives from `var(--color-text-secondary-light)` / `var(--color-text-secondary-dark)`;
  active and hovered links derive from `var(--color-content-link-light)` /
  `var(--color-content-link-dark)`.
- Focus rings use the same public content link variables as other public controls.
- Theme overrides may be added with the `doc-structure` prefix only where existing variables are
  insufficient. Candidate variables, if needed:
  - `doc-structure-background-light`
  - `doc-structure-background-dark`
  - `doc-structure-border-light`
  - `doc-structure-border-dark`
  - `doc-structure-radius`
  - `doc-structure-shadow`
  - `doc-structure-active-color-light`
  - `doc-structure-active-color-dark`
- Any new variables must be documented in `docs/content/themes.md` and `docs/user/theming.md`, and
  the built-in default theme must remain visually correct when those variables are absent.

#### Site Bundle Behavior

The site bundle enhances backend-rendered panel markup. It must stay within the classic public IIFE
model and the Safari 12 browser floor.

- The bundle initializes document-structure highlighting when `[data-site-doc-structure]` links
  exist; the state syncs across the side panel and the structure drawer links.
- Active section highlighting is based on scroll position and generated heading anchors.
- The active state is reflected by a class on the corresponding panel link and `aria-current="true"`;
  inactive links must not retain `aria-current`.
- The implementation must avoid unsupported browser APIs unless they are already polyfilled. Do not
  require `IntersectionObserver`; use scroll/resize listeners with bounded work or a feature-detected
  enhancement that has an equivalent fallback.
- Use `requestAnimationFrame` or equivalent throttling so scroll listeners do not do unbounded DOM
  work.
- Respect `prefers-reduced-motion` in CSS for panel, navbar, drawer, and chevron transitions.
- A click on a heading link in the desktop structure panel (`[data-site-doc-structure]`)
  calls `preventDefault`, leaves the URL unchanged, and eases the page with `setTimeout`
  / `scrollTop` (~650 ms; cubic ease-in for the first 35%, cubic ease-out for the rest,
  joined at equal speed so the scroll keeps settling gently instead of parking early).
  The heading `id` is removed for the ease so
  Safari cannot fragment-scroll to a live target, then restored when the ease finishes
  or is cancelled. Each tick writes `documentElement.scrollTop`, `body.scrollTop`, and
  two-argument `window.scrollTo`. No `ScrollToOptions`, no `history.pushState`, no hash
  write. The ease runs regardless of `prefers-reduced-motion`. Wheel or touch during the
  ease cancels it. Top and bottom entries in that panel use the same ease. The structure
  drawer still jumps immediately.

#### Page Top And Bottom Navigation

- Both document structure surfaces carry a top entry and a bottom entry alongside the
  heading links: the desktop panel (`>=1280px`) and the structure drawer (below
  `1280px`). Both surfaces render them through the shared structure-entry helper so
  they can never drift out of sync.
- Top entry: always shows the up-chevron-to-bar icon, left-aligned, followed by the
  excluded title/preamble heading's escaped label (a single leading `h1` per the
  selection rules above) when one exists. It always scrolls to the absolute page
  top, never to an `h1` anchor, so behavior is identical with and without a title.
- Bottom entry: always icon-only, scrolling to the document bottom.
- Icons are inline SVGs following the existing search-magnifier pattern
  (`currentColor` fill, `em`-based sizing, `aria-hidden="true"` on the SVG): an
  up-chevron with a top bar for "go to top" and a down-chevron with a bottom bar for
  "go to bottom". The buttons expose `aria-label="Go to top"` / `"Go to bottom"`.
  The CSS expander chevron and the `‹`/`›` topbar glyphs are not reused for these
  entries.
- No new data-model or sidecar fields. `disable_floating_nav = true` suppresses the
  top/bottom entries together with the panel, and hero pages keep the existing
  overlay-panel omission on wide screens.
- Bundle behavior: desktop-panel top and bottom clicks use the same ease as
  heading links. In the structure drawer the drawer dismisses first, then the
  page jumps immediately by writing `documentElement` / `body` `scrollTop`. Top
  and bottom entries never participate in active-link highlighting or
  `aria-current` state.
- Theme: icon buttons reuse the structure link color variables with the standard
  content-link focus ring; sizing and dark-mode rules live in `theme-preset.css`
  next to the existing structure styles.
- Tests: Rust render assertions cover title-top, icon-top, bottom icon, both
  surfaces, and the suppressed (`disable_floating_nav`) case; `navigation.test.ts`
  covers the panel ease (URL left unchanged, reduced motion, and cancellation)
  and drawer dismissal; Playwright covers the desktop panel ease and the narrow
  drawer jump.

### Scroll-Reveal Navbar

When a public Markdown page renders the top navbar, normal downward reading keeps the current
behavior: the navbar is part of the document flow and scrolls out with the page. If the reader then
scrolls upward while the original navbar is above the viewport, the same navbar visually floats down
from the top and remains available until the reader resumes downward scrolling or reaches the
navbar's original position.

Required behavior:

- The behavior applies only when `PageRenderState.disable_navbar` is `false` and the navbar markup is
  rendered.
- Pages with `disable_navbar = true` have no navbar markup and no scroll-reveal navbar state.
- Initial page load renders the navbar in normal document flow.
- Scrolling down never pins the navbar preemptively; it scrolls out naturally.
- When scroll direction changes upward and the navbar's original layout box is no longer visible,
  the navbar receives a revealed floating state and is positioned at the top of the viewport.
- When the reader scrolls downward again, the floating state is removed so the navbar exits upward
  rather than remaining sticky.
- When the reader returns to the original top-of-page navbar position, the floating state is removed
  and the navbar occupies its normal flow position.
- The revealed navbar must preserve existing search, dropdown, admin edit, admin, profile,
  and logout controls.
- The revealed navbar must not obscure the search overlay, modal-like surfaces, or open dropdowns.
  Existing overlay z-index ownership remains authoritative.
- Scroll-reveal applies at `>=1280px`, where the legacy navbar renders. Below `1280px` the
  floating top bar stays visible instead and never scroll-reveals.
- CSS transitions should be short and theme-neutral. Reduced-motion users receive immediate state
  changes without sliding animation.
- The behavior is implemented in `nop/ts/site/src/navigation.ts` or a focused public-site module
  initialized from `main.ts`; it must not require a separate script tag or module script.

### Shortcodes

- Raw Markdown is first passed through `process_text_with_shortcodes`, which replaces valid invocations with placeholders and records rendered HTML.
- Rendered shortcode HTML is keyed by unique `SHORTCODE_HASH_*` placeholders so it can be reinserted after sanitization without escaping.
- After Markdown rendering and sanitization, `replace_shortcode_placeholders` substitutes placeholders in a paragraph-aware way: standalone placeholder paragraphs are replaced as a whole, while inline placeholders are replaced literally.
- Built-in shortcodes live under `public/shortcode/` and include `start-unibox`, `video`, `link-card`,
  `tag-list`, and `hero-img`.
- The `tag-list` shortcode renders lists of content based on tags and uses the same listing HTML style as the existing listing helpers.

### Themes and Layout

Theme file format, variables, and rendering details live in `docs/content/themes.md`.
Public markdown pages support a sidecar `content_width` mode. Width selection is fully manual:
`auto` and `narrow` always use the font-relative content measure regardless of paragraph length;
only `wide` uses 1152px. Pages with long paragraphs that previously rendered wide via the retired
paragraph-length heuristic keep the normal width unless their sidecar sets `wide` explicitly. The navbar container is not
affected unless the page sidecar sets `disable_navbar` to `true`, in which case the navbar (and,
below `1280px`, the floating top bar and drawers) is omitted for that page.

### Admin Edit Button (Public Navbar)

- Markdown pages render `data-site-content-id` (hex) in `public/templates/main_layout.html` for frontend use.
- The site menu script (`nop/ts/site/src/userMenu.ts`) calls `/api/profile`; when the response includes the
  admin menu item, it inserts an `Admin` button immediately to the left of the profile dropdown,
  and the same edit/admin/profile rows into the menu drawer (`[data-site-drawer-rows]`), ordered
  after the inline search field and before the profile row and navigation.
- When a content ID is present, it also inserts an `Edit` button to the left of the admin button.
- The `Admin` button uses the admin menu item `href` from the profile payload to avoid leaking the path.
- The edit button opens to `<admin_path>/pages/edit/<content_id>` in the same tab. Admin access is treated as
  all-or-nothing; if the profile payload reports the admin menu item, the buttons are shown.

### Navigation

- The top navigation bar is explicit; no hierarchy is derived from paths.
- A page with `disable_navbar = true` can still be a navigation item for other pages. The flag only
  controls whether the navbar renders on that page's own public response.
- `nav_title` (string) determines inclusion; items without `nav_title` are excluded from navigation.
- Navigation labels are treated as plain text and HTML-escaped at render time.
- `nav_parent_id` (ContentId hex string) defines parent/child grouping; only root items (no parent) render top-level links.
- `nav_order` (integer) defines ordering for both top-level items and their children; lower numbers render first.
- Children are rendered under their parent in `nav_order` order; ties are resolved alphabetically by nav title
  (case-insensitive), then alias for determinism. The desktop navbar renders parents as hoverable
  dropdowns; the menu drawer renders the same items as chevron expander rows.
- Nav paths derive from the content alias (or `id/<hex>` when alias is empty); changing the alias for
  a navbar item is a navigation change and must bump the release tracker.
- Missing parent IDs or nodes are skipped with a warning so navigation generation never panics.
- Parent selection data is sourced from the page metadata cache and exposed via the content management domain.

### Static Assets and Streaming

- Non-Markdown files are served via `serve_static_file`.
- MIME types are read from sidecar metadata.
- Range requests are supported when `config.streaming.enabled` is true.

### Error Handling

- 404: `templates::error::serve_404` handles missing aliases, invalid routes, and access-denied responses for authenticated users.
- 500: `templates::error::serve_500` covers filesystem read failures and unexpected panics.
- Access denial redirects anonymous users to `/login?return_path=...`.

### Extension Tips

- New shortcodes should register in `create_default_registry_with_config` and ship templates under `public/shortcode/templates/`.
- New public endpoints must be registered in `public::configure` and should respect the same cache and security checks.
- For content-derived routes, use `PageMetaCache` to validate existence and permissions before touching the filesystem.

### Public Search Integration

- Public search UX and API contract live in `docs/content/search-ux.md`.
- Public endpoint `GET /api/search` returns search hits for the site bundle with payload fields:
  `id`, `alias`, and `title`.
- Public site search behavior is implemented in the existing TypeScript bundle (`nop/ts/site/src/search.ts`)
  and initialized from `nop/ts/site/src/main.ts`.
- The navbar search trigger remains always visible at `>=1280px`. Below `1280px` there is no trigger;
  the menu drawer opens with the inline search field instead.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
