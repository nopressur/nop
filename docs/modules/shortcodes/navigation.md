# Navigation Shortcodes

Status: Developed

## Objectives

- Document shortcodes that route the reader to other content: links, search, URL entry.

See `docs/modules/shortcodes.md` for the parser, registry, and substitution mechanism that all shortcodes share.

## Technical Details

### `link-card`

Produces a Bulma-styled card linking to an external or internal URL.

**Syntax**: `((link-card title="text" link="url" [noblank]))`

**Attributes**:

- `title` (required): Display title for the link.
- `link` (required): Target URL. Can include `javascript:` URLs for trusted operator use.
- `noblank` (optional flag): Prevent opening in a new tab. By default, links open in `_blank`.

**Examples**:

```markdown
((link-card title="Example Site" link="https://example.com"))
((link-card title="Internal Link" link="/page" noblank))
```

**Implementation notes**:

- Handler: `link_card::handle_link_card_shortcode` in `nop/crates/nop-public/src/shortcode/link_card.rs`.
- Template: `public/shortcode/link_card.html`.
- Auto-generates background gradients using helpers in `public::shortcode::color_hsv`.
- Registered with the default `ShortcodeType` (neither `dynamic` nor `container_escape`).

### `start-unibox`

Renders a universal search or URL box. The user can type either a URL (which is normalised and navigated to) or a search term (which is substituted into a configured search URL).

**Syntax**: `((start-unibox [label="placeholder"] [search="https://…/?q=<QUERY>"] [blank]))`

**Attributes**:

- `label` (optional): placeholder text. Defaults to `"Enter a URL or search term..."`.
- `search` (optional): custom search URL containing `<QUERY>`. Falls back to `config.shortcodes.start_unibox`.
- `blank` (optional flag): open results in a new tab.

**Examples**:

```markdown
((start-unibox))
((start-unibox label="Search the docs" search="https://duckduckgo.com/?q=<QUERY>"))
((start-unibox blank))
```

**Implementation notes**:

- Handler: `unibox::handle_start_unibox_shortcode` in `nop/crates/nop-public/src/shortcode/unibox.rs`. Config-aware — captures `ValidatedConfig` via the registration closure.
- Template: `public/shortcode/start_unibox.html`. Injects a unique element ID for JS bindings.
- Validates the search URL: must be `http://`/`https://` and contain a `<QUERY>` placeholder.
- Registered with the default `ShortcodeType`.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
