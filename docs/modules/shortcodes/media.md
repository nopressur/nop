# Media Shortcodes

Status: Developed

## Objectives

- Document shortcodes that embed media (audio, video, image-derived elements) in markdown content.

See `docs/modules/shortcodes.md` for the parser, registry, and substitution mechanism that all shortcodes share.

## Technical Details

### `video`

Renders an HTML5 `<video>` element with optional dimensions and controls.

**Syntax**: `((video src="path" [width="pixels"] [height="pixels"] [controls="true|false"]))`

**Attributes**:

- `src` (required): Video file path.
- `width` (optional): Video width in pixels.
- `height` (optional): Video height in pixels.
- `controls` (optional): Show video controls. Defaults to `true`. Set to `"false"` to disable.

**Examples**:

```markdown
((video src="demo.mp4"))
((video src="demo.mp4" width="800" height="600"))
((video src="demo.mp4" controls="false"))
```

**Implementation notes**:

- Handler: `video::handle_video_shortcode` in `nop/crates/nop-public/src/shortcode/video.rs`.
- Template: `public/shortcode/video.html`.
- Sanitises attributes; refuses to render when `src` is missing (the source shortcode is left in place so authors can spot the omission).
- Registered with the default `ShortcodeType` (neither `dynamic` nor `container_escape`).

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
