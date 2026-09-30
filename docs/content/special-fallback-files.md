# Special Fallback Files

Status: Developed

## Objectives

- Define a public routing mechanism for root-level files that may be supplied by uploaded content
  and fall back to built-in assets when no public uploaded file is available.
- Keep public page templates stable by allowing fixed root references such as `/favicon.ico`.
- Introduce `favicon.ico` as the first special fallback file without adding a dedicated top-level
  Actix route for that filename.

## Technical Details

### Routing Model

Special fallback files are root-level public paths handled inside the existing public catch-all
pipeline. They must not be registered as dedicated application routes like `/robots.txt` or
`/sitemap.xml`.

`nop-public::handlers::handle_route` owns the decision point:

1. Run the existing public route security checks.
2. Canonicalize the requested route path.
3. Check whether the canonical alias matches an entry in the special fallback file registry.
4. If it matches, resolve through special fallback handling and return the response immediately.
5. If it does not match, continue through the existing public alias access, render, stream, and
   access-denial flow.

Special fallback handling runs before ordinary access denial. A restricted uploaded object at a
special fallback alias must not redirect anonymous users to login and must not leak existence
through a different response. It is treated as unavailable for special-file purposes and falls back
to the built-in asset.

### Registry Contract

The special fallback file registry is a data-driven list in the public routing layer. Adding another
special file requires adding a registry entry and any required validation rule, not adding a new
top-level route.

Each entry defines:

- `alias`: the canonical public alias to intercept, for example `favicon.ico`.
- `builtin_filename`: the filename under the built-in asset provider, for example `favicon.ico`.
- `uploaded_object_policy`: validation for uploaded content before it may override the built-in
  fallback.

Current registry:

| Alias | Built-in filename | Uploaded object policy |
| --- | --- | --- |
| `favicon.ico` | `favicon.ico` | Must be anonymously accessible, non-Markdown, and image MIME. |

### Built-in Asset Provider

`nop-rt-builtin` remains the provider of built-in asset bytes. It exposes a reusable helper for
serving a named built-in asset so both routes below use the same implementation:

- `/builtin/{filename:.*}` for direct built-in asset URLs.
- Public special fallback handling for root-level fallback files.

If the built-in provider cannot find the requested fallback asset, the special fallback response is
404.

### Uploaded Object Resolution

For a special fallback file request, uploaded content may override the built-in asset only when all
entry policy checks pass.

For `favicon.ico`, the checks are:

- `PageMetaCache::get_by_alias("favicon.ico")` returns an object.
- `PageMetaCache::user_has_access("favicon.ico", None) == Some(true)`.
- The object is not Markdown.
- The object MIME type starts with `image/`.

When the uploaded object passes validation, the existing public blob-serving path streams or serves
the object bytes with the same range and cache behavior used for other public non-Markdown content.

When the uploaded object is missing, inaccessible to anonymous users, denied by resolved role
rules, Markdown, or not an image MIME type, the built-in fallback is served instead.

### Favicon Behavior

Public page templates reference the favicon with a fixed root URL:

```html
<link rel="icon" href="/favicon.ico">
```

The template must not compute uploaded-vs-built-in favicon URLs and must not add release or content
cache-busting query parameters for the favicon. The route response determines whether `/favicon.ico`
is uploaded public content, the built-in favicon, or 404.

### Testing Scope

Required targeted tests:

- `/favicon.ico` serves an uploaded object when the alias exists, is public to anonymous users, is
  non-Markdown, and has an image MIME type.
- `/favicon.ico` serves the built-in favicon when the alias is missing.
- `/favicon.ico` serves the built-in favicon when the uploaded alias exists but is not anonymously
  accessible.
- `/favicon.ico` serves the built-in favicon when the uploaded alias is Markdown or has a non-image
  MIME type.
- `/favicon.ico` returns 404 when no valid uploaded object is available and the built-in favicon is
  unavailable.
- `/builtin/favicon.ico` remains served directly by the built-in route.
- Playwright E2E coverage starts a real server with and without a seeded public `favicon.ico` alias,
  verifies the public layout references `/favicon.ico`, and compares `/favicon.ico` responses
  against uploaded and built-in bytes.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
