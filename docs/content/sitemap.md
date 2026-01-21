# Sitemap and Robots

Status: Developed

## Objectives

- Serve live `/robots.txt` and `/sitemap.xml` content for public-facing URLs.
- Keep sitemap and robots behavior aligned with canonical URL rules.
- Centralize reserved paths and exclusions so aliases, sitemap entries, and robots rules stay consistent.

## Technical Details

### Endpoints (in scope)

- `GET /robots.txt`
- `GET /sitemap.xml`

### Data sources and live generation

- Responses must be generated live per request from the current runtime root and configuration.
- Do not add a dedicated in-memory cache for robots or sitemap responses.
- Use the existing `PageMetaCache` for canonical content metadata; do not introduce a separate sitemap cache layer.
- `PageMetaCache` must store a `last_modified` timestamp for each object derived from the latest
  modification time between the content blob and its sidecar file.

### Canonical URL rules

- Only include Markdown documents.
- Only include Markdown documents with public access (exclude restricted/deny roles).
- Emit the alias URL when an alias exists; otherwise emit `/id/<hex>`.
- Output absolute URLs with the request scheme/host and the canonical trailing-slash policy.

### Base URL selection

- Build absolute URLs from the incoming request scheme/host.
- Do not introduce a dedicated base URL configuration for sitemap generation.
- Spoofed host headers only affect the requester; they do not create a security risk by
  themselves, but they can generate incorrect sitemap output for that request.
- When running behind a proxy or CDN, ensure the request host/scheme represent the public origin,
  otherwise crawlers will receive incorrect URLs.

### Reserved paths and exclusions (single source of truth)

Maintain a canonical registry of paths used by:

- Alias validation (cannot be used as aliases).
- Sitemap inclusion (excluded from sitemap output).
- Robots disallow rules (published, non-sensitive exclusions).

Initial entries must include:

- `robots.txt`
- `sitemap.xml`
- `id/`
- `login/`
- `builtin/`
- `api/`
- configured admin path prefix

Robots disallow rules must not publish the configured admin path. This is a conscious choice to avoid disclosing a potentially random, unguessable admin path. Admin endpoints remain excluded from the sitemap and protected by auth and routing rules.

### Robots.txt rules

- Format: UTF-8 text with `User-agent`, `Disallow`, optional `Allow`, and `Sitemap` lines.
- `Sitemap:` must point to `/sitemap.xml` and may appear once or multiple times.
- Wildcards follow Google rules: `*` for any characters and `$` for end-of-URL matching. Longest-match wins; ties favor the least restrictive rule.

Recommended baseline template (excluding admin path by design):

```txt
User-agent: *
Disallow: /login/
Disallow: /api/
Disallow: /builtin/
Allow: /

Sitemap: https://example.com/sitemap.xml
```

### Sitemap.xml rules

- Implement the sitemaps.org XML protocol.
- Required fields: `<loc>`.
- Optional field: `<lastmod>` only when it reflects the last significant content update.
- Do not emit `<changefreq>` or `<priority>`; they are ignored by major engines.
- XML must be UTF-8 and entity-escape all values.

Minimal example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/foo</loc>
    <lastmod>2026-01-20</lastmod>
  </url>
</urlset>
```

### HTTP response details

- `robots.txt`: `Content-Type: text/plain; charset=utf-8`
- `sitemap.xml`: `Content-Type: application/xml; charset=utf-8`
- Responses may set `ETag` or `Last-Modified`, but server-side memory caching is not allowed.

### Submission and discovery

- Search engines should discover the sitemap through the `Sitemap:` line in robots.txt.
- Do not rely on deprecated sitemap ping endpoints; use robots.txt and webmaster tools instead.

### Deferred requirements (tracked, not implemented in initial scope)

The following requirements must remain documented but are intentionally out of scope for the first delivery:

- Enforce sitemap size limits (50,000 URLs or 50 MB uncompressed per sitemap file).
- Split into a sitemap index (`/sitemap_index.xml`) and part files (`/sitemaps/sitemap-0001.xml`, etc.) when limits are exceeded.
- Reserve `/sitemap_index.xml` and `/sitemaps/` paths if sitemap splitting is introduced.
- Exclude content based on meta robots or X-Robots-Tag once those features exist.

### Testing scope

- `/robots.txt` and `/sitemap.xml` render live from current on-disk content and config.
- Reserved paths cannot be used as aliases and are excluded from sitemap output.
- Robots output never discloses the configured admin path.
- `<lastmod>` reflects the latest modification time between the blob and sidecar files.
- XML is well-formed and uses the sitemaps.org namespace.

## References

[1]: https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap "Build and Submit a Sitemap | Google Search Central | Documentation | Google for Developers"
[2]: https://developers.google.com/crawling/docs/robots-txt/robots-txt-spec "How Google Interprets the robots.txt Specification | Google Crawling Infrastructure | Crawling infrastructure | Google for Developers"
[3]: https://www.sitemaps.org/protocol.html "sitemaps.org - Protocol"
[4]: https://blogs.bing.com/webmaster/february-2023/The-Importance-of-Setting-the-lastmod-Tag-in-Your-Sitemap "The Importance of Setting the lastmod Tag in Your Sitemap"
[5]: https://developers.google.com/crawling/docs/robots-txt/submit-updated-robots-txt "Updating Your Robots.txt File"
[6]: https://blogs.bing.com/webmaster/August-2009/Crawl-delay-and-the-Bing-crawler%2C-MSNBot "Crawl delay and the Bing crawler, MSNBot"
[7]: https://www.bing.com/webmasters/help/Sitemaps-3b5cf6ed "Sitemaps - Bing Webmaster Tools"
[8]: https://developers.google.com/search/blog/2023/06/sitemaps-lastmod-ping "Sitemaps ping endpoint is going away"

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
