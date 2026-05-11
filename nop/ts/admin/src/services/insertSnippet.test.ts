// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import type { ContentListItem } from "./content";
import {
  type HeroOptions,
  buildModalInsertSnippet,
  defaultHeroOptions,
} from "./insertSnippet";

function makeItem(overrides: Partial<ContentListItem> = {}): ContentListItem {
  return {
    id: "abc123",
    alias: "media/hero",
    title: "Hero",
    mime: "image/png",
    tags: [],
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: null,
    isMarkdown: false,
    ...overrides,
  };
}

describe("buildModalInsertSnippet", () => {
  describe("non-hero modes", () => {
    it("emits markdown image syntax for image mode", () => {
      const snippet = buildModalInsertSnippet(makeItem(), "image");
      expect(snippet).toBe("![Hero](/media/hero)");
    });

    it("emits markdown link syntax for link mode", () => {
      const snippet = buildModalInsertSnippet(makeItem(), "link");
      expect(snippet).toBe("[Hero](/media/hero)");
    });

    it("emits video shortcode for video mode with JSON-stringified src", () => {
      const snippet = buildModalInsertSnippet(makeItem({ alias: "videos/demo" }), "video");
      expect(snippet).toBe('((video src="/videos/demo"))');
    });

    it("uses /id/<id> when alias is empty", () => {
      const snippet = buildModalInsertSnippet(makeItem({ alias: "" }), "image");
      expect(snippet).toBe("![Hero](/id/abc123)");
    });
  });

  describe("hero mode", () => {
    it("emits hero-img with only src when no options are set", () => {
      const snippet = buildModalInsertSnippet(makeItem(), "hero", defaultHeroOptions());
      expect(snippet).toBe('((hero-img src="/media/hero"))');
    });

    it("falls back to default options when none are provided", () => {
      const snippet = buildModalInsertSnippet(makeItem(), "hero");
      expect(snippet).toBe('((hero-img src="/media/hero"))');
    });

    it("includes title and subtitle when set", () => {
      const opts: HeroOptions = {
        ...defaultHeroOptions(),
        title: "Welcome",
        subtitle: "Built for nopressure",
      };
      const snippet = buildModalInsertSnippet(makeItem(), "hero", opts);
      expect(snippet).toBe(
        '((hero-img src="/media/hero" title="Welcome" subtitle="Built for nopressure"))',
      );
    });

    it("appends each flag token when its option is true", () => {
      const opts: HeroOptions = {
        title: "",
        subtitle: "",
        lightify: true,
        darkify: true,
        lightShadow: true,
        darkShadow: true,
      };
      const snippet = buildModalInsertSnippet(makeItem(), "hero", opts);
      expect(snippet).toBe(
        '((hero-img src="/media/hero" lightify darkify light-shadow dark-shadow))',
      );
    });

    it("omits empty title and subtitle from the snippet", () => {
      const opts: HeroOptions = {
        title: "",
        subtitle: "",
        lightify: true,
        darkify: false,
        lightShadow: false,
        darkShadow: false,
      };
      const snippet = buildModalInsertSnippet(makeItem(), "hero", opts);
      expect(snippet).toBe('((hero-img src="/media/hero" lightify))');
      expect(snippet).not.toContain('title=""');
      expect(snippet).not.toContain('subtitle=""');
    });

    it("escapes embedded quotes and backslashes via JSON.stringify", () => {
      const opts: HeroOptions = {
        ...defaultHeroOptions(),
        title: 'She said "hi" \\ now',
        subtitle: 'with " inside',
      };
      const snippet = buildModalInsertSnippet(makeItem(), "hero", opts);
      // JSON.stringify escapes `"` to `\"` and `\` to `\\` (inside the
      // surrounding `"…"`), which exactly matches the shortcode parser's
      // quoted-value grammar.
      expect(snippet).toBe(
        '((hero-img src="/media/hero" title="She said \\"hi\\" \\\\ now" subtitle="with \\" inside"))',
      );
    });

    it("preserves option order: src first, title, subtitle, then flags", () => {
      const opts: HeroOptions = {
        title: "T",
        subtitle: "S",
        lightify: true,
        darkify: true,
        lightShadow: true,
        darkShadow: true,
      };
      const snippet = buildModalInsertSnippet(makeItem(), "hero", opts);
      const srcIdx = snippet.indexOf("src=");
      const titleIdx = snippet.indexOf("title=");
      const subtitleIdx = snippet.indexOf("subtitle=");
      const lightifyIdx = snippet.indexOf("lightify");
      const darkifyIdx = snippet.indexOf("darkify");
      const lightShadowIdx = snippet.indexOf("light-shadow");
      const darkShadowIdx = snippet.indexOf("dark-shadow");
      expect(srcIdx).toBeLessThan(titleIdx);
      expect(titleIdx).toBeLessThan(subtitleIdx);
      expect(subtitleIdx).toBeLessThan(lightifyIdx);
      expect(lightifyIdx).toBeLessThan(darkifyIdx);
      expect(darkifyIdx).toBeLessThan(lightShadowIdx);
      expect(lightShadowIdx).toBeLessThan(darkShadowIdx);
    });
  });
});
