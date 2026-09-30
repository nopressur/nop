// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { convertMarkdownLinkToLinkCard } from "./markdownLinkCard";

describe("convertMarkdownLinkToLinkCard", () => {
  it("converts a selected markdown link into a noblank link-card shortcode", () => {
    const content = "Before\n[Docs](/docs/home)\nAfter";
    const start = content.indexOf("[Docs]");
    const end = content.indexOf("\nAfter");

    const result = convertMarkdownLinkToLinkCard(content, start, end);

    expect(result).toMatchObject({
      startOffset: start,
      endOffset: end,
      shortcode: '((link-card title="Docs" link="/docs/home" noblank))',
      title: "Docs",
      link: "/docs/home",
    });
    expect(result?.cursorOffset).toBe(start + result!.shortcode.length);
  });

  it("converts the markdown link containing the cursor", () => {
    const content = "Intro [Portal](https://example.test/path) outro";
    const cursor = content.indexOf("Portal");

    const result = convertMarkdownLinkToLinkCard(content, cursor, cursor);

    expect(result?.shortcode).toBe(
      '((link-card title="Portal" link="https://example.test/path" noblank))',
    );
  });

  it("trims surrounding whitespace when the selected text is one link", () => {
    const content = "A\n  [Docs](/docs/home)  \nB";
    const start = content.indexOf("  [");
    const end = content.indexOf("\nB");

    const result = convertMarkdownLinkToLinkCard(content, start, end);

    expect(result?.startOffset).toBe(content.indexOf("[Docs]"));
    expect(result?.endOffset).toBe(content.indexOf(")  ") + 1);
    expect(result?.shortcode).toBe('((link-card title="Docs" link="/docs/home" noblank))');
  });

  it("uses the link destination as the title when label text is blank", () => {
    const content = "[](/docs/blank)";

    const result = convertMarkdownLinkToLinkCard(content, 0, 0);

    expect(result?.shortcode).toBe(
      '((link-card title="/docs/blank" link="/docs/blank" noblank))',
    );
  });

  it("extracts the destination before an inline link title", () => {
    const content = '[Docs](/docs/home "Documentation")';

    const result = convertMarkdownLinkToLinkCard(content, content.length - 2, content.length - 2);

    expect(result?.shortcode).toBe('((link-card title="Docs" link="/docs/home" noblank))');
  });

  it("supports angle-wrapped destinations", () => {
    const content = "[Docs](</docs/home page>)";

    const result = convertMarkdownLinkToLinkCard(content, 0, content.length);

    expect(result?.shortcode).toBe(
      '((link-card title="Docs" link="/docs/home page" noblank))',
    );
  });

  it("escapes shortcode attributes with JSON.stringify rules", () => {
    const content = String.raw`[A \"quote\" \\ path](/docs/card\(1\))`;

    const result = convertMarkdownLinkToLinkCard(content, 0, content.length);

    expect(result?.shortcode).toBe(
      '((link-card title="A \\"quote\\" \\\\ path" link="/docs/card(1)" noblank))',
    );
  });

  it("does not convert markdown images", () => {
    const content = "![Diagram](/images/diagram.png)";

    const result = convertMarkdownLinkToLinkCard(content, 0, content.length);

    expect(result).toBeNull();
  });

  it("does not convert escaped markdown link syntax", () => {
    const content = String.raw`\[Docs](/docs/home)`;

    const result = convertMarkdownLinkToLinkCard(content, 2, 2);

    expect(result).toBeNull();
  });

  it("does not convert a selection containing more than one link", () => {
    const content = "[One](/one) and [Two](/two)";

    const result = convertMarkdownLinkToLinkCard(content, 0, content.length);

    expect(result).toBeNull();
  });
});
