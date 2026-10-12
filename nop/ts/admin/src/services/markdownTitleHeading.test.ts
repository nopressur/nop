// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { insertTitleAsPageHeading } from "./markdownTitleHeading";

describe("insertTitleAsPageHeading", () => {
  it("replaces an existing first-line H1 without adding blank lines", () => {
    const result = insertTitleAsPageHeading("# New Page\n\nKeep this body.\n", "Getting Started");

    expect(result.replaced).toBe(true);
    expect(result.content).toBe("# Getting Started\n\nKeep this body.\n");
    expect(result.cursorOffset).toBe("# Getting Started\n\n".length);
    expect(result.content.slice(result.cursorOffset)).toBe("Keep this body.\n");
  });

  it("replaces only the H1 text when the heading has no following blank line", () => {
    const result = insertTitleAsPageHeading("# Old Title\nBody immediately.\n", "New Title");

    expect(result.replaced).toBe(true);
    expect(result.content).toBe("# New Title\nBody immediately.\n");
    expect(result.content.slice(result.cursorOffset)).toBe("Body immediately.\n");
  });

  it("ignores leading blank lines when detecting an existing H1", () => {
    const result = insertTitleAsPageHeading("\n\n# Old Title\n\nBody.\n", "New Title");

    expect(result.replaced).toBe(true);
    expect(result.content).toBe("\n\n# New Title\n\nBody.\n");
    expect(result.content.slice(result.cursorOffset)).toBe("Body.\n");
  });

  it("inserts an H1 and one blank line when the first contentful line is not an H1", () => {
    const result = insertTitleAsPageHeading("## Section\n\nBody.\n", "Page Title");

    expect(result.replaced).toBe(false);
    expect(result.content).toBe("# Page Title\n\n## Section\n\nBody.\n");
    expect(result.content.slice(result.cursorOffset)).toBe("## Section\n\nBody.\n");
  });

  it("collapses leading blank lines when inserting so blanks are not doubled", () => {
    const result = insertTitleAsPageHeading("\n\nBody only.\n", "Page Title");

    expect(result.replaced).toBe(false);
    expect(result.content).toBe("# Page Title\n\nBody only.\n");
    expect(result.content.slice(result.cursorOffset)).toBe("Body only.\n");
  });

  it("inserts an H1 and a blank line into an empty document", () => {
    const result = insertTitleAsPageHeading("", "Page Title");

    expect(result.replaced).toBe(false);
    expect(result.content).toBe("# Page Title\n\n");
    expect(result.cursorOffset).toBe(result.content.length);
  });

  it("does not treat a deeper ATX heading as an H1", () => {
    const result = insertTitleAsPageHeading("### Detail\n", "Page Title");

    expect(result.replaced).toBe(false);
    expect(result.content).toBe("# Page Title\n\n### Detail\n");
  });

  it("does not treat a hash without a following space as an H1", () => {
    const result = insertTitleAsPageHeading("#Tag\nBody.\n", "Page Title");

    expect(result.replaced).toBe(false);
    expect(result.content).toBe("# Page Title\n\n#Tag\nBody.\n");
  });

  it("treats a lone hash as an existing H1", () => {
    const result = insertTitleAsPageHeading("#\n\nBody.\n", "Page Title");

    expect(result.replaced).toBe(true);
    expect(result.content).toBe("# Page Title\n\nBody.\n");
  });

  it("preserves leading whitespace on a replaced H1 line", () => {
    const result = insertTitleAsPageHeading("  # Old Title\n\nBody.\n", "New Title");

    expect(result.replaced).toBe(true);
    expect(result.content).toBe("  # New Title\n\nBody.\n");
  });

  it("trims the title field and leaves the document unchanged when it is empty", () => {
    const existing = "# Old Title\n\nBody.\n";
    const result = insertTitleAsPageHeading(existing, "   ");

    expect(result.replaced).toBe(false);
    expect(result.content).toBe(existing);
    expect(result.cursorOffset).toBe(0);
  });
});
