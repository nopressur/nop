// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { buildEditorSnapshot, isEditorDirty } from "./contentEditorState";

describe("contentEditorState", () => {
  it("normalizes tags and nav fields in snapshots", () => {
    const snapshot = buildEditorSnapshot({
      alias: "docs",
      title: "Title",
      selectedTags: [" ui ", "", "docs"],
      navTitle: "  Nav  ",
      navParentId: " parent ",
      navOrder: 2,
      theme: "default",
      contentValue: "Body",
      isMarkdown: true,
    });

    expect(snapshot.tags).toEqual(["docs", "ui"]);
    expect(snapshot.navTitle).toBe("Nav");
    expect(snapshot.navParentId).toBe("parent");
    expect(snapshot.navOrder).toBe("2");
  });

  it("treats equivalent tag order as clean", () => {
    const initial = buildEditorSnapshot({
      alias: "docs",
      title: "Title",
      selectedTags: ["docs", "ui"],
      navTitle: "",
      navParentId: "",
      navOrder: "",
      theme: "",
      contentValue: "Body",
      isMarkdown: true,
    });
    const current = buildEditorSnapshot({
      alias: "docs",
      title: "Title",
      selectedTags: ["ui", "docs"],
      navTitle: "",
      navParentId: "",
      navOrder: "",
      theme: "",
      contentValue: "Body",
      isMarkdown: true,
    });

    expect(isEditorDirty(initial, current)).toBe(false);
  });

  it("flags title changes as dirty", () => {
    const initial = buildEditorSnapshot({
      alias: "docs",
      title: "Title",
      selectedTags: [],
      navTitle: "",
      navParentId: "",
      navOrder: "",
      theme: "",
      contentValue: "Body",
      isMarkdown: true,
    });
    const current = buildEditorSnapshot({
      alias: "docs",
      title: "Updated",
      selectedTags: [],
      navTitle: "",
      navParentId: "",
      navOrder: "",
      theme: "",
      contentValue: "Body",
      isMarkdown: true,
    });

    expect(isEditorDirty(initial, current)).toBe(true);
  });
});
