// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { parseRoles, validateRoles, validateTagId, validateTagName } from "./tags";

describe("tag validation", () => {
  it("validates tag id", () => {
    expect(validateTagId("news/latest").valid).toBe(true);
    const invalidId = validateTagId("BAD");
    expect(invalidId.valid).toBe(false);
    if (!invalidId.valid) {
      expect(invalidId.error).toMatch(/invalid/);
    }
  });

  it("validates tag name", () => {
    expect(validateTagName("News").valid).toBe(true);
    const invalidName = validateTagName("");
    expect(invalidName.valid).toBe(false);
    if (!invalidName.valid) {
      expect(invalidName.error).toMatch(/required/);
    }
  });

  it("parses roles", () => {
    const result = parseRoles("admin, editor\nviewer");
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.value).toEqual(["admin", "editor", "viewer"]);
    }
  });

  it("validates roles", () => {
    expect(validateRoles(["admin", "editor"]).valid).toBe(true);
    const invalidRoles = validateRoles(["bad role"]);
    expect(invalidRoles.valid).toBe(false);
    if (!invalidRoles.valid) {
      expect(invalidRoles.error).toMatch(/invalid/);
    }
  });
});
