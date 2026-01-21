// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { normalizeAlias } from "./alias";

describe("normalizeAlias", () => {
  it("normalizes slashes and lowercases", () => {
    const result = normalizeAlias("//Blog//Post//");
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.value).toBe("blog/post");
    }
  });

  it("rejects dot segments", () => {
    const result = normalizeAlias("foo/../bar");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/dot segments/);
    }
  });

  it("rejects backslashes", () => {
    const result = normalizeAlias("foo\\bar");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/backslashes/);
    }
  });

  it("rejects invalid URL characters", () => {
    const invalidSpace = normalizeAlias("docs/hello world");
    expect(invalidSpace.valid).toBe(false);
    if (!invalidSpace.valid) {
      expect(invalidSpace.error).toMatch(/invalid URL characters/);
    }

    const invalidPercent = normalizeAlias("docs/hello%20world");
    expect(invalidPercent.valid).toBe(false);
    if (!invalidPercent.valid) {
      expect(invalidPercent.error).toMatch(/invalid URL characters/);
    }

    const invalidQuery = normalizeAlias("docs/hello?world");
    expect(invalidQuery.valid).toBe(false);
    if (!invalidQuery.valid) {
      expect(invalidQuery.error).toMatch(/invalid URL characters/);
    }
  });

  it("rejects reserved id prefix", () => {
    const reservedLower = normalizeAlias("id/0123456789abcdef");
    expect(reservedLower.valid).toBe(false);
    if (!reservedLower.valid) {
      expect(reservedLower.error).toMatch(/reserved prefix/);
    }

    const reservedUpper = normalizeAlias("ID/ABCDEF");
    expect(reservedUpper.valid).toBe(false);
    if (!reservedUpper.valid) {
      expect(reservedUpper.error).toMatch(/reserved prefix/);
    }
  });

  it("rejects reserved login and builtin prefixes", () => {
    const loginRoot = normalizeAlias("login");
    expect(loginRoot.valid).toBe(false);
    if (!loginRoot.valid) {
      expect(loginRoot.error).toMatch(/reserved prefix/);
    }

    const loginNested = normalizeAlias("Login/Profile");
    expect(loginNested.valid).toBe(false);
    if (!loginNested.valid) {
      expect(loginNested.error).toMatch(/reserved prefix/);
    }

    const builtinRoot = normalizeAlias("builtin");
    expect(builtinRoot.valid).toBe(false);
    if (!builtinRoot.valid) {
      expect(builtinRoot.error).toMatch(/reserved prefix/);
    }

    const builtinNested = normalizeAlias("builtin/admin/assets");
    expect(builtinNested.valid).toBe(false);
    if (!builtinNested.valid) {
      expect(builtinNested.error).toMatch(/reserved prefix/);
    }
  });

  it("rejects reserved admin path prefix", () => {
    const reservedAdmin = normalizeAlias("admin/tools", { adminPath: "/admin" });
    expect(reservedAdmin.valid).toBe(false);
    if (!reservedAdmin.valid) {
      expect(reservedAdmin.error).toMatch(/reserved prefix/);
    }
  });
});
