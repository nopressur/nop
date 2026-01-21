// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { validateFileName } from "./filename";

describe("validateFileName", () => {
  it("accepts lowercase names", () => {
    const result = validateFileName("theme_one");
    expect(result.valid).toBe(true);
  });

  it("rejects empty names", () => {
    const result = validateFileName("");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/empty/);
    }
  });

  it("rejects dots", () => {
    const result = validateFileName("bad.name");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/dots/);
    }
  });

  it("rejects uppercase", () => {
    const result = validateFileName("BadName");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/lowercase/);
    }
  });
});
