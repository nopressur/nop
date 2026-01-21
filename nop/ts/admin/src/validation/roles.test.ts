// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { validateRoleName } from "./roles";

describe("validateRoleName", () => {
  it("accepts empty and valid roles", () => {
    expect(validateRoleName("").valid).toBe(true);
    expect(validateRoleName("admin_role").valid).toBe(true);
  });

  it("rejects invalid roles", () => {
    const result = validateRoleName("bad role");
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toMatch(/letters, numbers/);
    }
  });
});
