// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { validationError, validationOk, type ValidationResult } from "./result";

const ROLE_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_ROLE_CHARS = 64;

export function validateRoleName(role: string): ValidationResult<string> {
  if (role.length === 0) {
    return validationOk(role);
  }
  if (role.length > MAX_ROLE_CHARS) {
    return validationError("Role name must be 64 characters or fewer");
  }
  if (!ROLE_PATTERN.test(role)) {
    return validationError(
      "Role name may only include letters, numbers, dashes, and underscores",
    );
  }
  return validationOk(role);
}
