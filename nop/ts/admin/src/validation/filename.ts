// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { validationError, validationOk, type ValidationResult } from "./result";

export function validateFileName(name: string): ValidationResult<string> {
  if (!name || name.length === 0) {
    return validationError("Name cannot be empty");
  }

  if (name.length > 128) {
    return validationError("Name cannot exceed 128 characters");
  }

  if (name.includes(".")) {
    return validationError("Name cannot contain dots (extensions will be added automatically)");
  }

  const validPattern = /^[a-z0-9_-]+$/;
  if (!validPattern.test(name)) {
    return validationError(
      "Name can only contain lowercase letters and numbers, dashes, and underscores",
    );
  }

  return validationOk(name);
}
