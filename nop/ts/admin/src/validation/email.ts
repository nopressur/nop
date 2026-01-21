// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { validationError, validationOk, type ValidationResult } from "./result";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_CHARS = 128;

export function validateEmailAddress(email: string): ValidationResult<string> {
  if (email.length > MAX_EMAIL_CHARS) {
    return validationError("Email must be 128 characters or fewer");
  }
  if (!EMAIL_PATTERN.test(email)) {
    return validationError("Email format is invalid");
  }
  return validationOk(email);
}
