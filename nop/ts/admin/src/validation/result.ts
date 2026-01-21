// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type ValidationResult<T> =
  | { valid: true; value: T }
  | { valid: false; error: string };

export function validationOk<T>(value: T): ValidationResult<T> {
  return { valid: true, value };
}

export function validationError<T = never>(error: string): ValidationResult<T> {
  return { valid: false, error };
}
