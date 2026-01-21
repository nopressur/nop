// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { validationError, validationOk, type ValidationResult } from "./result";

export const TAG_ID_PATTERN = /^[a-z0-9/_-]+$/;
const ROLE_PATTERN = /^[A-Za-z0-9_-]+$/;
export const MAX_TAG_ID_CHARS = 128;
const MAX_TAG_NAME_CHARS = 256;
const MAX_ROLE_COUNT = 64;
const MAX_ROLE_CHARS = 64;

export function validateTagId(id: string): ValidationResult<string> {
  if (!id) {
    return validationError("Tag ID is required");
  }
  if (id.length > MAX_TAG_ID_CHARS) {
    return validationError(
      `Tag ID must be at most ${MAX_TAG_ID_CHARS} characters`,
    );
  }
  if (!TAG_ID_PATTERN.test(id)) {
    return validationError("Tag ID contains invalid characters");
  }
  return validationOk(id);
}

export function validateTagName(name: string): ValidationResult<string> {
  if (!name) {
    return validationError("Tag name is required");
  }
  if (name.length > MAX_TAG_NAME_CHARS) {
    return validationError(
      `Tag name must be at most ${MAX_TAG_NAME_CHARS} characters`,
    );
  }
  return validationOk(name);
}

export function parseRoles(value: string): ValidationResult<string[]> {
  if (!value.trim()) {
    return validationOk([]);
  }
  const roles = value
    .split(/[\n,]+/)
    .map((role) => role.trim())
    .filter((role) => role.length > 0);
  return validationOk(roles);
}

export function validateRoles(roles: string[]): ValidationResult<string[]> {
  if (roles.length > MAX_ROLE_COUNT) {
    return validationError(`Roles must be at most ${MAX_ROLE_COUNT} entries`);
  }
  for (const role of roles) {
    if (role.length > MAX_ROLE_CHARS) {
      return validationError(
        `Role '${role}' must be at most ${MAX_ROLE_CHARS} characters`,
      );
    }
    if (!ROLE_PATTERN.test(role)) {
      return validationError(`Role '${role}' contains invalid characters`);
    }
  }
  return validationOk(roles);
}
