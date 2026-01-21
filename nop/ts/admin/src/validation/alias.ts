// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { validationError, validationOk, type ValidationResult } from "./result";

type AliasValidationOptions = {
  adminPath?: string;
};

const RESERVED_PREFIXES = ["login", "builtin"];

function normalizeAdminPrefix(adminPath?: string): string | null {
  if (!adminPath) {
    return null;
  }
  const trimmed = adminPath.trim().replace(/^\/+|\/+$/g, "");
  if (!trimmed) {
    return null;
  }
  return trimmed.toLowerCase();
}

export function normalizeAlias(
  value: string,
  options: AliasValidationOptions = {},
): ValidationResult<string> {
  const trimmed = value.trim();
  if (!trimmed) {
    return validationError("Alias cannot be empty");
  }
  if (trimmed.length > 512) {
    return validationError("Alias is too long");
  }
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    return validationError("Alias contains control characters");
  }
  if (trimmed.includes("\\")) {
    return validationError("Alias cannot contain backslashes");
  }
  if (!/^[A-Za-z0-9\-._~!$&'()*+,;=:@/]+$/.test(trimmed)) {
    return validationError("Alias contains invalid URL characters");
  }

  const parts = trimmed.split("/").filter((part) => part.length > 0);
  for (const part of parts) {
    if (part === "." || part === "..") {
      return validationError("Alias cannot contain dot segments");
    }
  }

  const alias = parts.join("/").toLowerCase();
  if (!alias) {
    return validationError("Alias cannot be empty");
  }
  if (alias.startsWith("id/")) {
    return validationError("Alias uses reserved prefix 'id/'");
  }
  const reservedPrefixes = [...RESERVED_PREFIXES];
  const adminPrefix = normalizeAdminPrefix(options.adminPath);
  if (adminPrefix) {
    reservedPrefixes.push(adminPrefix);
  }
  for (const prefix of reservedPrefixes) {
    if (alias === prefix || alias.startsWith(`${prefix}/`)) {
      return validationError(`Alias uses reserved prefix '${prefix}/'`);
    }
  }
  return validationOk(alias);
}
