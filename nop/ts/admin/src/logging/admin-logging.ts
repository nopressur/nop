// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { getLocalStorage } from "../services/browser";

const DEBUG_KEY = "nopAdminDebug";

type DebugOwner = {
  NOP_ADMIN_DEBUG?: boolean;
};

export function isAdminDebugEnabled(): boolean {
  const adminWindow = globalThis as DebugOwner;

  if (adminWindow.NOP_ADMIN_DEBUG === true) {
    return true;
  }

  try {
    const storage = getLocalStorage();
    return storage?.getItem(DEBUG_KEY) === "true";
  } catch (_error) {
    return false;
  }
}

function logWithLevel(
  level: "info" | "warn",
  scope: string,
  message: string,
  details?: unknown,
): void {
  if (!isAdminDebugEnabled()) {
    return;
  }
  const prefix = `[${scope}] ${message}`;
  if (details !== undefined) {
    console[level](prefix, details);
    return;
  }
  console[level](prefix);
}

export function logAdminInfo(
  scope: string,
  message: string,
  details?: unknown,
): void {
  logWithLevel("info", scope, message, details);
}

export function logAdminWarn(
  scope: string,
  message: string,
  details?: unknown,
): void {
  logWithLevel("warn", scope, message, details);
}
