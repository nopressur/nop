// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { navigate } from "../stores/router";
import { pushNotification } from "../stores/notifications";

export type AdminRouteOutcome = "valid" | "invalid" | "users-disabled";

const VALID_ROUTE_PATTERNS: RegExp[] = [
  /^\/pages$/,
  /^\/pages\/new$/,
  /^\/pages\/edit\/[^/]+$/,
  /^\/tags$/,
  /^\/tags\/new$/,
  /^\/tags\/edit$/,
  /^\/roles$/,
  /^\/roles\/new$/,
  /^\/roles\/edit$/,
  /^\/themes$/,
  /^\/themes\/new$/,
  /^\/themes\/customize\/[^/]+$/,
  /^\/users$/,
  /^\/users\/new$/,
  /^\/users\/edit\/[^/]+$/,
  /^\/system$/
];

export function getAdminRouteOutcome(
  path: string,
  userManagementEnabled: boolean
): AdminRouteOutcome {
  const normalized = normalizePath(path);
  if (!normalized || normalized === "/") {
    return "valid";
  }

  if (!userManagementEnabled && normalized.startsWith("/users")) {
    return "users-disabled";
  }

  if (VALID_ROUTE_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return "valid";
  }

  return "invalid";
}

export function enforceAdminRoute(
  path: string,
  userManagementEnabled: boolean
): void {
  const outcome = getAdminRouteOutcome(path, userManagementEnabled);
  if (outcome === "users-disabled") {
    navigate("/pages", true);
    return;
  }
  if (outcome === "invalid") {
    pushNotification("Invalid admin URL.", "info");
    navigate("/pages", true);
  }
}

function normalizePath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed) {
    return "";
  }
  const normalized = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  if (normalized === "/") {
    return normalized;
  }
  return normalized.replace(/\/+$/, "");
}
