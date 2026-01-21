// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { createCsrfClient } from "../../../shared/src/csrf";
import { getAdminRuntimeConfig } from "../config/runtime";
import { logAdminWarn } from "../logging/admin-logging";

const csrfClient = createCsrfClient({
  tokenPath: () => getAdminRuntimeConfig().csrfTokenPath,
  onRetry: () => logAdminWarn("CSRF", "CSRF validation failed, retrying"),
});

export function getCsrfToken(): Promise<string> {
  return csrfClient.getToken();
}

export function clearCsrfToken(): void {
  csrfClient.clear();
}

export async function csrfFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
): Promise<Response> {
  return csrfClient.csrfFetch(input, init);
}
