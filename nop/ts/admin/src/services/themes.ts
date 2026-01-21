// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { getAdminRuntimeConfig } from "../config/runtime";
import { getLocationOrigin } from "./browser";
import { restJson } from "../transport/restClient";

export type ThemeCreateResponse = {
  success: boolean;
  message: string;
  redirect?: string;
};

export type ThemeListSummary = {
  name: string;
  is_default: boolean;
};

export async function listThemes(): Promise<ThemeListSummary[]> {
  const { adminPath } = getAdminRuntimeConfig();
  const response = await restJson<{ themes: ThemeListSummary[] }>(
    `${adminPath}/themes/list-api`,
  );
  return response.themes;
}

export async function createTheme(name: string, content: string): Promise<ThemeCreateResponse> {
  const { adminPath } = getAdminRuntimeConfig();
  return restJson<ThemeCreateResponse>(`${adminPath}/themes/create-api`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name, content })
  });
}

export async function saveTheme(theme: string, content: string): Promise<{ success: boolean; message: string }> {
  const { adminPath } = getAdminRuntimeConfig();
  return restJson<{ success: boolean; message: string }>(
    `${adminPath}/themes/save-api/${encodeURIComponent(theme)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ content })
    },
  );
}

export async function deleteTheme(theme: string): Promise<{ success: boolean; message: string }> {
  const { adminPath } = getAdminRuntimeConfig();
  const url = new URL(`${adminPath}/themes/delete-api`, getLocationOrigin());
  url.searchParams.set("theme", theme);
  return restJson<{ success: boolean; message: string }>(url.toString(), {
    method: "DELETE"
  });
}
