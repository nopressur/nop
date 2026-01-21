// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import type { Page } from "@playwright/test";
import type { SeededUser } from "./seed";
import type { SeededRandom } from "./rng";
import { humanClick, humanType } from "./humanInput";

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export async function login(options: {
  page: Page;
  baseUrl: string;
  user: SeededUser;
  rng: SeededRandom;
  returnPath?: string;
  expectedPath?: string;
}): Promise<void> {
  const { page, baseUrl, user, rng, returnPath, expectedPath } = options;
  const loginUrl = new URL("/login", baseUrl);

  if (returnPath) {
    loginUrl.searchParams.set("return_path", returnPath);
  }

  await page.goto(loginUrl.toString());

  const emailInput = page.getByLabel("Email");
  await emailInput.waitFor();
  await humanType(emailInput, user.email, rng);
  await humanClick(page.getByRole("button", { name: "Continue" }), rng);

  const passwordInput = page.getByLabel("Password");
  await passwordInput.waitFor();
  await humanType(passwordInput, user.password, rng);

  const expectedPattern = expectedPath
    ? new RegExp(`${escapeRegex(baseUrl)}${escapeRegex(expectedPath)}`)
    : undefined;

  const signInButton = page.getByRole("button", { name: "Sign in" });
  if (expectedPattern) {
    await Promise.all([
      page.waitForURL(expectedPattern, { timeout: 15000 }),
      humanClick(signInButton, rng),
    ]);
    return;
  }

  await humanClick(signInButton, rng);
  await page.waitForLoadState("domcontentloaded");
}

export async function logoutViaApi(options: {
  page: Page;
  baseUrl: string;
  csrfEndpoint?: string;
}): Promise<void> {
  const { page, baseUrl, csrfEndpoint = "/admin/csrf-token-api" } = options;
  const tokenUrl = new URL(csrfEndpoint, baseUrl);
  const tokenResponse = await page.request.post(tokenUrl.toString());
  if (!tokenResponse.ok()) {
    throw new Error(
      `Failed to fetch CSRF token (${csrfEndpoint}): ${tokenResponse.status()}`,
    );
  }

  const tokenJson = (await tokenResponse.json()) as { csrf_token?: string };
  if (!tokenJson.csrf_token) {
    throw new Error(`CSRF token missing from response (${csrfEndpoint})`);
  }

  const logoutResponse = await page.request.post(`${baseUrl}/login/logout-api`, {
    headers: {
      "X-CSRF-Token": tokenJson.csrf_token,
    },
  });

  if (!logoutResponse.ok()) {
    throw new Error(`Logout failed: ${logoutResponse.status()}`);
  }
}
