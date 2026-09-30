// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from "fs/promises";
import path from "path";
import { test, expect } from "../../fixtures";
import { login, logoutViaApi } from "../../utils/auth";
import { humanClearAndType, humanClick } from "../../utils/humanInput";
import { getAvailablePort } from "../../utils/ports";
import { seedFixtureData } from "../../utils/seed";
import { launchServer } from "../../utils/server";
import { createTempRoot } from "../../utils/tempRoot";

test("admin settings updates public website identity", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/settings",
    expectedPath: "/admin/settings",
  });

  const navLabels = await page.locator("nav a").allTextContents();
  expect(navLabels.map((label) => label.trim())).toEqual([
    "Content",
    "Tags",
    "Roles",
    "Themes",
    "Users",
    "Settings",
    "System",
  ]);

  await expect(page.getByRole("heading", { name: "Website" })).toBeVisible();
  const nameInput = page.getByLabel("Website Name");
  const titleInput = page.getByLabel("Website Title");
  const descriptionInput = page.getByLabel("Website Description");
  const cancelButton = page.getByRole("button", { name: "Cancel" });
  const saveButton = page.getByRole("button", { name: "Save" });

  await expect(nameInput).not.toHaveValue("");
  await expect(titleInput).toHaveValue("");
  await expect(cancelButton).toBeDisabled();
  await expect(saveButton).toBeDisabled();

  await humanClearAndType(nameInput, "Playwright Name", rng);
  await humanClearAndType(titleInput, "Playwright Site", rng);
  await humanClearAndType(descriptionInput, "Playwright public description", rng);
  await expect(cancelButton).toBeEnabled();
  await expect(saveButton).toBeEnabled();
  await humanClick(saveButton, rng);
  await expect(page.getByText("Website settings updated")).toBeVisible();

  await page.goto(`${harness.baseUrl}${harness.smoke.path}`);
  await expect(page).toHaveTitle(`${harness.smoke.title} | Playwright Site`);
  await expect(page.locator("nav").getByText("Playwright Name")).toBeVisible();
  await expect(page.locator('meta[name="description"]')).toHaveAttribute(
    "content",
    "Playwright public description",
  );

  const configContent = await fs.readFile(
    path.join(harness.runtimeRoot, "config.yaml"),
    "utf8",
  );
  expect(configContent).toContain("name: Playwright Name");
  expect(configContent).toContain("title: Playwright Site");
  expect(configContent).toContain("description: Playwright public description");
  expect(configContent).not.toContain("\napp:");

  await logoutViaApi({ page, baseUrl: harness.baseUrl });
});

test("seeded Website Title is reflected in public page titles", async ({ page }) => {
  const tempRoot = await createTempRoot();
  const port = await getAvailablePort();
  const seeded = await seedFixtureData(tempRoot.rootDir, { port });
  await fs.appendFile(
    path.join(tempRoot.rootDir, "config.yaml"),
    '\nsettings:\n  title: "Seeded Site"\n',
    "utf8",
  );
  const server = await launchServer({
    runtimeRoot: tempRoot.rootDir,
    port,
  });

  try {
    await page.goto(`${server.baseUrl}${seeded.smoke.path}`);
    await expect(page).toHaveTitle(`${seeded.smoke.title} | Seeded Site`);
  } finally {
    await server.stop();
    await tempRoot.cleanup();
  }
});
