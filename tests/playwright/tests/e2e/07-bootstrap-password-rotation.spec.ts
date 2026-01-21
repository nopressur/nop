// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";
import { createSeededRandom } from "../../utils/rng";
import { createTempRoot } from "../../utils/tempRoot";
import { getAvailablePort } from "../../utils/ports";
import { launchBootstrapServer } from "../../utils/server";
import { login } from "../../utils/auth";
import { humanClick, humanType } from "../../utils/humanInput";

function buildBootstrapConfig(port: number): string {
  return `server:\n  host: "127.0.0.1"\n  port: ${port}\n  workers: 2\n\nadmin:\n  path: "/admin"\n\nusers:\n  auth_method: "local"\n  local:\n    jwt:\n      secret: "test-secret"\n\nnavigation: {}\n\nlogging:\n  level: "info"\n\nsecurity: {}\n\napp:\n  name: "NoPressure Bootstrap Test"\n  description: "Playwright bootstrap flow"\n\nupload: {}\n`;
}

test("bootstrap admin password rotation works across sessions", async ({ page, browser }, testInfo) => {
  const tempRoot = await createTempRoot("nopressure-pw-bootstrap-");
  const port = await getAvailablePort();
  const rng = createSeededRandom(testInfo.titlePath.join("::"));
  const newPassword = "PlaywrightNewPass123!";

  await fs.writeFile(
    path.join(tempRoot.rootDir, "config.yaml"),
    buildBootstrapConfig(port),
    "utf8"
  );

  const server = await launchBootstrapServer({
    runtimeRoot: tempRoot.rootDir,
    port,
  });

  try {
    const adminUser = {
      email: "admin@example.com",
      name: "Administrator",
      password: server.bootstrapPassword,
      roles: ["admin"],
    };

    await login({
      page,
      baseUrl: server.baseUrl,
      user: adminUser,
      rng,
      returnPath: "/admin",
      expectedPath: "/admin",
    });

    await page.goto(`${server.baseUrl}/login/profile`);
    await expect(page.getByRole("heading", { name: "Profile" })).toBeVisible();
    await humanClick(page.getByRole("button", { name: "Change" }), rng);
    await humanType(
      page.getByLabel("Current password", { exact: true }),
      server.bootstrapPassword,
      rng
    );
    await humanType(
      page.getByLabel("New password", { exact: true }),
      newPassword,
      rng
    );
    await humanType(
      page.getByLabel("Confirm new password", { exact: true }),
      newPassword,
      rng
    );
    await humanClick(page.getByRole("button", { name: "Update password" }), rng);
    await expect(page.getByText("Password updated successfully")).toBeVisible({
      timeout: 15000,
    });

    const context = await browser.newContext();
    const newPage = await context.newPage();
    const newRng = createSeededRandom(`${testInfo.titlePath.join("::")}::fresh`);

    await login({
      page: newPage,
      baseUrl: server.baseUrl,
      user: { ...adminUser, password: newPassword },
      rng: newRng,
      returnPath: "/admin",
      expectedPath: "/admin",
    });

    await expect(
      newPage.getByRole("heading", { name: "Content Library" })
    ).toBeVisible({ timeout: 15000 });

    await context.close();
  } finally {
    await server.stop();
    await tempRoot.cleanup();
  }
});
