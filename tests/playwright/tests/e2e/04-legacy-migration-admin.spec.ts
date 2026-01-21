// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "@playwright/test";
import fs from "fs/promises";
import path from "path";
import { login } from "../../utils/auth";
import { humanClick, humanClearAndType } from "../../utils/humanInput";
import { getAvailablePort } from "../../utils/ports";
import { createSeededRandom } from "../../utils/rng";
import { launchServer } from "../../utils/server";
import { seedFixtureData, writeLegacyMarkdown } from "../../utils/seed";
import { createTempRoot } from "../../utils/tempRoot";

test("legacy migration populates admin editor", async ({ page }, testInfo) => {
  const tempRoot = await createTempRoot();
  const port = await getAvailablePort();
  const seeded = await seedFixtureData(tempRoot.rootDir, { port });
  const rng = createSeededRandom(
    process.env.PW_RNG_SEED ?? testInfo.titlePath.join("::")
  );

  const contentDir = path.join(tempRoot.rootDir, "content");
  await writeLegacyMarkdown({
    contentDir,
    relativePath: "docs/getting-started.md",
    body: "---\ntitle: Legacy Intro\nnav: true\n---\n# Legacy Intro\n\nLegacy body.\n",
  });

  const server = await launchServer({ runtimeRoot: tempRoot.rootDir, port });

  try {
    const legacyPath = path.join(contentDir, "docs", "getting-started.md");
    const migratedPath = path.join(
      contentDir,
      "legacy",
      "docs",
      "getting-started.md"
    );

    await expect(fs.stat(legacyPath)).rejects.toThrow();
    await expect(fs.stat(migratedPath)).resolves.toBeDefined();

    await login({
      page,
      baseUrl: server.baseUrl,
      user: seeded.users.admin,
      rng,
      returnPath: "/admin/pages",
      expectedPath: "/admin/pages",
    });

    await expect(
      page.getByRole("heading", { name: "Content Library" })
    ).toBeVisible();

    const legacyRow = page.locator("tr", { hasText: "Legacy Intro" });
    await expect(legacyRow).toBeVisible();
    await humanClick(legacyRow.getByText("Legacy Intro"), rng);

    await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
    const aliasField = page.locator("#content-alias");
    if (!(await aliasField.isVisible())) {
      await humanClick(page.getByRole("button", { name: "Expand details" }), rng);
    }
    await expect(aliasField).toHaveValue(
      "docs/getting-started"
    );
    await expect(page.locator("#content-title")).toHaveValue("Legacy Intro");

    await humanClearAndType(
      page.locator("#content-title"),
      "Legacy Intro Updated",
      rng
    );
    await humanClick(page.getByRole("button", { name: "Save" }), rng);
    await expect(page.getByText("Content saved")).toBeVisible();
  } finally {
    await server.stop();
    await tempRoot.cleanup();
  }
});
