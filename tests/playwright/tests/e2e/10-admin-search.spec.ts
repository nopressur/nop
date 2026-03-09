// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login } from "../../utils/auth";
import { humanClick, humanClearAndType, humanType } from "../../utils/humanInput";

const DOCS_TAG = { id: "docs", name: "Docs" };

test("admin search uses seeded fixtures and respects tags in insert modal", async ({
  page,
  harness,
  rng,
}) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  const ensureDocsTag = async () => {
    await humanClick(page.getByRole("link", { name: "Tags" }), rng);
    await expect(page.getByRole("heading", { name: "Tag Catalog" })).toBeVisible();

    const existingRow = page.locator("tr", { hasText: DOCS_TAG.id });
    if ((await existingRow.count()) > 0) {
      return;
    }

    await humanClick(page.getByRole("button", { name: "New Tag" }), rng);
    await expect(page.getByRole("heading", { name: "Create Tag" })).toBeVisible();
    await humanType(page.locator("#tag-id"), DOCS_TAG.id, rng);
    await humanType(page.locator("#tag-name"), DOCS_TAG.name, rng);
    await humanClick(page.getByRole("button", { name: "Save" }), rng);
    await page.waitForURL(/\/admin\/tags/);
    await expect(page.locator("tr", { hasText: DOCS_TAG.id })).toBeVisible();
  };

  const openContentByTitle = async (title: string) => {
    const mobileButton = page.getByRole("button", { name: title }).first();
    if (await mobileButton.isVisible()) {
      await humanClick(mobileButton, rng);
      return;
    }
    const row = page.locator("tbody tr", { hasText: title }).first();
    await expect(row).toBeVisible();
    await humanClick(row, rng);
  };

  await ensureDocsTag();

  await humanClick(page.getByRole("link", { name: "Content" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  const searchInput = page.getByPlaceholder("Search");

  await humanClearAndType(searchInput, "nimbus", rng);
  await expect(page.locator("tr", { hasText: "Search Table Fixture" })).toBeVisible();
  await expect(page.locator("tr", { hasText: "Search HTML Fixture" })).toBeVisible();

  await humanClearAndType(searchInput, "NIMBUS", rng);
  await expect(page.locator("tr", { hasText: "Search Table Fixture" })).toBeVisible();
  await expect(page.locator("tr", { hasText: "Search HTML Fixture" })).toBeVisible();

  await humanClearAndType(searchInput, "zzattrtoken", rng);
  await expect(
    page.getByRole("cell", { name: "No content matches this filter." })
  ).toBeVisible();

  await humanClearAndType(searchInput, "nimbus", rng);
  await openContentByTitle("Search Table Fixture");
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();

  const insertShortcut = process.platform === "darwin" ? "Meta+Shift+I" : "Control+Shift+I";
  await page.keyboard.press(insertShortcut);
  const insertModal = page.getByRole("dialog", { name: "Insert content" });
  await expect(insertModal).toBeVisible();
  await expect(insertModal.locator("#insert-tag")).toHaveValue("docs");

  await humanClearAndType(insertModal.locator("#insert-search"), "nimbus", rng);
  await expect(
    insertModal.getByRole("option", { name: /Search Table Fixture/ })
  ).toBeVisible();
  await expect(
    insertModal.getByRole("option", { name: /Search HTML Fixture/ })
  ).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(insertModal).toHaveCount(0);
});
