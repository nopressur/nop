// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login, logoutViaApi } from "../../utils/auth";
import { humanClick, humanClearAndType, humanType } from "../../utils/humanInput";

const TAG = {
  id: "release/alpha",
  name: "Release Alpha",
  updatedName: "Release Alpha Updated",
  accessRule: "union",
  updatedAccessRule: "intersect",
};

test("tag management CRUD and listing", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/tags",
    expectedPath: "/admin/tags",
  });

  await expect(page.getByRole("heading", { name: "Tag Catalog" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "No tags found." })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New Tag" }), rng);
  await expect(page.getByRole("heading", { name: "Create Tag" })).toBeVisible();

  await humanType(page.locator("#tag-id"), TAG.id, rng);
  await humanType(page.locator("#tag-name"), TAG.name, rng);
  const rolesSelect = page.locator("#tag-roles");
  await expect(rolesSelect.locator('option[value="editor"]')).toHaveCount(1);
  await rolesSelect.selectOption("editor");
  await expect(page.locator('[aria-label="Remove editor"]')).toBeVisible();
  await rolesSelect.selectOption("admin");
  await expect(page.locator('[aria-label="Remove admin"]')).toBeVisible();

  const accessSelect = page.locator("#tag-access");
  await humanClick(accessSelect, rng);
  await accessSelect.selectOption(TAG.accessRule);

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/tags/);

  let tagRow = page.locator("tr", { hasText: TAG.id });
  await expect(tagRow).toContainText(TAG.name);

  await humanClick(tagRow.getByRole("button", { name: "Edit" }), rng);
  await expect(page.getByRole("heading", { name: "Edit Tag" })).toBeVisible();
  await expect(page.locator("#tag-name")).toHaveValue(TAG.name);
  await expect(page.locator('[aria-label="Remove editor"]')).toBeVisible();
  await expect(page.locator('[aria-label="Remove admin"]')).toBeVisible();
  await expect(page.locator("#tag-access")).toHaveValue(TAG.accessRule);

  await humanClearAndType(
    page.locator("#tag-name"),
    TAG.updatedName,
    rng
  );
  await humanClick(page.locator('[aria-label="Remove editor"]'), rng);

  const editAccessSelect = page.locator("#tag-access");
  await humanClick(editAccessSelect, rng);
  await editAccessSelect.selectOption(TAG.updatedAccessRule);

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/tags/);

  tagRow = page.locator("tr", { hasText: TAG.id });
  await expect(tagRow).toContainText(TAG.updatedName);

  await humanClick(tagRow.getByRole("button", { name: "Delete" }), rng);
  const deleteModal = page.getByRole("dialog", { name: "Delete" });
  await expect(deleteModal).toBeVisible();
  await humanClick(deleteModal.getByRole("button", { name: "Delete" }), rng);

  await expect(page.locator("tr", { hasText: TAG.id })).toHaveCount(0);
  await expect(page.getByRole("cell", { name: "No tags found." })).toBeVisible();

  await logoutViaApi({ page, baseUrl: harness.baseUrl });
});

test("non-admin users are redirected from tag management", async ({
  browser,
  harness,
  rng,
}) => {
  const nonAdmins = [harness.users.editor, harness.users.viewer];

  for (const user of nonAdmins) {
    const context = await browser.newContext();
    const page = await context.newPage();

    await login({
      page,
      baseUrl: harness.baseUrl,
      user,
      rng,
      returnPath: "/admin/tags",
      expectedPath: "/",
    });

    const userMenu = page.locator("[data-site-user-menu]");
    await expect(userMenu.getByRole("link", { name: user.name })).toBeVisible({
      timeout: 15000,
    });
    await expect(page).toHaveURL(new RegExp(`${harness.baseUrl}/?$`));
    await expect(
      userMenu.getByRole("link", { name: "Admin" })
    ).toHaveCount(0);

    await context.close();
  }
});
