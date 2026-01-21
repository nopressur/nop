// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login, logoutViaApi } from "../../utils/auth";
import { humanClick, humanClearAndType, humanType } from "../../utils/humanInput";

const ROLE = {
  name: "reviewer",
  updated: "reviewer-updated",
};

test("role management CRUD", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/roles",
    expectedPath: "/admin/roles",
  });

  await expect(page.getByRole("heading", { name: "Role Directory" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "admin" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New Role" }), rng);
  await expect(page.getByRole("heading", { name: "Create Role" })).toBeVisible();

  await humanType(page.locator("#role-name"), ROLE.name, rng);
  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/roles/);

  let roleRow = page.locator("tr", { hasText: ROLE.name });
  await expect(roleRow).toContainText(ROLE.name);

  await humanClick(roleRow.getByRole("button", { name: "Edit" }), rng);
  await expect(page.getByRole("heading", { name: "Edit Role" })).toBeVisible();

  await humanClearAndType(page.locator("#role-new"), ROLE.updated, rng);
  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/roles/);

  roleRow = page.locator("tr", { hasText: ROLE.updated });
  await expect(roleRow).toContainText(ROLE.updated);

  await humanClick(roleRow.getByRole("button", { name: "Delete" }), rng);
  const deleteModal = page.getByRole("dialog", { name: "Delete" });
  await expect(deleteModal).toBeVisible();
  await humanClick(deleteModal.getByRole("button", { name: "Delete" }), rng);

  await expect(page.locator("tr", { hasText: ROLE.updated })).toHaveCount(0);

  await logoutViaApi({ page, baseUrl: harness.baseUrl });
});
