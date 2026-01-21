// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login } from "../../utils/auth";
import { humanClick } from "../../utils/humanInput";

test("admin UX navigation visits all admin pages", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New Page" }), rng);
  await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();

  await humanClick(page.getByRole("link", { name: "Content" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  const smokeRow = page.locator("tr", { hasText: harness.smoke.title }).first();
  await expect(smokeRow).toBeVisible({ timeout: 15000 });
  await humanClick(smokeRow, rng);
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();

  await humanClick(page.getByRole("link", { name: "Tags" }), rng);
  await expect(page.getByRole("heading", { name: "Tag Catalog" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New Tag" }), rng);
  await expect(page.getByRole("heading", { name: "Create Tag" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "Cancel" }), rng);
  await expect(page.getByRole("heading", { name: "Tag Catalog" })).toBeVisible();

  await humanClick(page.getByRole("link", { name: "Roles" }), rng);
  await expect(page.getByRole("heading", { name: "Role Directory" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New Role" }), rng);
  await expect(page.getByRole("heading", { name: "Create Role" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "Cancel" }), rng);
  await expect(page.getByRole("heading", { name: "Role Directory" })).toBeVisible();

  await humanClick(page.getByRole("link", { name: "Themes" }), rng);
  await expect(page.getByRole("heading", { name: "Theme Library" })).toBeVisible();

  await humanClick(page.getByRole("cell", { name: "default" }), rng);
  await expect(
    page.getByRole("heading", { name: /Customize/i })
  ).toBeVisible();

  await humanClick(page.getByRole("link", { name: "Users" }), rng);
  await expect(page.getByRole("heading", { name: "User Directory" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New User" }), rng);
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();
});
