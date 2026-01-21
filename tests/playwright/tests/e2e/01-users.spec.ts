// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login, logoutViaApi } from "../../utils/auth";
import { humanClick, humanClearAndType, humanType } from "../../utils/humanInput";

const NEW_USER = {
  email: "qa.user@example.com",
  name: "QA User",
  updatedName: "QA User Updated",
  password: "qaPass123!",
  updatedPassword: "qaPass456!",
};

test("user management CRUD and listing", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/users",
    expectedPath: "/admin/users",
  });

  await expect(page.getByRole("heading", { name: "User Directory" })).toBeVisible();
  await expect(
    page.getByRole("cell", { name: harness.users.admin.email })
  ).toBeVisible();
  await expect(
    page.getByRole("cell", { name: harness.users.editor.email })
  ).toBeVisible();
  await expect(
    page.getByRole("cell", { name: harness.users.viewer.email })
  ).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New User" }), rng);
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();

  await humanType(page.locator("#user-email"), NEW_USER.email, rng);
  await humanType(page.locator("#user-name"), NEW_USER.name, rng);
  await humanType(page.locator("#user-password"), NEW_USER.password, rng);
  await humanType(page.locator("#user-confirm"), NEW_USER.password, rng);

  const editorRole = page.getByLabel("editor", { exact: true });
  await expect(editorRole).toBeVisible();
  await humanClick(editorRole, rng);

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/users/);

  await expect(page.getByRole("cell", { name: NEW_USER.email })).toBeVisible({
    timeout: 15000,
  });

  const newUserRow = page.locator("tr").filter({
    hasText: NEW_USER.email,
  });

  await expect(newUserRow).toContainText(NEW_USER.name);
  await expect(newUserRow).toContainText("editor");

  await humanClick(newUserRow.getByRole("button", { name: "Edit" }), rng);
  await expect(page.getByRole("heading", { name: "Edit User" })).toBeVisible();

  await humanClearAndType(
    page.locator("#user-name"),
    NEW_USER.updatedName,
    rng
  );
  await humanClearAndType(
    page.locator("#user-password"),
    NEW_USER.updatedPassword,
    rng
  );
  await humanClearAndType(
    page.locator("#user-confirm"),
    NEW_USER.updatedPassword,
    rng
  );

  const viewerRole = page.getByLabel("viewer", { exact: true });
  await expect(viewerRole).toBeVisible();
  await humanClick(viewerRole, rng);

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/users/);

  await expect(
    page.getByRole("cell", { name: NEW_USER.updatedName })
  ).toBeVisible({ timeout: 15000 });

  const updatedRow = page.locator("tr").filter({
    hasText: NEW_USER.email,
  });

  await expect(updatedRow).toContainText("viewer");

  await logoutViaApi({ page, baseUrl: harness.baseUrl });
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: {
      email: NEW_USER.email,
      name: NEW_USER.updatedName,
      password: NEW_USER.updatedPassword,
      roles: ["editor", "viewer"],
    },
    rng,
    expectedPath: "/",
  });

  await expect(
    page.getByRole("link", { name: NEW_USER.updatedName })
  ).toBeVisible({ timeout: 15000 });

  await logoutViaApi({
    page,
    baseUrl: harness.baseUrl,
    csrfEndpoint: "/login/csrf-token-api",
  });
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/users",
    expectedPath: "/admin/users",
  });

  const cleanupRow = page.locator("tr").filter({
    hasText: NEW_USER.email,
  });
  await humanClick(cleanupRow.getByRole("button", { name: "Delete" }), rng);
  const deleteModal = page.getByRole("dialog", { name: "Delete" });
  await expect(deleteModal).toBeVisible();
  await humanClick(deleteModal.getByRole("button", { name: "Delete" }), rng);
  await expect(cleanupRow).toHaveCount(0);

  await logoutViaApi({ page, baseUrl: harness.baseUrl });
  await page.goto(`${harness.baseUrl}/`);
  await expect(page.getByRole("link", { name: harness.users.admin.name })).toHaveCount(0);
});

test("non-admin users are redirected from admin routes", async ({
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
      returnPath: "/admin/users",
      expectedPath: "/",
    });

    await expect(page.getByRole("link", { name: user.name })).toBeVisible({
      timeout: 15000,
    });
    await expect(page).toHaveURL(new RegExp(`${harness.baseUrl}/?$`));
    await expect(
      page.getByRole("link", { name: "Admin Dashboard" })
    ).toHaveCount(0);

    await context.close();
  }
});

test("user creation missing email shows error", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/users",
    expectedPath: "/admin/users",
  });

  await humanClick(page.getByRole("button", { name: "New User" }), rng);
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();

  await humanType(page.locator("#user-name"), "Missing Email", rng);
  await humanType(page.locator("#user-password"), "MissingEmail123!", rng);
  await humanType(page.locator("#user-confirm"), "MissingEmail123!", rng);
  await humanClick(page.getByRole("button", { name: "Save" }), rng);

  await expect(page.getByText("Email is required")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();
});

test("user creation missing password shows error", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/users",
    expectedPath: "/admin/users",
  });

  await humanClick(page.getByRole("button", { name: "New User" }), rng);
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();

  await humanType(page.locator("#user-email"), "missing.password@example.com", rng);
  await humanType(page.locator("#user-name"), "Missing Password", rng);
  await humanClick(page.getByRole("button", { name: "Save" }), rng);

  await expect(page.getByText("Password is required")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();
});

test("user creation password mismatch shows error", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/users",
    expectedPath: "/admin/users",
  });

  await humanClick(page.getByRole("button", { name: "New User" }), rng);
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();

  await humanType(page.locator("#user-email"), "password.mismatch@example.com", rng);
  await humanType(page.locator("#user-name"), "Password Mismatch", rng);
  await humanType(page.locator("#user-password"), "Mismatch123!", rng);
  await humanType(page.locator("#user-confirm"), "Mismatch456!", rng);
  await humanClick(page.getByRole("button", { name: "Save" }), rng);

  await expect(page.getByText("Passwords do not match")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Create User" })).toBeVisible();
});

test("user list self delete blocked", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/users",
    expectedPath: "/admin/users",
  });

  await expect(page.getByRole("heading", { name: "User Directory" })).toBeVisible();

  const adminRow = page.locator("tr").filter({
    hasText: harness.users.admin.email,
  });
  await expect(
    adminRow.getByRole("button", { name: "Delete" })
  ).toBeDisabled();
});

test("user delete cancel leaves user intact", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/users",
    expectedPath: "/admin/users",
  });

  await expect(page.getByRole("heading", { name: "User Directory" })).toBeVisible();

  const viewerRow = page.locator("tr").filter({
    hasText: harness.users.viewer.email,
  });
  await humanClick(viewerRow.getByRole("button", { name: "Delete" }), rng);
  const deleteModal = page.getByRole("dialog", { name: "Delete" });
  await expect(deleteModal).toBeVisible();
  await humanClick(deleteModal.getByRole("button", { name: "Cancel" }), rng);

  await expect(viewerRow).toContainText(harness.users.viewer.email);
});
