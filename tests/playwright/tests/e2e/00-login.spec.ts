// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login } from "../../utils/auth";
import {
  humanClick,
  humanClearAndType,
  humanType,
} from "../../utils/humanInput";

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test("login flow renders and signs in", async ({ page, harness, rng }) => {
  const loginUrl = new URL("/login", harness.baseUrl);
  loginUrl.searchParams.set("return_path", "/");
  await page.goto(loginUrl.toString());

  await expect(
    page.getByRole("heading", { name: /sign in/i })
  ).toBeVisible();

  await humanType(page.getByLabel("Email"), harness.users.admin.email, rng);
  await humanClick(page.getByRole("button", { name: "Continue" }), rng);

  const passwordInput = page.getByLabel("Password");
  await passwordInput.waitFor();
  await humanType(passwordInput, harness.users.admin.password, rng);

  const expectedUrl = new RegExp(`${escapeRegex(harness.baseUrl)}/?$`);
  await Promise.all([
    page.waitForURL(expectedUrl, { timeout: 15000 }),
    humanClick(page.getByRole("button", { name: "Sign in" }), rng),
  ]);

  const userMenu = page.locator("[data-site-user-menu]");
  await expect(
    userMenu.getByRole("link", { name: harness.users.admin.name })
  ).toBeVisible({ timeout: 15000 });
});

test("profile view updates display name", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin",
    expectedPath: "/admin",
  });

  await page.goto(`${harness.baseUrl}/login/profile`);
  await expect(
    page.getByRole("heading", { name: "Profile" })
  ).toBeVisible();
  await expect(page.getByText(harness.users.admin.email)).toBeVisible();

  await humanClearAndType(
    page.getByLabel("Display name"),
    "Admin User Updated",
    rng
  );
  await humanClick(page.getByRole("button", { name: "Save profile" }), rng);

  await expect(
    page.getByText("Profile updated successfully")
  ).toBeVisible();
});

test("login invalid password resets to email step", async ({ page, harness, rng }) => {
  const loginUrl = new URL("/login", harness.baseUrl);
  loginUrl.searchParams.set("return_path", "/admin");
  await page.goto(loginUrl.toString());

  const emailInput = page.getByLabel("Email");
  await emailInput.waitFor();
  await humanType(emailInput, harness.users.admin.email, rng);
  await humanClick(page.getByRole("button", { name: "Continue" }), rng);

  const passwordInput = page.getByLabel("Password");
  await passwordInput.waitFor();
  await humanType(passwordInput, "not-the-password", rng);
  await humanClick(page.getByRole("button", { name: "Sign in" }), rng);

  await expect(page.locator(".callout-error")).toContainText(
    /invalid email or password/i,
    { timeout: 15000 }
  );
  await expect(emailInput).toBeVisible();
  await expect(emailInput).toHaveValue("");
  await expect(page.getByLabel("Password")).toHaveCount(0);
});

test("login unknown email resets to email step", async ({ page, harness, rng }) => {
  const loginUrl = new URL("/login", harness.baseUrl);
  loginUrl.searchParams.set("return_path", "/admin");
  await page.goto(loginUrl.toString());

  const emailInput = page.getByLabel("Email");
  await emailInput.waitFor();
  await humanType(emailInput, "missing.user@example.com", rng);
  await humanClick(page.getByRole("button", { name: "Continue" }), rng);

  const passwordInput = page.getByLabel("Password");
  await passwordInput.waitFor();
  await humanType(passwordInput, "missing-password", rng);
  await humanClick(page.getByRole("button", { name: "Sign in" }), rng);

  await expect(page.locator(".callout-error")).toContainText(
    /invalid email or password/i,
    { timeout: 15000 }
  );
  await expect(emailInput).toBeVisible();
  await expect(emailInput).toHaveValue("");
  await expect(page.getByLabel("Password")).toHaveCount(0);
});

test("login invalid return_path falls back to admin", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "https://example.invalid/evil",
    expectedPath: "/admin",
  });

  await expect(
    page.getByRole("heading", { name: "Content Library" })
  ).toBeVisible({ timeout: 15000 });
});

test("profile password mismatch shows error", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin",
    expectedPath: "/admin",
  });

  await page.goto(`${harness.baseUrl}/login/profile`);
  await expect(page.getByRole("heading", { name: "Profile" })).toBeVisible();
  await humanClick(page.getByRole("button", { name: "Change" }), rng);

  await humanType(
    page.getByLabel("Current password", { exact: true }),
    harness.users.admin.password,
    rng
  );
  await humanType(
    page.getByLabel("New password", { exact: true }),
    "MismatchPass123!",
    rng
  );
  await humanType(
    page.getByLabel("Confirm new password", { exact: true }),
    "MismatchPass456!",
    rng
  );

  await humanClick(page.getByRole("button", { name: "Update password" }), rng);
  await expect(page.getByText("New passwords do not match.")).toBeVisible();
});

test("profile wrong current password shows error", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin",
    expectedPath: "/admin",
  });

  await page.goto(`${harness.baseUrl}/login/profile`);
  await expect(page.getByRole("heading", { name: "Profile" })).toBeVisible();
  await humanClick(page.getByRole("button", { name: "Change" }), rng);

  await humanType(
    page.getByLabel("Current password", { exact: true }),
    "wrong-password",
    rng
  );
  await humanType(
    page.getByLabel("New password", { exact: true }),
    "CorrectPass123!",
    rng
  );
  await humanType(
    page.getByLabel("Confirm new password", { exact: true }),
    "CorrectPass123!",
    rng
  );

  await humanClick(page.getByRole("button", { name: "Update password" }), rng);
  await expect(
    page.getByText("Current password is invalid")
  ).toBeVisible({ timeout: 15000 });
});

test("public navbar logout clears auth cookie", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin",
    expectedPath: "/admin",
  });

  await page.goto(`${harness.baseUrl}/`);
  await page.waitForFunction(() => {
    return Boolean((window as { __nopSiteNavigationInit?: boolean }).__nopSiteNavigationInit);
  });

  const userMenu = page.locator("[data-site-user-menu]");
  const userNav = userMenu.getByRole("link", { name: harness.users.admin.name });
  await expect(userNav).toBeVisible({ timeout: 15000 });

  await humanClick(userNav, rng);
  const dropdown = userMenu.locator("[data-site-dropdown]");
  await expect(dropdown).toHaveClass(/is-active/, { timeout: 15000 });
  const logoutLink = userMenu.getByRole("link", { name: "Logout" });
  await expect(logoutLink).toBeVisible({ timeout: 15000 });

  const logoutResponsePromise = page.waitForResponse((response) => {
    return (
      response.url().endsWith("/login/logout-api") &&
      response.request().method() === "POST"
    );
  });

  const homePattern = new RegExp(`${escapeRegex(harness.baseUrl)}/?$`);
  await Promise.all([
    page.waitForURL(homePattern, { timeout: 15000 }),
    humanClick(logoutLink, rng),
  ]);

  const logoutResponse = await logoutResponsePromise;
  expect(logoutResponse.ok()).toBeTruthy();

  const cookies = await page.context().cookies();
  expect(cookies.some((cookie) => cookie.name === "nop_auth")).toBeFalsy();

  const browser = page.context().browser();
  if (!browser) {
    throw new Error("Browser instance unavailable for logout check");
  }

  const freshContext = await browser.newContext();
  const freshPage = await freshContext.newPage();
  await freshPage.goto(`${harness.baseUrl}/login/profile`);
  await expect(freshPage.getByRole("heading", { name: /sign in/i })).toBeVisible();
  await freshContext.close();
});

test("profile logout returns to login", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin",
    expectedPath: "/admin",
  });

  await page.goto(`${harness.baseUrl}/login/profile`);
  await expect(page.getByRole("heading", { name: "Profile" })).toBeVisible();

  const loginUrlPattern = new RegExp(
    `${escapeRegex(harness.baseUrl)}/login(?:\\?.*)?$`
  );
  const logoutResponsePromise = page.waitForResponse((response) => {
    return (
      response.url().endsWith("/login/logout-api") &&
      response.request().method() === "POST"
    );
  });

  await Promise.all([
    page.waitForURL(loginUrlPattern, {
      timeout: 15000,
    }),
    humanClick(page.getByRole("button", { name: "Log out" }), rng),
  ]);

  const logoutResponse = await logoutResponsePromise;
  expect(logoutResponse.ok()).toBeTruthy();

  await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
  const cookies = await page.context().cookies();
  expect(cookies.some((cookie) => cookie.name === "nop_auth")).toBeFalsy();

  const browser = page.context().browser();
  if (!browser) {
    throw new Error("Browser instance unavailable for logout check");
  }

  const freshContext = await browser.newContext();
  const freshPage = await freshContext.newPage();
  await freshPage.goto(`${harness.baseUrl}/login/profile`);
  await expect(freshPage.getByRole("heading", { name: /sign in/i })).toBeVisible();
  await freshContext.close();
});
