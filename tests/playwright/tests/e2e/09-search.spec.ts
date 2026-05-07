// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { humanClick, humanType } from "../../utils/humanInput";

test("search button is always visible on mobile and outside hamburger menu", async ({ page, harness, rng }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}/`);

  const searchButton = page.locator("[data-site-search-button]:visible");
  await expect(searchButton).toBeVisible();
  await expect(page.locator("[data-site-mobile-menu] [data-site-search-button]:visible")).toHaveCount(0);

  await humanClick(page.locator("[data-site-mobile-toggle]"), rng);
  await expect(searchButton).toBeVisible();

  await humanClick(searchButton, rng);
  await expect(page.locator("[data-site-search-overlay]")).toBeVisible();
});

test("search overlay supports threshold, keyboard navigation, and enter routing", async ({ page, harness, rng }) => {
  let requestCount = 0;
  await page.route("**/api/search**", async (route) => {
    requestCount += 1;
    const url = new URL(route.request().url());
    const q = (url.searchParams.get("q") ?? "").trim().toLowerCase();
    if (q.length < 3) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        { id: "0000000000000001", alias: "docs/search-alpha", title: "Search Alpha" },
        { id: "0000000000000002", alias: "docs/search-beta", title: "Search Beta" },
      ]),
    });
  });

  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await expect(input).toBeFocused();

  await humanType(input, "se", rng);
  await page.waitForTimeout(350);
  await expect(page.getByText("No results")).toHaveCount(0);
  await expect(page.locator(".site-search-result")).toHaveCount(0);
  expect(requestCount).toBe(0);

  await humanType(input, "arch", rng);
  await expect(page.locator(".site-search-result")).toHaveCount(2);

  await page.keyboard.press("ArrowDown");
  await expect(page.locator(".site-search-result.is-active")).toContainText("Search Alpha");

  await page.keyboard.press("ArrowDown");
  await expect(page.locator(".site-search-result.is-active")).toContainText("Search Beta");

  await page.keyboard.press("ArrowDown");
  await expect(page.locator(".site-search-result.is-active")).toContainText("Search Alpha");

  await page.keyboard.press("ArrowUp");
  await expect(page.locator(".site-search-result.is-active")).toContainText("Search Beta");

  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/docs\/search-beta$/);
});

test("search overlay renders request failure state and closes with escape", async ({ page, harness, rng }) => {
  await page.goto(`${harness.baseUrl}/`);
  await page.route("**/api/search**", async (route) => {
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ message: "forced failure" }),
    });
  });

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, "search", rng);
  await expect(page.getByText("Search didn't work.")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.locator("[data-site-search-overlay]")).toBeHidden();
});

test("search overlay returns seeded fixtures", async ({ page, harness, rng }) => {
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await expect(input).toBeFocused();

  await humanType(input, "nimbus", rng);

  const tableResult = page.locator(".site-search-result__title", {
    hasText: "Search Table Fixture",
  });
  const htmlResult = page.locator(".site-search-result__title", {
    hasText: "Search HTML Fixture",
  });

  await expect(tableResult).toBeVisible();
  await expect(htmlResult).toBeVisible();
});

async function stubSearchAndCapture(page: import("@playwright/test").Page): Promise<string[]> {
  const queries: string[] = [];
  await page.route("**/api/search**", async (route) => {
    const url = new URL(route.request().url());
    queries.push(url.searchParams.get("q") ?? "");
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    });
  });
  return queries;
}

test("search input keeps trailing space and sends trimmed query", async ({ page, harness, rng }) => {
  const queries = await stubSearchAndCapture(page);
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, "sea ", rng);
  await page.waitForTimeout(350);

  await expect(input).toHaveValue("sea ");
  expect(queries).toEqual(["sea"]);
});

test("search input keeps leading space and sends trimmed query", async ({ page, harness, rng }) => {
  const queries = await stubSearchAndCapture(page);
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, " sea", rng);
  await page.waitForTimeout(350);

  await expect(input).toHaveValue(" sea");
  expect(queries).toEqual(["sea"]);
});

test("search input keeps interior space when typed mid-string", async ({ page, harness, rng }) => {
  const queries = await stubSearchAndCapture(page);
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, "hel", rng);
  await input.press("Space");
  await humanType(input, "lo", rng);
  await page.waitForTimeout(350);

  await expect(input).toHaveValue("hel lo");
  expect(queries[queries.length - 1]).toBe("hel lo");
});

test("search input stays idle for whitespace-only query", async ({ page, harness, rng }) => {
  const queries = await stubSearchAndCapture(page);
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, "   ", rng);
  await page.waitForTimeout(350);

  await expect(input).toHaveValue("   ");
  expect(queries).toEqual([]);
  await expect(page.getByText("No results")).toHaveCount(0);
});

test("search input stays idle when padded query trims below threshold", async ({ page, harness, rng }) => {
  const queries = await stubSearchAndCapture(page);
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, "  ab  ", rng);
  await page.waitForTimeout(350);

  await expect(input).toHaveValue("  ab  ");
  expect(queries).toEqual([]);
  await expect(page.getByText("No results")).toHaveCount(0);
});

test("search input fires trimmed query when padding wraps a threshold-length term", async ({ page, harness, rng }) => {
  const queries = await stubSearchAndCapture(page);
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, " abc ", rng);
  await page.waitForTimeout(350);

  await expect(input).toHaveValue(" abc ");
  expect(queries).toEqual(["abc"]);
});

test("search input survives typing additional characters after a trailing space", async ({ page, harness, rng }) => {
  const queries = await stubSearchAndCapture(page);
  await page.goto(`${harness.baseUrl}/`);

  await humanClick(page.locator("[data-site-search-button]:visible"), rng);
  const input = page.locator("[data-site-search-input]");
  await humanType(input, "sea", rng);
  await input.press("Space");
  await humanType(input, "rch", rng);
  await page.waitForTimeout(350);

  await expect(input).toHaveValue("sea rch");
  expect(queries[queries.length - 1]).toBe("sea rch");
});
