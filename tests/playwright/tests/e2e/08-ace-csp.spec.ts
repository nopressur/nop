// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login } from "../../utils/auth";
import { humanClick } from "../../utils/humanInput";

test("ace editor styles include CSP nonce", async ({ page, harness, rng }) => {
  const consoleErrors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      consoleErrors.push(msg.text());
    }
  });

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

  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );

  await page.waitForFunction(
    () => {
      const styles = Array.from(document.querySelectorAll("style"));
      return styles.some((style) => {
        const id = style.getAttribute("id") ?? "";
        return id.startsWith("ace-") || id === "error_marker.css";
      });
    },
    { timeout: 15000 }
  );

  const aceStyles = await page.evaluate(() => {
    const styles = Array.from(document.querySelectorAll("style"));
    return styles
      .filter((style) => {
        const id = style.getAttribute("id") ?? "";
        return id.startsWith("ace-") || id === "error_marker.css";
      })
      .map((style) => ({
        id: style.getAttribute("id"),
        hasNonce: style.hasAttribute("nonce"),
      }));
  });

  expect(aceStyles.length).toBeGreaterThan(0);
  expect(aceStyles.filter((style) => !style.hasNonce)).toEqual([]);

  const cspErrors = consoleErrors.filter((message) =>
    /Content Security Policy|Refused to apply a stylesheet/i.test(message)
  );
  expect(cspErrors).toEqual([]);
});
