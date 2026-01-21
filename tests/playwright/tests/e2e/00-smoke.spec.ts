// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";

test("00 smoke renders known page", async ({ page, harness }) => {
  await page.goto(`${harness.baseUrl}${harness.smoke.path}`);

  const heading = page.getByRole("heading", {
    name: harness.smoke.heading,
  });

  await expect(heading).toBeVisible();
  await expect(page).toHaveTitle(harness.smoke.title);
});
