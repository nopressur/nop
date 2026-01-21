// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from "fs/promises";
import path from "path";
import { test, expect } from "../../fixtures";
import { login, logoutViaApi } from "../../utils/auth";
import { humanClick, humanClearAndType } from "../../utils/humanInput";

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

test("system logging settings save and cancel behavior", async ({
  page,
  harness,
  rng,
}) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/system",
    expectedPath: "/admin/system",
  });

  await expect(page.getByRole("heading", { name: "Runtime Settings" })).toBeVisible();

  await expect(page.getByText(/run mode:\s*foreground/i)).toBeVisible();
  await expect(page.getByText(/file logging:\s*inactive/i)).toBeVisible();

  const sizeInput = page.locator("#logging-size");
  const filesInput = page.locator("#logging-files");
  const cancelButton = page.getByRole("button", { name: "Cancel" });
  const saveButton = page.getByRole("button", { name: "Save" });

  await expect(sizeInput).toHaveValue("16");
  await expect(filesInput).toHaveValue("10");
  await expect(cancelButton).toBeDisabled();
  await expect(saveButton).toBeDisabled();

  await humanClearAndType(sizeInput, "20", rng);
  await expect(saveButton).toBeEnabled();
  await expect(cancelButton).toBeEnabled();

  await humanClick(cancelButton, rng);
  await expect(sizeInput).toHaveValue("16");
  await expect(filesInput).toHaveValue("10");
  await expect(saveButton).toBeDisabled();

  await humanClearAndType(sizeInput, "20", rng);
  await humanClearAndType(filesInput, "5", rng);
  await humanClick(saveButton, rng);

  await expect(page.getByText("Logging settings updated")).toBeVisible();
  await expect(sizeInput).toHaveValue("20");
  await expect(filesInput).toHaveValue("5");
  await expect(saveButton).toBeDisabled();

  const configPath = path.join(harness.runtimeRoot, "config.yaml");
  const configContent = await fs.readFile(configPath, "utf8");
  expect(configContent).toContain("rotation:");
  expect(configContent).toContain("max_size_mb: 20");
  expect(configContent).toContain("max_files: 5");

  await logoutViaApi({ page, baseUrl: harness.baseUrl });
});

test("system logging clear deletes log files", async ({ page, harness, rng }) => {
  const logsDir = path.join(harness.runtimeRoot, "logs");
  await fs.mkdir(logsDir, { recursive: true });
  const baseLog = path.join(logsDir, "nopressure.log");
  const rotatedLog = path.join(logsDir, "nopressure.log.1");
  await fs.writeFile(baseLog, "log data", "utf8");
  await fs.writeFile(rotatedLog, "more log data", "utf8");

  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/system",
    expectedPath: "/admin/system",
  });

  await expect(page.getByRole("heading", { name: "Runtime Settings" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "Clear Logs" }), rng);
  const clearModal = page.getByRole("dialog", { name: "Clear logs" });
  await expect(clearModal).toBeVisible();
  await humanClick(clearModal.getByRole("button", { name: "Clear logs" }), rng);

  await expect(page.getByText(/cleared .* log files/i)).toBeVisible();
  expect(await fileExists(baseLog)).toBe(false);
  expect(await fileExists(rotatedLog)).toBe(false);

  await logoutViaApi({ page, baseUrl: harness.baseUrl });
});
