// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { defineConfig } from "@playwright/test";
import os from "os";
import path from "path";

const runId = process.env.PW_RUN_ID ?? "local";
const artifactsRoot =
  process.env.PW_OUTPUT_DIR ?? path.join(os.tmpdir(), `nopressure-pw-${runId}`);

export default defineConfig({
  testDir: path.join(__dirname, "tests"),
  outputDir: path.join(artifactsRoot, "test-results"),
  timeout: 120_000,
  expect: {
    timeout: 3_000,
  },
  fullyParallel: true,
  reporter: [
    ["list"],
    [
      "html",
      {
        outputFolder: path.join(artifactsRoot, "report"),
        open: "never",
      },
    ],
  ],
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    actionTimeout: 5_000,
    navigationTimeout: 3_000,
  },
  projects: [
    {
      name: "e2e",
      testDir: path.join(__dirname, "tests", "e2e"),
    },
    {
      name: "ux",
      testDir: path.join(__dirname, "tests", "ux"),
      use: {
        trace: "off",
        video: "off",
      },
    },
  ],
});
