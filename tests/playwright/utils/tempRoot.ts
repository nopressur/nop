// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from "fs/promises";
import os from "os";
import path from "path";

export type TempRoot = {
  rootDir: string;
  cleanup: () => Promise<void>;
};

export async function createTempRoot(prefix = "nopressure-pw-"): Promise<TempRoot> {
  const baseDir = "/tmp/nop-test";
  try {
    await fs.mkdir(baseDir, { recursive: true });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "unknown error";
    throw new Error(
      `Playwright temp roots must live under ${baseDir}. Failed to create it: ${message}`
    );
  }
  const rootDir = await fs.mkdtemp(path.join(baseDir, prefix));

  return {
    rootDir,
    cleanup: async () => {
      await fs.rm(rootDir, { recursive: true, force: true });
    },
  };
}
