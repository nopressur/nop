// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test as base } from "@playwright/test";
import { createSeededRandom } from "./utils/rng";
import { createTempRoot } from "./utils/tempRoot";
import { seedFixtureData } from "./utils/seed";
import { launchServer } from "./utils/server";
import { getAvailablePort } from "./utils/ports";

export type HarnessFixture = {
  baseUrl: string;
  runtimeRoot: string;
  users: Awaited<ReturnType<typeof seedFixtureData>>["users"];
  smoke: Awaited<ReturnType<typeof seedFixtureData>>["smoke"];
};

export const test = base.extend<{
  harness: HarnessFixture;
  rng: ReturnType<typeof createSeededRandom>;
}>({
  harness: async ({}, use) => {
    const tempRoot = await createTempRoot();
    const port = await getAvailablePort();
    const seeded = await seedFixtureData(tempRoot.rootDir, { port });
    const server = await launchServer({
      runtimeRoot: tempRoot.rootDir,
      port,
    });

    try {
      await use({
        baseUrl: server.baseUrl,
        runtimeRoot: tempRoot.rootDir,
        users: seeded.users,
        smoke: seeded.smoke,
      });
    } finally {
      await server.stop();
      await tempRoot.cleanup();
    }
  },
  rng: async ({}, use, testInfo) => {
    const seed = process.env.PW_RNG_SEED ?? testInfo.titlePath.join("::");
    const rng = createSeededRandom(seed);
    await use(rng);
  },
});

export { expect } from "@playwright/test";
