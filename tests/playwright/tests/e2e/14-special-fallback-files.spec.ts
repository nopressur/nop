// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import fs from "fs/promises";
import path from "path";
import { test, expect } from "@playwright/test";
import { getAvailablePort } from "../../utils/ports";
import { seedFixtureData } from "../../utils/seed";
import { launchServer } from "../../utils/server";
import { createTempRoot } from "../../utils/tempRoot";

const UPLOADED_FAVICON = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x46, 0x41, 0x56,
]);

test("favicon special fallback serves builtin asset when no public alias exists", async ({
  page,
  request,
}) => {
  const tempRoot = await createTempRoot();
  const port = await getAvailablePort();
  await seedFixtureData(tempRoot.rootDir, { port });
  const server = await launchServer({ runtimeRoot: tempRoot.rootDir, port });

  try {
    await page.goto(server.baseUrl);
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", "/favicon.ico");

    const [favicon, builtin] = await Promise.all([
      request.get(`${server.baseUrl}/favicon.ico`),
      request.get(`${server.baseUrl}/builtin/favicon.ico`),
    ]);

    expect(favicon.status()).toBe(200);
    expect(builtin.status()).toBe(200);
    expect(await favicon.body()).toEqual(await builtin.body());
  } finally {
    await server.stop();
    await tempRoot.cleanup();
  }
});

test("favicon special fallback serves public uploaded alias before builtin", async ({
  page,
  request,
}) => {
  const tempRoot = await createTempRoot();
  const port = await getAvailablePort();
  await seedFixtureData(tempRoot.rootDir, { port });
  await writeFlatBinary({
    rootDir: tempRoot.rootDir,
    idHex: "0000000000fafa01",
    alias: "favicon.ico",
    mime: "image/png",
    originalFilename: "favicon.ico",
    content: UPLOADED_FAVICON,
  });
  const server = await launchServer({ runtimeRoot: tempRoot.rootDir, port });

  try {
    await page.goto(server.baseUrl);
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", "/favicon.ico");

    const [favicon, builtin] = await Promise.all([
      request.get(`${server.baseUrl}/favicon.ico`),
      request.get(`${server.baseUrl}/builtin/favicon.ico`),
    ]);

    expect(favicon.status()).toBe(200);
    expect(builtin.status()).toBe(200);
    expect(await favicon.body()).toEqual(UPLOADED_FAVICON);
    expect(await favicon.body()).not.toEqual(await builtin.body());
  } finally {
    await server.stop();
    await tempRoot.cleanup();
  }
});

async function writeFlatBinary(options: {
  rootDir: string;
  idHex: string;
  alias: string;
  mime: string;
  originalFilename: string;
  content: Buffer;
}): Promise<void> {
  const version = 0;
  const shard = options.idHex.slice(-2);
  const shardDir = path.join(options.rootDir, "content", shard);
  await fs.mkdir(shardDir, { recursive: true });

  const blobPath = path.join(shardDir, `${options.idHex}.${version}`);
  const sidecarPath = `${blobPath}.ron`;
  const sidecar = `(
    alias: "${options.alias}",
    title: None,
    mime: "${options.mime}",
    tags: [],
    nav_title: None,
    nav_parent_id: None,
    nav_order: None,
    disable_navbar: false,
    content_width: "auto",
    original_filename: Some("${options.originalFilename}"),
    theme: None,
)
`;

  await Promise.all([
    fs.writeFile(blobPath, options.content),
    fs.writeFile(sidecarPath, sidecar, "utf8"),
  ]);
}
