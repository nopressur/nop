// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import crypto from "crypto";
import fs from "fs/promises";
import path from "path";

const TEST_PASSWORD = "admin123";
const TEST_PASSWORD_BLOCK = {
  front_end_salt: "4bb8e9efee75b8dee093321b00ba8d34",
  back_end_salt: "b5e0df9f7eb148728012a0d654663a0e",
  stored_hash:
    "$argon2id$v=19$m=131072,t=3,p=2$teDfn36xSHKAEqDWVGY6Dg$rlmqD3Zg9rwLO1x3w4+e8hUgTUnXmMBNUyexVOwDaYg",
  password_version: 2,
};

export type SeededUser = {
  email: string;
  name: string;
  password: string;
  roles: string[];
};

export type SeededData = {
  users: {
    admin: SeededUser;
    editor: SeededUser;
    viewer: SeededUser;
  };
  smoke: {
    title: string;
    heading: string;
    path: string;
  };
};

export async function seedFixtureData(
  rootDir: string,
  options: { port: number }
): Promise<SeededData> {
  const contentDir = path.join(rootDir, "content");
  const themesDir = path.join(rootDir, "themes");
  const stateDir = path.join(rootDir, "state");
  const stateSysDir = path.join(stateDir, "sys");
  const stateScDir = path.join(stateDir, "sc");

  await Promise.all([
    fs.mkdir(contentDir, { recursive: true }),
    fs.mkdir(themesDir, { recursive: true }),
    fs.mkdir(stateDir, { recursive: true }),
    fs.mkdir(stateSysDir, { recursive: true }),
    fs.mkdir(stateScDir, { recursive: true }),
  ]);

  const smokeTitle = "00 Smoke Test";
  const smokeHeading = "00 Smoke Test";

  const config = buildConfigYaml(options.port);
  const users = buildUsersYaml();
  const roles = buildRolesYaml();
  const indexMd = buildIndexContent(smokeHeading);
  const theme = buildThemeCss();

  await Promise.all([
    fs.writeFile(path.join(rootDir, "config.yaml"), config, "utf8"),
    fs.writeFile(path.join(rootDir, "users.yaml"), users, "utf8"),
    fs.writeFile(path.join(stateSysDir, "roles.yaml"), roles, "utf8"),
    fs.writeFile(path.join(themesDir, "default.html"), theme, "utf8"),
  ]);

  await writeFlatMarkdown({
    contentDir,
    alias: "index",
    title: smokeTitle,
    navTitle: smokeTitle,
    navParentId: null,
    navOrder: 0,
    originalFilename: "index.md",
    body: indexMd,
  });

  const seededUsers = buildSeededUsers();

  return {
    users: seededUsers,
    smoke: {
      title: smokeTitle,
      heading: smokeHeading,
      path: "/",
    },
  };
}

export async function writeLegacyMarkdown(options: {
  contentDir: string;
  relativePath: string;
  body: string;
}): Promise<void> {
  const fullPath = path.join(options.contentDir, options.relativePath);
  await fs.mkdir(path.dirname(fullPath), { recursive: true });
  await fs.writeFile(fullPath, options.body, "utf8");
}

function buildConfigYaml(port: number): string {
  return `server:\n  host: "127.0.0.1"\n  port: ${port}\n  workers: 2\n\nadmin:\n  path: "/admin"\n\nusers:\n  auth_method: "local"\n  local:\n    jwt:\n      secret: "test-secret"\n\nnavigation: {}\n\nlogging:\n  level: "info"\n\nsecurity:\n  login_sessions:\n    id_requests: 20\n\napp:\n  name: "NoPressure Playwright"\n  description: "Playwright test instance"\n\nupload: {}\n`;
}

function buildUsersYaml(): string {
  return `${buildUserBlock({
    email: "admin@example.com",
    name: "Admin User",
    roles: ["admin"],
  })}\n${buildUserBlock({
    email: "editor@example.com",
    name: "Editor User",
    roles: ["editor"],
  })}\n${buildUserBlock({
    email: "viewer@example.com",
    name: "Viewer User",
    roles: ["viewer"],
  })}`;
}

function buildRolesYaml(): string {
  return ['"admin"', '"editor"', '"viewer"'].map((role) => `- ${role}`).join("\n") + "\n";
}

function buildUserBlock(user: { email: string; name: string; roles: string[] }): string {
  const rolesYaml = user.roles.map((role) => `  - "${role}"`).join("\n");

  return `${user.email}:\n  name: "${user.name}"\n  password:\n    front_end_salt: "${TEST_PASSWORD_BLOCK.front_end_salt}"\n    back_end_salt: "${TEST_PASSWORD_BLOCK.back_end_salt}"\n    stored_hash: "${TEST_PASSWORD_BLOCK.stored_hash}"\n  password_version: ${TEST_PASSWORD_BLOCK.password_version}\n  roles:\n${rolesYaml}\n`;
}

function buildIndexContent(heading: string): string {
  return `# ${heading}\n\nThis page validates the Playwright harness.`;
}

function buildThemeCss(): string {
  return `    <style>\n        body {\n            font-family: Arial, sans-serif;\n            background-color: #f6f6f6;\n            color: #222;\n        }\n\n        .content h1 {\n            color: #1f2933;\n        }\n    </style>\n`;
}

function buildSeededUsers(): SeededData["users"] {
  return {
    admin: {
      email: "admin@example.com",
      name: "Admin User",
      password: TEST_PASSWORD,
      roles: ["admin"],
    },
    editor: {
      email: "editor@example.com",
      name: "Editor User",
      password: TEST_PASSWORD,
      roles: ["editor"],
    },
    viewer: {
      email: "viewer@example.com",
      name: "Viewer User",
      password: TEST_PASSWORD,
      roles: ["viewer"],
    },
  };
}

async function writeFlatMarkdown(options: {
  contentDir: string;
  alias: string;
  title: string;
  navTitle: string | null;
  navParentId: string | null;
  navOrder: number | null;
  originalFilename: string;
  body: string;
}): Promise<void> {
  const { idHex, shard } = generateContentId();
  const version = 0;
  const shardDir = path.join(options.contentDir, shard);
  await fs.mkdir(shardDir, { recursive: true });

  const blobName = `${idHex}.${version}`;
  const blobPath = path.join(shardDir, blobName);
  const sidecarPath = `${blobPath}.ron`;

  const sidecar = buildSidecarRon({
    alias: options.alias,
    title: options.title,
    mime: "text/markdown",
    tags: [],
    navTitle: options.navTitle,
    navParentId: options.navParentId,
    navOrder: options.navOrder,
    originalFilename: options.originalFilename,
    theme: null,
  });

  await Promise.all([
    fs.writeFile(blobPath, options.body, "utf8"),
    fs.writeFile(sidecarPath, sidecar, "utf8"),
  ]);
}

function generateContentId(): { idHex: string; shard: string } {
  const idHex = crypto.randomBytes(8).toString("hex");
  const shard = idHex.slice(-2);
  return { idHex, shard };
}

function buildSidecarRon(options: {
  alias: string;
  title: string;
  mime: string;
  tags: string[];
  navTitle: string | null;
  navParentId: string | null;
  navOrder: number | null;
  originalFilename: string | null;
  theme: string | null;
}): string {
  const tags = options.tags.map((tag) => `"${tag}"`).join(", ");
  const theme = options.theme ? `Some("${options.theme}")` : "None";
  const originalFilename = options.originalFilename
    ? `Some("${options.originalFilename}")`
    : "None";
  const title = options.title ? `Some("${options.title}")` : "None";
  const navTitle = options.navTitle ? `Some("${options.navTitle}")` : "None";
  const navParentId = options.navParentId ? `Some("${options.navParentId}")` : "None";
  const navOrder =
    options.navOrder !== null && options.navOrder !== undefined
      ? `Some(${options.navOrder})`
      : "None";

  return `(\n    alias: "${options.alias}",\n    title: ${title},\n    mime: "${options.mime}",\n    tags: [${tags}],\n    nav_title: ${navTitle},\n    nav_parent_id: ${navParentId},\n    nav_order: ${navOrder},\n    original_filename: ${originalFilename},\n    theme: ${theme},\n)\n`;
}
