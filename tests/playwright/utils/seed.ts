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
  theme: {
    title: string;
    heading: string;
    path: string;
    name: string;
    variables: typeof THEME_E2E_VARIABLES;
  };
  publicRenderFixtures: {
    noNavbarPath: string;
    heroFirstPath: string;
    heroWithHeadingsPath: string;
    autoWidthPath: string;
    wideWidthPath: string;
    narrowWidthPath: string;
    documentStructurePath: string;
    shortcodeDocumentStructurePath: string;
    multipleH1DocumentStructurePath: string;
    noH1DocumentStructurePath: string;
    noRepeatedDocumentStructurePath: string;
    disabledNavbarDocumentStructurePath: string;
    disabledFloatingNavDocumentStructurePath: string;
    heroTitleSubtitleMargin: string;
  };
};

const THEME_E2E_NAME = "theme-e2e";
const THEME_E2E_TITLE = "Theme E2E";
const THEME_E2E_HEADING = "Theme E2E Heading";
export const THEME_E2E_FONT_FAMILY = "Theme E2E Uploaded";

export const THEME_E2E_VARIABLES = {
  "color-background-primary-light": "#f1f2f3",
  "color-background-secondary-light": "#e1e2e3",
  "color-content-background-light": "#ffffff",
  "color-text-primary-light": "#111213",
  "color-text-secondary-light": "#414243",
  "color-navbar-background-light": "#c9d8e8",
  "color-footer-background-light": "#dbe6ef",
  "color-border-light": "rgba(10, 20, 30, 0.4)",
  "color-shadow-light": "rgba(10, 20, 30, 0.25)",
  "color-code-background-light": "#d1d2d3",
  "color-blockquote-background-light": "#c1c2c3",
  "color-table-border-light": "#b1b2b3",
  "color-table-header-background-light": "#a1a2a3",
  "color-background-primary-dark": "#101820",
  "color-background-secondary-dark": "#203040",
  "color-content-background-dark": "#182838",
  "color-text-primary-dark": "#e8f1f8",
  "color-text-secondary-dark": "#9fb3c8",
  "color-navbar-background-dark": "#1a2c3c",
  "color-footer-background-dark": "#152535",
  "color-border-dark": "rgba(200, 210, 220, 0.45)",
  "color-shadow-dark": "rgba(200, 210, 220, 0.2)",
  "color-code-background-dark": "#23384d",
  "color-blockquote-background-dark": "#2a3f54",
  "color-table-border-dark": "#49647f",
  "color-table-header-background-dark": "#31465b",
  "color-content-link-light": "#315f9f",
  "color-content-link-dark": "#7cc7ff",
  "color-breadcrumb-link-dark": "#8dd7ff",
  "color-content-blockquote-border-light": "#215f3f",
  "color-navbar-dropdown-arrow-light": "#733f9f",
  "color-navbar-dropdown-border-top-light": "#51307d",
  "color-navbar-dropdown-item-hover-background-light": "#eadcf7",
  "color-navbar-dropdown-background-dark": "#13273a",
  "color-navbar-dropdown-border-dark": "#2e4d68",
  "color-navbar-dropdown-shadow-dark": "rgba(120, 160, 200, 0.3)",
  "color-navbar-dropdown-item-hover-background-dark": "#24425d",
  "color-navbar-link-hover-background-dark": "#1f3b55",
  "color-navbar-dropdown-link-hover-background-dark": "#2c4e6d",
  "color-notification-warning-background-dark": "#665500",
  "color-notification-warning-text-dark": "#fff2aa",
  "font-body-family": `"${THEME_E2E_FONT_FAMILY}", "Courier New", monospace`,
  "font-heading-family": "Georgia, serif",
  "font-mono-family": "Menlo, monospace",
  "font-body-size": "18px",
  "font-body-line-height": "1.65",
  "font-body-weight": "500",
  "font-heading-weight": "800",
  "font-heading-line-height": "1.35",
  "font-nav-family": `"${THEME_E2E_FONT_FAMILY}", Arial, sans-serif`,
  "font-nav-weight": "600",
  "font-control-family": `"${THEME_E2E_FONT_FAMILY}", Arial, sans-serif`,
  "font-code-size": "15px",
  "font-code-line-height": "1.6",
  "size-content-padding": "28px",
  "size-content-margin-y": "19px",
  "size-navbar-min-height": "54px",
  "size-search-panel-radius": "17px",
  "size-control-radius": "11px",
  "size-code-radius": "9px",
  "size-table-cell-padding": "13px 17px",
  "size-blockquote-padding": "21px",
  "shadow-search-panel": "rgba(12, 34, 56, 0.35) 0px 11px 31px",
  "shadow-content-media": "rgba(12, 34, 56, 0.25) 0px 5px 13px",
  "border-width-control": "3px",
  "border-width-table": "2px",
  "opacity-search-backdrop-light": "0.43",
  "opacity-search-backdrop-dark": "0.81",
  "sc-hero-img-size-height-sm": "41vh",
  "sc-hero-img-size-height-md": "42vh",
  "sc-hero-img-size-height-lg": "63vh",
  "sc-hero-img-size-title-subtitle-margin": "14px",
} as const;

const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=",
  "base64",
);
const WOFF2_STUB = Buffer.from("d09GMgABAAAAAA==", "base64");

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
  const theme = buildThemeVars();
  const themeE2e = buildThemeE2EVars();

  await Promise.all([
    fs.writeFile(path.join(rootDir, "config.yaml"), config, "utf8"),
    fs.writeFile(path.join(rootDir, "users.yaml"), users, "utf8"),
    fs.writeFile(path.join(stateSysDir, "roles.yaml"), roles, "utf8"),
    fs.writeFile(path.join(themesDir, "default.theme"), theme, "utf8"),
    fs.writeFile(path.join(themesDir, `${THEME_E2E_NAME}.theme`), themeE2e, "utf8"),
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

  await writeFlatMarkdown({
    contentDir,
    alias: "docs/search-alpha",
    title: "Search Alpha",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "search-alpha.md",
    body: "# Search Alpha\n\nAlpha search result entry.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "docs/search-beta",
    title: "Search Beta",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "search-beta.md",
    body: "# Search Beta\n\nBeta search result entry.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "docs/search-table-fixture",
    title: "Search Table Fixture",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "search-table-fixture.md",
    tags: ["docs"],
    body: `| Nimbus | Orion | Orion Quartz |
|--------|-------|--------------|`,
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "docs/search-html-fixture",
    title: "Search HTML Fixture",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "search-html-fixture.md",
    tags: ["docs"],
    body: `<p data-kind="zzattrtoken">Nimbus <strong>Orion</strong></p>
<a href="https://zzurltoken.example/path">Orion Quartz</a>`,
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "theme-e2e",
    title: THEME_E2E_TITLE,
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "theme-e2e.md",
    theme: THEME_E2E_NAME,
    body: buildThemeE2EContent(),
  });

  await writeFlatBinary({
    contentDir,
    alias: "assets/render-hero.png",
    title: null,
    mime: "image/png",
    originalFilename: "render-hero.png",
    content: PNG_1X1,
  });

  await writeFlatBinary({
    contentDir,
    alias: "fonts/theme-e2e.woff2",
    title: null,
    mime: "font/woff2",
    originalFilename: "theme-e2e.woff2",
    content: WOFF2_STUB,
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/no-navbar",
    title: "Render No Navbar",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-no-navbar.md",
    disableNavbar: true,
    disableFloatingNav: false,
    body: "# Render No Navbar\n\nThis page intentionally omits the navbar.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/hero-first",
    title: "Render Hero First",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-hero-first.md",
    body: `((hero-img src="/assets/render-hero.png" title="Render Hero" subtitle="Render subtitle"))

# After Render Hero
`,
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/hero-with-headings",
    title: "Render Hero With Headings",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-hero-with-headings.md",
    body: `((hero-img src="/assets/render-hero.png" title="Render Hero" subtitle="Render subtitle"))

# After Render Hero

## Alpha Section

## Beta Section
`,
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/width-auto",
    title: "Render Width Auto",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-width-auto.md",
    contentWidth: "auto",
    body: "# Render Width Auto\n\nShort auto-width text.\n\nThis second paragraph is deliberately long, well beyond any historical automatic-width threshold, so the default auto mode visibly keeps the compact content measure and proves width selection ignores paragraph length.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/width-wide",
    title: "Render Width Wide",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-width-wide.md",
    contentWidth: "wide",
    body: "# Render Width Wide\n\nShort text forced to wide layout.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/width-narrow",
    title: "Render Width Narrow",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-width-narrow.md",
    contentWidth: "narrow",
    body: "# Render Width Narrow\n\nThis paragraph is deliberately long so the narrow metadata mode keeps the content container at the compact width; width selection is fully manual and paragraph length never triggers the wide layout.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/document-structure",
    title: "Render Document Structure",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-document-structure.md",
    theme: THEME_E2E_NAME,
    contentWidth: "narrow",
    body: buildDocumentStructureContent(),
  });

  const navParentId = generateContentId().idHex;
  await writeFlatMarkdown({
    contentDir,
    alias: "render/nav-parent",
    title: "Render Nav Parent",
    navTitle: "Nav Parent",
    navParentId: null,
    navOrder: 1,
    originalFilename: "render-nav-parent.md",
    contentWidth: "narrow",
    idHex: navParentId,
    body: "# Render Nav Parent\n\nParent navigation page.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/nav-child",
    title: "Render Nav Child",
    navTitle: "Nav Child",
    navParentId: navParentId,
    navOrder: 1,
    originalFilename: "render-nav-child.md",
    contentWidth: "narrow",
    body: "# Render Nav Child\n\nChild navigation page.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/document-structure-shortcode",
    title: "Render Shortcode Structure Boundary",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-document-structure-shortcode.md",
    body: buildShortcodeDocumentStructureContent(),
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/document-structure-multiple-h1",
    title: "Render Multiple H1 Structure",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-document-structure-multiple-h1.md",
    body: `# First Top

${longParagraph("First top")}

## First Top Detail

${longParagraph("First detail")}

# Second Top

${longParagraph("Second top")}

## Second Top Detail

${longParagraph("Second detail")}
`,
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/document-structure-no-h1",
    title: "Render No H1 Structure",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-document-structure-no-h1.md",
    body: `## Alpha Without H1

${longParagraph("Alpha")}

## Beta Without H1

${longParagraph("Beta")}
`,
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/document-structure-no-repeat",
    title: "Render No Structure",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-document-structure-no-repeat.md",
    body: "# Lone Title\n\n## Lone Section\n\n### Lone Detail\n\nNo repeated heading rank exists.",
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/document-structure-disabled-navbar",
    title: "Render Disabled Navbar Structure",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-document-structure-disabled-navbar.md",
    disableNavbar: true,
    disableFloatingNav: false,
    body: buildDocumentStructureContent(),
  });

  await writeFlatMarkdown({
    contentDir,
    alias: "render/document-structure-disabled-floating-nav",
    title: "Render Disabled Floating Nav Structure",
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: "render-document-structure-disabled-floating-nav.md",
    disableFloatingNav: true,
    contentWidth: "wide",
    body: buildDocumentStructureContent(),
  });

  const seededUsers = buildSeededUsers();

  return {
    users: seededUsers,
    smoke: {
      title: smokeTitle,
      heading: smokeHeading,
      path: "/",
    },
    theme: {
      title: THEME_E2E_TITLE,
      heading: THEME_E2E_HEADING,
      path: "/theme-e2e",
      name: THEME_E2E_NAME,
      variables: THEME_E2E_VARIABLES,
    },
    publicRenderFixtures: {
      noNavbarPath: "/render/no-navbar",
      heroFirstPath: "/render/hero-first",
      heroWithHeadingsPath: "/render/hero-with-headings",
      autoWidthPath: "/render/width-auto",
      wideWidthPath: "/render/width-wide",
      narrowWidthPath: "/render/width-narrow",
      documentStructurePath: "/render/document-structure",
      shortcodeDocumentStructurePath: "/render/document-structure-shortcode",
      multipleH1DocumentStructurePath: "/render/document-structure-multiple-h1",
      noH1DocumentStructurePath: "/render/document-structure-no-h1",
      noRepeatedDocumentStructurePath: "/render/document-structure-no-repeat",
      disabledNavbarDocumentStructurePath: "/render/document-structure-disabled-navbar",
      disabledFloatingNavDocumentStructurePath: "/render/document-structure-disabled-floating-nav",
      heroTitleSubtitleMargin: "14px",
    },
  };
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

function buildThemeVars(): string {
  return `# Playwright seed theme\ncolor-background-primary-light #f6f6f6\ncolor-text-primary-light #222\ncolor-content-link-light #1f2933\nfont-body-family Arial, sans-serif\nfont-body-size 16px\nfont-body-line-height normal\nsc-hero-img-size-title-subtitle-margin 14px\n`;
}

function buildThemeE2EVars(): string {
  const variables = Object.entries(THEME_E2E_VARIABLES)
    .map(([name, value]) => `${name} ${value}`)
    .join("\n");
  const fontFaces = [
    `font-face-body-family ${THEME_E2E_FONT_FAMILY}`,
    "font-face-body-src /fonts/theme-e2e.woff2",
    "font-face-body-weight 400 800",
    "font-face-body-style normal",
    "font-face-body-display swap",
  ].join("\n");

  return `# Playwright full theme coverage\n${fontFaces}\n${variables}\n`;
}

function buildThemeE2EContent(): string {
  return `# ${THEME_E2E_HEADING}

Theme paragraph text with a [theme link](https://example.test).

> Theme blockquote

\`inline-code\`

\`\`\`text
code block
\`\`\`

| Header | Value |
|--------|-------|
| Cell   | Value |

![Theme image](/assets/render-hero.png)`;
}

function buildDocumentStructureContent(): string {
  return `# Render Document Structure

## Alpha Section

${longParagraph("Alpha")}

### Alpha Detail

${longParagraph("Alpha detail")}

## Beta Section

${longParagraph("Beta")}

### Beta Detail

${longParagraph("Beta detail")}

## Gamma Section

${longParagraph("Gamma")}
`;
}

function buildShortcodeDocumentStructureContent(): string {
  return `# Render Shortcode Structure Boundary

## Markdown Alpha

${longParagraph("Markdown alpha")}

((hero-img src="/assets/render-hero.png" title="Shortcode Generated Heading"))

## Markdown Beta

${longParagraph("Markdown beta")}
`;
}

function longParagraph(label: string): string {
  return Array.from({ length: 18 }, (_, index) => {
    return `${label} paragraph sentence ${index + 1} keeps the public page tall enough for scroll validation.`;
  }).join(" ");
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
  tags?: string[];
  theme?: string | null;
  disableNavbar?: boolean;
  disableFloatingNav?: boolean;
  contentWidth?: "auto" | "wide" | "narrow";
  idHex?: string;
}): Promise<void> {
  const generated = generateContentId();
  const idHex = options.idHex ?? generated.idHex;
  const shard = idHex.slice(-2);
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
    tags: options.tags ?? [],
    navTitle: options.navTitle,
    navParentId: options.navParentId,
    navOrder: options.navOrder,
    originalFilename: options.originalFilename,
    theme: options.theme ?? null,
    disableNavbar: options.disableNavbar ?? false,
    disableFloatingNav: options.disableFloatingNav ?? false,
    contentWidth: options.contentWidth ?? "auto",
  });

  await Promise.all([
    fs.writeFile(blobPath, options.body, "utf8"),
    fs.writeFile(sidecarPath, sidecar, "utf8"),
  ]);
}

async function writeFlatBinary(options: {
  contentDir: string;
  alias: string;
  title: string | null;
  mime: string;
  originalFilename: string;
  content: Buffer;
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
    mime: options.mime,
    tags: [],
    navTitle: null,
    navParentId: null,
    navOrder: null,
    originalFilename: options.originalFilename,
    theme: null,
    disableNavbar: false,
    disableFloatingNav: false,
    contentWidth: "auto",
  });

  await Promise.all([
    fs.writeFile(blobPath, options.content),
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
  title: string | null;
  mime: string;
  tags: string[];
  navTitle: string | null;
  navParentId: string | null;
  navOrder: number | null;
  originalFilename: string | null;
  theme: string | null;
  disableNavbar: boolean;
  disableFloatingNav: boolean;
  contentWidth: "auto" | "wide" | "narrow";
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

  return `(\n    alias: "${options.alias}",\n    title: ${title},\n    mime: "${options.mime}",\n    tags: [${tags}],\n    nav_title: ${navTitle},\n    nav_parent_id: ${navParentId},\n    nav_order: ${navOrder},\n    disable_navbar: ${options.disableNavbar},\n    disable_floating_nav: ${options.disableFloatingNav},\n    content_width: "${options.contentWidth}",\n    original_filename: ${originalFilename},\n    theme: ${theme},\n)\n`;
}
