// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import type { Page } from "@playwright/test";
import { expect, test } from "../../fixtures";
import { THEME_E2E_FONT_FAMILY, THEME_E2E_VARIABLES } from "../../utils/seed";

type Scheme = "light" | "dark";

test("exposes every configurable theme variable in the browser", async ({ page, harness }) => {
  await page.goto(`${harness.baseUrl}${harness.theme.path}`);

  const variableNames = Object.keys(THEME_E2E_VARIABLES);
  const observed = await page.evaluate((names) => {
    const rootStyle = getComputedStyle(document.documentElement);

    return Object.fromEntries(
      names.map((name) => [name, rootStyle.getPropertyValue(`--${name}`).trim()])
    );
  }, variableNames);

  for (const [name, expectedValue] of Object.entries(THEME_E2E_VARIABLES)) {
    expect(observed[name], name).toBe(expectedValue);
  }
});

test("emits uploaded font-face rules with release-busted public font urls", async ({
  page,
  harness,
}) => {
  const fontResponse = await page.request.get(`${harness.baseUrl}/fonts/theme-e2e.woff2`);
  expect(fontResponse.status()).toBe(200);

  await page.goto(`${harness.baseUrl}${harness.theme.path}`);

  const fontFaces = await page.evaluate(() => {
    const rules: Array<Record<string, string>> = [];

    for (const sheet of Array.from(document.styleSheets)) {
      let cssRules: CSSRuleList;
      try {
        cssRules = sheet.cssRules;
      } catch {
        continue;
      }

      for (const rule of Array.from(cssRules)) {
        if (rule instanceof CSSFontFaceRule) {
          rules.push({
            family: rule.style.getPropertyValue("font-family").trim(),
            src: rule.style.getPropertyValue("src").trim(),
            weight: rule.style.getPropertyValue("font-weight").trim(),
            style: rule.style.getPropertyValue("font-style").trim(),
            display: rule.style.getPropertyValue("font-display").trim(),
          });
        }
      }
    }

    return rules;
  });

  const uploadedFont = fontFaces.find((rule) => rule.family === `"${THEME_E2E_FONT_FAMILY}"`);
  expect(uploadedFont).toBeDefined();
  expect(uploadedFont?.src).toContain("/fonts/theme-e2e.woff2?v=");
  expect(uploadedFont?.weight).toBe("400 800");
  expect(uploadedFont?.style).toBe("normal");
  expect(uploadedFont?.display).toBe("swap");
});

test("code copy button reveals on hover or focus without reserving space", async ({
  page,
  harness,
}) => {
  await page.goto(`${harness.baseUrl}${harness.theme.path}`);

  const figure = page.locator('.content figure[data-site-code-block="true"]').first();
  const button = figure.locator('button[data-site-code-copy="true"]');
  await expect(button).toBeAttached();
  await expect(button.locator('img[src="/builtin/copy.svg"]')).toBeAttached();

  const opacity = () => button.evaluate((el) => getComputedStyle(el).opacity);
  await expect.poll(opacity).toBe("0");

  await figure.hover();
  await expect.poll(opacity).toBe("1");

  await button.focus();
  await expect.poll(opacity).toBe("1");
});

for (const scheme of ["light", "dark"] as const) {
  test(`applies theme variables to public computed styles in ${scheme} mode`, async ({
    page,
    harness,
  }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(`${harness.baseUrl}${harness.theme.path}`);

    const styles = await collectThemeStyles(page);
    const expected = expectedStyles(scheme);

    expect(styles.body.backgroundColor).toBe(expected.backgroundPrimary);
    expect(styles.body.color).toBe(expected.textPrimary);
    expect(styles.body.fontFamily).toContain("Courier New");
    expect(styles.body.fontFamily).toContain(THEME_E2E_FONT_FAMILY);
    expect(styles.body.fontSize).toBe("18px");
    expect(styles.body.lineHeight).toBe("29.7px");
    expect(styles.body.fontWeight).toBe("500");

    expect(styles.main.backgroundImage).toContain(expected.backgroundPrimary);
    expect(styles.main.backgroundImage).toContain(expected.backgroundSecondary);

    expect(styles.content.color).toBe(expected.textPrimary);
    expect(styles.content.marginTop).toBe("19px");
    expect(styles.content.paddingTop).toBe("28px");
    expect(styles.heading.color).toBe(expected.textPrimary);
    expect(styles.heading.fontFamily).toContain("Georgia");
    expect(styles.heading.fontWeight).toBe("800");
    expect(lineHeightRatio(styles.heading.lineHeight, styles.heading.fontSize)).toBeCloseTo(
      1.35,
      2
    );
    expect(styles.paragraph.color).toBe(expected.textSecondary);
    expect(styles.link.color).toBe(expected.link);

    expect(styles.blockquote.backgroundColor).toBe(expected.blockquoteBackground);
    expect(styles.blockquote.color).toBe(expected.textPrimary);
    expect(styles.blockquote.borderLeftColor).toBe(expected.blockquoteBorder);
    expect(styles.blockquote.borderLeftWidth).toBe("3px");
    expect(styles.blockquote.paddingTop).toBe("21px");

    expect(styles.inlineCode.backgroundColor).toBe(expected.codeBackground);
    expect(styles.inlineCode.color).toBe(expected.textPrimary);
    expect(styles.inlineCode.fontFamily).toContain("Menlo");
    expect(styles.inlineCode.borderTopLeftRadius).toBe("9px");
    expect(styles.inlineCode.fontSize).toBe("15px");
    expect(styles.inlineCode.lineHeight).toBe("24px");
    expect(styles.codeBlock.backgroundColor).toBe(expected.codeBackground);
    expect(styles.codeBlock.borderTopColor).toBe(expected.border);
    expect(styles.codeBlock.borderTopWidth).toBe("3px");
    expect(styles.codeBlock.borderTopLeftRadius).toBe("9px");

    expect(styles.table.borderTopColor).toBe(expected.tableBorder);
    expect(styles.table.borderTopWidth).toBe("2px");
    expect(styles.tableHeading.backgroundColor).toBe(expected.tableHeadingBackground);
    expect(styles.tableHeading.color).toBe(expected.textPrimary);
    expect(styles.tableCell.color).toBe(expected.textSecondary);
    expect(styles.tableCell.borderTopWidth).toBe("2px");
    expect(styles.tableCell.paddingTop).toBe("13px");
    expect(styles.tableCell.paddingRight).toBe("17px");

    expect(styles.media.boxShadow).toContain("rgba(12, 34, 56, 0.25)");
    expect(styles.searchTrigger.fontFamily).toContain(THEME_E2E_FONT_FAMILY);
    expect(styles.searchTrigger.fontWeight).toBe("600");
    expect(styles.searchTrigger.minHeight).toBe("54px");
    expect(styles.searchBackdrop.opacity).toBe(
      THEME_E2E_VARIABLES[`opacity-search-backdrop-${scheme}`]
    );
    expect(styles.searchPanel.borderTopLeftRadius).toBe("17px");
    expect(styles.searchPanel.borderTopWidth).toBe("3px");
    expect(styles.searchPanel.boxShadow).toContain("rgba(12, 34, 56, 0.35)");
    expect(styles.searchInput.borderTopLeftRadius).toBe("11px");
    expect(styles.searchInput.fontFamily).toContain(THEME_E2E_FONT_FAMILY);

    expect(styles.title.color).toBe(expected.textPrimary);
    expect(styles.title.bulmaTitleColor).toBe(
      THEME_E2E_VARIABLES[`color-text-primary-${scheme}`]
    );
    expect(styles.subtitle.color).toBe(expected.textSecondary);
    expect(styles.subtitle.bulmaSubtitleColor).toBe(
      THEME_E2E_VARIABLES[`color-text-secondary-${scheme}`]
    );

    if (scheme === "dark") {
      expect(styles.warning.backgroundColor).toBe(rgb("#665500"));
      expect(styles.warning.color).toBe(rgb("#fff2aa"));
    }
  });
}

async function collectThemeStyles(page: Page) {
  return page.evaluate(() => {
    const pick = <T extends keyof CSSStyleDeclaration & string>(
      style: CSSStyleDeclaration,
      properties: readonly T[]
    ): Record<T, string> => {
      return Object.fromEntries(
        properties.map((property) => [property, String(style[property] ?? "")])
      ) as Record<T, string>;
    };

    const style = (selector: string) => {
      const element = document.querySelector(selector);
      if (!element) {
        throw new Error(`Missing theme fixture element: ${selector}`);
      }

      return getComputedStyle(element);
    };
    const probe = (className: string) => {
      const element = document.createElement("p");
      element.className = className;
      element.textContent = className;
      element.setAttribute("data-theme-style-probe", className);
      element.style.position = "absolute";
      element.style.left = "-10000px";
      document.body.append(element);

      return element;
    };

    const titleProbe = probe("title");
    const subtitleProbe = probe("subtitle");
    const warningProbe = probe("notification is-warning");
    const body = style("body");
    const main = style(".main-container");
    const content = style(".content");
    const heading = style(".content h1");
    const paragraph = style(".content p:not(.title):not(.subtitle)");
    const link = style('.content a[href^="https://example.test"]');
    const blockquote = style(".content blockquote");
    const inlineCode = style(".content p code");
    const codeBlock = style('.content figure[data-site-code-block="true"] pre');
    const table = style(".content table");
    const tableHeading = style(".content table th");
    const tableCell = style(".content table td");
    const title = getComputedStyle(titleProbe);
    const subtitle = getComputedStyle(subtitleProbe);
    const warning = getComputedStyle(warningProbe);

    return {
      body: pick(body, [
        "backgroundColor",
        "color",
        "fontFamily",
        "fontSize",
        "fontWeight",
        "lineHeight",
      ]),
      main: pick(main, ["backgroundImage"]),
      content: pick(content, ["color", "marginTop", "paddingTop"]),
      heading: pick(heading, ["color", "fontFamily", "fontSize", "fontWeight", "lineHeight"]),
      paragraph: pick(paragraph, ["color"]),
      link: pick(link, ["color"]),
      blockquote: pick(blockquote, [
        "backgroundColor",
        "borderLeftColor",
        "borderLeftWidth",
        "color",
        "paddingTop",
      ]),
      inlineCode: pick(inlineCode, [
        "backgroundColor",
        "borderTopLeftRadius",
        "color",
        "fontFamily",
        "fontSize",
        "lineHeight",
      ]),
      codeBlock: pick(codeBlock, [
        "backgroundColor",
        "borderTopColor",
        "borderTopLeftRadius",
        "borderTopWidth",
      ]),
      table: pick(table, ["borderTopColor", "borderTopWidth"]),
      tableHeading: pick(tableHeading, ["backgroundColor", "color"]),
      tableCell: pick(tableCell, ["borderTopWidth", "color", "paddingRight", "paddingTop"]),
      media: pick(style(".content img"), ["boxShadow"]),
      searchTrigger: pick(style(".site-search-trigger"), ["fontFamily", "fontWeight", "minHeight"]),
      searchBackdrop: pick(style(".site-search-overlay__backdrop"), ["opacity"]),
      searchPanel: pick(style(".site-search-overlay__panel"), [
        "borderTopLeftRadius",
        "borderTopWidth",
        "boxShadow",
      ]),
      searchInput: pick(style(".site-search-overlay__input"), [
        "borderTopLeftRadius",
        "fontFamily",
      ]),
      title: {
        color: title.color,
        bulmaTitleColor: title.getPropertyValue("--bulma-title-color").trim(),
      },
      subtitle: {
        color: subtitle.color,
        bulmaSubtitleColor: subtitle.getPropertyValue("--bulma-subtitle-color").trim(),
      },
      warning: pick(warning, ["backgroundColor", "color"]),
    };
  });
}

function expectedStyles(scheme: Scheme) {
  const suffix = `-${scheme}` as const;
  const border =
    scheme === "light"
      ? THEME_E2E_VARIABLES["color-border-light"]
      : THEME_E2E_VARIABLES["color-border-dark"];
  const blockquoteBorder = rgb(THEME_E2E_VARIABLES["color-content-blockquote-border-light"]);

  return {
    backgroundPrimary: rgb(themeValue(`color-background-primary${suffix}`)),
    backgroundSecondary: rgb(themeValue(`color-background-secondary${suffix}`)),
    textPrimary: rgb(themeValue(`color-text-primary${suffix}`)),
    textSecondary: rgb(themeValue(`color-text-secondary${suffix}`)),
    link: rgb(themeValue(`color-content-link${suffix}`)),
    border,
    codeBackground: rgb(themeValue(`color-code-background${suffix}`)),
    blockquoteBackground: rgb(themeValue(`color-blockquote-background${suffix}`)),
    blockquoteBorder,
    tableBorder: rgb(themeValue(`color-table-border${suffix}`)),
    tableHeadingBackground: rgb(themeValue(`color-table-header-background${suffix}`)),
  };
}

function themeValue(name: keyof typeof THEME_E2E_VARIABLES): string {
  return THEME_E2E_VARIABLES[name];
}

function rgb(hex: string): string {
  const normalized = hex.replace("#", "");
  const red = Number.parseInt(normalized.slice(0, 2), 16);
  const green = Number.parseInt(normalized.slice(2, 4), 16);
  const blue = Number.parseInt(normalized.slice(4, 6), 16);

  return `rgb(${red}, ${green}, ${blue})`;
}

function lineHeightRatio(lineHeight: string, fontSize: string): number {
  return Number.parseFloat(lineHeight) / Number.parseFloat(fontSize);
}
