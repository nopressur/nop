// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";

// Centered content column with the document structure panel floating in the
// left gutter, hugging the content block. The content measure is font-relative
// (75ch); the panel lives only in the leftover left space at >=1280px.
const DESKTOP_WIDTHS = [1280, 1390, 1500, 1625, 1760, 1840];

const PANEL_GAP = 32;
const CONTENT_MEASURE_CH = 75;

async function measureCh(page) {
  return page.evaluate(() => {
    const reference = document.querySelector(".container.content-container") ?? document.body;
    const probe = document.createElement("span");
    probe.style.cssText =
      "position:absolute;visibility:hidden;white-space:nowrap;padding:0;margin:0;border:0;";
    probe.style.font = getComputedStyle(reference).font;
    probe.textContent = "0".repeat(100);
    document.body.appendChild(probe);
    const ch = probe.getBoundingClientRect().width / 100;
    probe.remove();
    return ch;
  });
}

test("document structure layout keeps font-measured content centered with panel hugging from the left", async ({
  page,
  harness,
}) => {
  for (const width of DESKTOP_WIDTHS) {
    await test.step(`viewport ${width}px`, async () => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
      await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

      const panel = page.locator("[data-site-doc-structure]");
      await expect(panel).toBeVisible();

      const ch = await measureCh(page);
      const layout = await page.evaluate(() => {
        const panelElement = document.querySelector("[data-site-doc-structure]");
        const content = document.querySelector(".container.content-container");
        const contentText = content?.querySelector(".content");
        const panelRect = panelElement?.getBoundingClientRect();
        const contentRect = content?.getBoundingClientRect();
        const panelPosition =
          panelElement instanceof HTMLElement ? getComputedStyle(panelElement).position : null;
        const rootFontSize = parseFloat(getComputedStyle(document.documentElement).fontSize);
        const contentTextStyle =
          contentText instanceof HTMLElement ? getComputedStyle(contentText) : null;

        return {
          viewportWidth: window.innerWidth,
          panelPosition,
          contentWidth: contentRect?.width ?? 0,
          contentCenter: (contentRect?.left ?? 0) + (contentRect?.width ?? 0) / 2,
          panelRight: panelRect?.right ?? 0,
          panelWidth: panelRect?.width ?? 0,
          panelTop: panelRect?.top ?? 0,
          contentLeft: contentRect?.left ?? 0,
          contentTop: contentRect?.top ?? 0,
          panelLeft: panelRect?.left ?? 0,
          rootFontSize,
          contentPaddingTop:
            (contentTextStyle ? parseFloat(contentTextStyle.borderTopWidth) : 0) +
            (contentTextStyle ? parseFloat(contentTextStyle.paddingTop) : 0),
          scrollWidth: document.documentElement.scrollWidth,
        };
      });

      expect(layout.viewportWidth).toBe(width);
      expect(layout.panelPosition).toBe("sticky");
      expect(layout.contentWidth).toBeCloseTo(CONTENT_MEASURE_CH * ch, 0);
      expect(Math.abs(layout.contentCenter - width / 2)).toBeLessThanOrEqual(2);
      expect(layout.panelRight).toBeLessThan(layout.contentLeft);
      expect(layout.contentLeft - layout.panelRight).toBeCloseTo(PANEL_GAP, 0);
      expect(layout.panelLeft).toBeGreaterThanOrEqual(-1);
      expect(layout.scrollWidth).toBeLessThanOrEqual(width + 1);

      // Fluid panel: fills the left gutter with symmetric margins, capped at 24rem.
      const gutter = (width - layout.contentWidth) / 2;
      const expectedPanelWidth = Math.min(gutter - 2 * PANEL_GAP, 24 * layout.rootFontSize);
      expect(layout.panelWidth).toBeCloseTo(expectedPanelWidth, 0);
      expect(layout.contentLeft - layout.panelLeft - layout.panelWidth).toBeCloseTo(PANEL_GAP, 0);
      expect(layout.panelLeft).toBeGreaterThanOrEqual(30);

      // Content-top alignment: panel box top matches the content padding-box top
      // (the top margin collapses outward, so only border plus padding count).
      expect(layout.panelTop - layout.contentTop).toBeCloseTo(layout.contentPaddingTop, 0);
    });
  }
});

test("below 1280px the side panel gives way to the narrow top bar", async ({ page, harness }) => {
  for (const width of [390, 1023, 1024, 1180, 1279]) {
    await test.step(`viewport ${width}px`, async () => {
      await page.setViewportSize({ width, height: 800 });
      await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
      await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();
      await expect(page.locator("[data-site-doc-structure]")).toBeHidden();
      await expect(page.locator("[data-site-topbar]")).toBeVisible();
    });
  }
});
