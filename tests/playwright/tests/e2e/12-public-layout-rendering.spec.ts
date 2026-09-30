// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login } from "../../utils/auth";
import { humanClick } from "../../utils/humanInput";

test("public layout renders disabled navbar and leading hero without empty container", async ({
  page,
  harness,
}) => {
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.noNavbarPath}`);
  await expect(page.getByRole("heading", { name: "Render No Navbar" })).toBeVisible();
  await expect(page.locator("[data-site-navbar]")).toHaveCount(0);

  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.heroFirstPath}`);
  await expect(page.getByRole("heading", { name: "After Render Hero" })).toBeVisible();
  await expect(page.locator("[data-site-navbar]")).toBeVisible();
  await expect(page.locator(".sc-hero-img")).toBeVisible();
  await expect(page.locator(".sc-hero-img__title")).toHaveText("Render Hero");
  await expect(page.locator(".sc-hero-img__subtitle")).toHaveText("Render subtitle");

  const layout = await page.evaluate(() => {
    const grid = document.querySelector(".doc-layout");
    const hero = document.querySelector(".sc-hero-img");
    const band = hero?.parentElement;
    const bandRect = band?.getBoundingClientRect();
    const heroRect = hero?.getBoundingClientRect();
    const wrapper = document.querySelector(".content-wrapper");

    return {
      heroBandClass: band?.classList.contains("site-doc-band") ?? false,
      bandDirectGridChild: !!band && !!grid && band.parentElement === grid,
      bandBeforeWrapper:
        !!band &&
        !!wrapper &&
        !!(band.compareDocumentPosition(wrapper) & Node.DOCUMENT_POSITION_FOLLOWING),
      heroFillsBand:
        !!bandRect &&
        !!heroRect &&
        Math.abs(heroRect.left - bandRect.left) <= 1 &&
        Math.abs(heroRect.width - bandRect.width) <= 1,
      viewportWidth: window.innerWidth,
      bandLeft: bandRect?.left ?? -1,
      bandWidth: bandRect?.width ?? -1,
      scrollWidth: document.documentElement.scrollWidth,
      wrapperPaddingTop: wrapper ? getComputedStyle(wrapper).paddingTop : null,
    };
  });

  expect(layout.heroBandClass).toBe(true);
  expect(layout.bandDirectGridChild).toBe(true);
  expect(layout.bandBeforeWrapper).toBe(true);
  expect(layout.heroFillsBand).toBe(true);
  expect(layout.bandLeft).toBeCloseTo(0, 0);
  expect(layout.bandWidth).toBeCloseTo(layout.viewportWidth, 0);
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.viewportWidth + 1);
  expect(layout.wrapperPaddingTop).toBe("0px");
});

test("hero band escapes the grid and inhibits the overlay aside", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1840, height: 900 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.heroWithHeadingsPath}`);
  await expect(page.getByRole("heading", { name: "After Render Hero" })).toBeVisible();
  await expect(page.locator(".sc-hero-img")).toBeVisible();

  const wide = await page.evaluate(() => {
    const hero = document.querySelector(".sc-hero-img");
    const heroRect = hero?.getBoundingClientRect();
    return {
      heroLeft: heroRect?.left ?? -1,
      heroWidth: heroRect?.width ?? -1,
      viewportWidth: window.innerWidth,
      scrollWidth: document.documentElement.scrollWidth,
    };
  });
  expect(wide.heroLeft).toBeCloseTo(0, 0);
  expect(wide.heroWidth).toBeCloseTo(wide.viewportWidth, 0);
  expect(wide.scrollWidth).toBeLessThanOrEqual(wide.viewportWidth + 1);
  await expect(page.locator("[data-site-doc-structure]")).toHaveCount(0);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole("heading", { name: "After Render Hero" })).toBeVisible();
  await expect(page.locator("[data-site-topbar-structure]")).toBeVisible();
  await page.locator("[data-site-topbar-structure]").click();
  await expect(page.locator("[data-site-structure-drawer]")).toBeVisible();
});

test("hero title and subtitle use configurable spacing without overlap", async ({
  page,
  harness,
}) => {
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.heroFirstPath}`);
  await expect(page.locator(".sc-hero-img__title")).toBeVisible();
  await expect(page.locator(".sc-hero-img__subtitle")).toBeVisible();

  const titleSubtitleLayout = await page.evaluate(() => {
    const title = document.querySelector(".sc-hero-img__title");
    const subtitle = document.querySelector(".sc-hero-img__subtitle");
    const titleRect = title?.getBoundingClientRect();
    const subtitleRect = subtitle?.getBoundingClientRect();

    return {
      subtitleMarginTop: subtitle ? getComputedStyle(subtitle).marginTop : null,
      subtitleStartsAfterTitle:
        !!titleRect && !!subtitleRect && subtitleRect.top >= titleRect.bottom,
    };
  });

  expect(titleSubtitleLayout).toEqual({
    subtitleMarginTop: harness.publicRenderFixtures.heroTitleSubtitleMargin,
    subtitleStartsAfterTitle: true,
  });
});

test("hero image height uses viewport-height values selected by viewport-width breakpoints", async ({
  page,
  harness,
}) => {
  const cases = [
    { width: 500, height: 900, ratio: 0.45 },
    { width: 800, height: 900, ratio: 0.45 },
    { width: 1100, height: 1000, ratio: 0.65 },
  ];

  for (const viewport of cases) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.heroFirstPath}`);
    await expect(page.locator(".sc-hero-img")).toBeVisible();

    const heroHeight = await page.locator(".sc-hero-img").evaluate((element) => {
      return element.getBoundingClientRect().height;
    });

    expect(heroHeight).toBeCloseTo(viewport.height * viewport.ratio, 0);
  }
});

test("public layout applies forced content width metadata", async ({ page, harness }) => {
  const cases = [
    {
      path: harness.publicRenderFixtures.autoWidthPath,
      heading: "Render Width Auto",
      fontMeasured: true,
    },
    {
      path: harness.publicRenderFixtures.wideWidthPath,
      heading: "Render Width Wide",
      fontMeasured: false,
    },
    {
      path: harness.publicRenderFixtures.narrowWidthPath,
      heading: "Render Width Narrow",
      fontMeasured: true,
    },
  ];

  for (const fixture of cases) {
    await page.goto(`${harness.baseUrl}${fixture.path}`);
    await expect(page.getByRole("heading", { name: fixture.heading })).toBeVisible();

    const measured = await page.locator(".container.content-container").first().evaluate((element) => {
      const probe = document.createElement("span");
      probe.style.cssText =
        "position:absolute;visibility:hidden;white-space:nowrap;padding:0;margin:0;border:0;";
      probe.style.font = getComputedStyle(element).font;
      probe.textContent = "0".repeat(100);
      document.body.appendChild(probe);
      const ch = probe.getBoundingClientRect().width / 100;
      probe.remove();
      return {
        maxWidth: getComputedStyle(element).maxWidth,
        width: element.getBoundingClientRect().width,
        ch,
      };
    });

    if (fixture.fontMeasured) {
      expect(measured.width).toBeCloseTo(75 * measured.ch, 0);
    } else {
      expect(measured.maxWidth).toBe("1152px");
    }
  }
});

test("public document structure renders as a themed non-overlapping desktop panel", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1840, height: 900 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const panel = page.locator("[data-site-doc-structure]");
  await expect(panel).toBeVisible();
  await expect(page.locator("[data-site-doc-structure-menu]")).toHaveCount(0);

  const links = page.locator("[data-site-doc-structure] [data-site-doc-structure-link]");
  await expect(links).toHaveText([
    "Alpha Section",
    "Alpha Detail",
    "Beta Section",
    "Beta Detail",
    "Gamma Section",
  ]);
  await expect(links.nth(0)).toHaveAttribute("href", "#alpha-section");
  await expect(links.nth(1)).toHaveAttribute("href", "#alpha-detail");

  const layout = await page.evaluate(() => {
    const panelElement = document.querySelector("[data-site-doc-structure]");
    const panelNav = document.querySelector(".site-doc-structure__nav");
    const content = document.querySelector(".container.content-container");
    const firstLink = document.querySelector("[data-site-doc-structure] [data-site-doc-structure-link]");
    const panelRect = panelElement?.getBoundingClientRect();
    const contentRect = content?.getBoundingClientRect();
    const panelStyle = panelNav ? getComputedStyle(panelNav) : null;
    const linkStyle = firstLink ? getComputedStyle(firstLink) : null;
    const panelPosition =
      panelElement instanceof HTMLElement
        ? getComputedStyle(panelElement).position
        : null;

    return {
      panelVisible: !!panelRect && panelRect.width > 0 && panelRect.height > 0,
      panelPosition,
      panelLeftOfContent:
        !!panelRect && !!contentRect && panelRect.right < contentRect.left,
      borderWidth: panelStyle?.borderTopWidth ?? null,
      borderRadius: panelStyle?.borderTopLeftRadius ?? null,
      boxShadow: panelStyle?.boxShadow ?? null,
      backgroundColor: panelStyle?.backgroundColor ?? null,
      linkColor: linkStyle?.color ?? null,
      panelColor: panelStyle?.color ?? null,
    };
  });

  expect(layout.panelVisible).toBe(true);
  expect(layout.panelPosition).toBe("sticky");
  expect(layout.panelLeftOfContent).toBe(true);
  expect(layout.borderWidth).toBe(harness.theme.variables["border-width-control"]);
  expect(layout.borderRadius).toBe(harness.theme.variables["size-control-radius"]);
  expect(layout.boxShadow).toBe("none");
  expect(layout.backgroundColor).toBe("rgb(255, 255, 255)");
  expect(layout.panelColor).toBe("rgb(65, 66, 67)");
  expect(layout.linkColor).not.toBe(layout.panelColor);

  await links.nth(2).click();
  await expect(page.locator("#beta-section")).toBeInViewport();
  await expect(links.nth(2)).toHaveAttribute("aria-current", "true");
});

test("public document structure ignores shortcode-generated heading-like content", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1840, height: 900 });
  await page.goto(
    `${harness.baseUrl}${harness.publicRenderFixtures.shortcodeDocumentStructurePath}`
  );
  await expect(
    page.getByRole("heading", { name: "Render Shortcode Structure Boundary" })
  ).toBeVisible();

  const shortcodeTitle = page.locator(".sc-hero-img__title", {
    hasText: "Shortcode Generated Heading",
  });
  await expect(shortcodeTitle).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Shortcode Generated Heading" })
  ).toBeVisible();

  // Hero pages inhibit the overlay aside even with multiple markdown headings.
  await expect(page.locator("[data-site-doc-structure]")).toHaveCount(0);

  await page.setViewportSize({ width: 390, height: 760 });
  await page.reload();
  await expect(shortcodeTitle).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Shortcode Generated Heading" })
  ).toBeVisible();

  // Markdown structure stays available through the narrow structure drawer,
  // still excluding shortcode-generated headings.
  await page.locator("[data-site-topbar-structure]").click();
  const drawerLinks = page.locator(
    "[data-site-structure-drawer] [data-site-doc-structure-link]"
  );
  await expect(drawerLinks).toHaveText(["Markdown Alpha", "Markdown Beta"]);
  await expect(drawerLinks.nth(0)).toHaveAttribute("href", "#markdown-alpha");
  await expect(drawerLinks.nth(1)).toHaveAttribute("href", "#markdown-beta");
  await expect(
    drawerLinks.filter({ hasText: "Shortcode Generated Heading" })
  ).toHaveCount(0);

  await page.locator("[data-site-topbar-menu]").click();
  await expect(page.locator("[data-site-menu-drawer]")).toBeVisible();
  await expect(page.locator("[data-site-doc-structure-menu]")).toHaveCount(0);
  await expect(
    page.locator("[data-site-menu-drawer] [data-site-doc-structure-link]")
  ).toHaveCount(0);
});

test("mid-width viewports use the narrow top bar instead of a side panel", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1180, height: 820 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await expect(page.locator("[data-site-doc-structure]")).toBeHidden();
  await expect(page.locator("[data-site-topbar]")).toBeVisible();
  await expect(page.locator("[data-site-topbar-structure]")).toBeVisible();
  await expect(page.locator("[data-site-topbar-menu]")).toBeVisible();
  await expect(page.locator("[data-site-navbar]")).toBeHidden();
  await expect(page.locator("[data-site-mobile-toggle]")).toHaveCount(0);
});

test("public layout switches between top bar and navbar at the 1280 boundary", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1279, height: 760 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();
  await expect(page.locator("[data-site-doc-structure]")).toBeHidden();
  await expect(page.locator("[data-site-topbar]")).toBeVisible();
  await expect(page.locator("[data-site-navbar]")).toBeHidden();
  await expect(page.locator("[data-site-mobile-toggle]")).toHaveCount(0);

  await page.setViewportSize({ width: 1280, height: 760 });
  await page.reload();
  await expect(page.locator("[data-site-doc-structure]")).toBeVisible();
  await expect(page.locator("[data-site-topbar]")).toBeHidden();
  await expect(page.locator("[data-site-navbar]")).toBeVisible();
  await expect(page.locator("[data-site-mobile-toggle]")).toHaveCount(0);
});

test("scroll-revealed navbar preserves content flow and ignores height-only resize", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1390, height: 760 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const navbar = page.locator("[data-site-navbar]");
  const contentDocumentTop = async () =>
    page.evaluate(() => {
      const content = document.querySelector(".content-wrapper");
      const rect = content?.getBoundingClientRect();
      return rect ? Math.round(window.scrollY + rect.top) : -1;
    });

  const initialContentTop = await contentDocumentTop();

  await page.mouse.wheel(0, 900);
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  await page.mouse.wheel(0, -180);
  await expect(navbar).toHaveAttribute("data-site-navbar-revealed", "true");
  expect(await contentDocumentTop()).toBe(initialContentTop);

  const heightResizeHandled = page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        window.addEventListener("resize", () => resolve(), { once: true });
      })
  );
  await page.setViewportSize({ width: 1390, height: 620 });
  await heightResizeHandled;
  await expect(navbar).toHaveAttribute("data-site-navbar-revealed", "true");
  expect(await contentDocumentTop()).toBe(initialContentTop);

  await page.mouse.wheel(0, 180);
  await expect(navbar).not.toHaveAttribute("data-site-navbar-revealed");
  expect(await contentDocumentTop()).toBe(initialContentTop);

  await page.mouse.wheel(0, -180);
  await expect(navbar).toHaveAttribute("data-site-navbar-revealed", "true");
  const widthResizeHandled = page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        window.addEventListener("resize", () => resolve(), { once: true });
      })
  );
  await page.setViewportSize({ width: 1600, height: 620 });
  await widthResizeHandled;
  await expect(navbar).not.toHaveAttribute("data-site-navbar-revealed");
});

test("public document structure handles no-H1 and no-structure pages", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1840, height: 900 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.multipleH1DocumentStructurePath}`);
  await expect(page.getByRole("heading", { name: "First Top", exact: true })).toBeVisible();
  await expect(page.locator("[data-site-doc-structure] [data-site-doc-structure-link]")).toHaveText([
    "First Top",
    "First Top Detail",
    "Second Top",
    "Second Top Detail",
  ]);

  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.noH1DocumentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Alpha Without H1" })).toBeVisible();
  await expect(page.locator("[data-site-doc-structure] [data-site-doc-structure-link]")).toHaveText([
    "Alpha Without H1",
    "Beta Without H1",
  ]);

  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.noRepeatedDocumentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Lone Title" })).toBeVisible();
  await expect(page.locator("[data-site-doc-structure]")).toHaveCount(0);
  await expect(page.locator("[data-site-doc-structure-menu]")).toHaveCount(0);
});

test("disabled-navbar pages keep desktop structure but omit navbar structure access", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1840, height: 900 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.disabledNavbarDocumentStructurePath}`);

  await expect(page.locator("[data-site-navbar]")).toHaveCount(0);
  await expect(page.locator("[data-site-doc-structure]")).toBeVisible();
  await expect(page.locator("[data-site-doc-structure-menu]")).toHaveCount(0);
});

test("disabled-floating-nav pages omit document structure on desktop and mobile", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 1180, height: 820 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.disabledFloatingNavDocumentStructurePath}`);

  await expect(page.locator("[data-site-navbar]")).toBeHidden();
  await expect(page.locator("[data-site-topbar]")).toBeVisible();
  await expect(page.locator("[data-site-topbar-structure]")).toHaveCount(0);
  await expect(page.locator("[data-site-doc-structure]")).toHaveCount(0);
  await expect(page.locator("[data-site-doc-structure-menu]")).toHaveCount(0);
  await expect(
    page.locator(".container.content-container").first()
  ).toHaveCSS("max-width", "1152px");

  await page.setViewportSize({ width: 1840, height: 900 });
  await page.reload();
  await expect(page.locator("[data-site-doc-structure]")).toHaveCount(0);
  await expect(page.locator("[data-site-doc-structure-menu]")).toHaveCount(0);

  await page.setViewportSize({ width: 390, height: 760 });
  await page.reload();
  await page.locator("[data-site-topbar-menu]").click();
  await expect(page.locator("[data-site-menu-drawer]")).toBeVisible();
  await expect(page.locator("[data-site-doc-structure-link]")).toHaveCount(0);
});

test("public page footer reload link is visible without signing in", async ({
  page,
  harness,
}) => {
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();
  await expect(page.locator("[data-site-page-footer]")).toBeVisible();
  await expect(page.locator("[data-site-asset-reload]")).toHaveText("reload");
  await expect(page.locator("[data-site-admin-version]")).toHaveCount(0);
});

test("public page footer reload link refetches assets then reloads the page", async ({
  page,
  harness,
  rng,
}) => {
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const footer = page.locator("[data-site-page-footer]");
  const reloadLink = page.locator("[data-site-asset-reload]");
  await expect(footer).toBeVisible();
  await expect(reloadLink).toHaveText("reload");

  const styles = await reloadLink.evaluate((el) => {
    const footerEl = el.closest("[data-site-page-footer]");
    const linkStyle = getComputedStyle(el);
    const footerStyle = footerEl ? getComputedStyle(footerEl) : null;
    return {
      linkColor: linkStyle.color,
      footerColor: footerStyle?.color ?? "",
      fontSize: linkStyle.fontSize,
      footerFontSize: footerStyle?.fontSize ?? "",
      decoration: linkStyle.textDecorationLine,
    };
  });
  expect(styles.linkColor).toBe(styles.footerColor);
  expect(styles.fontSize).toBe(styles.footerFontSize);
  expect(styles.decoration).toBe("none");

  const assetFetches: string[] = [];
  page.on("request", (request) => {
    const type = request.resourceType();
    if (type === "fetch" || type === "xhr") {
      assetFetches.push(request.url());
    }
  });

  const siteJsFetch = page.waitForRequest(
    (request) =>
      (request.resourceType() === "fetch" || request.resourceType() === "xhr") &&
      request.url().includes("/builtin/site.js"),
  );
  const reloaded = page.waitForEvent("load");
  await humanClick(reloadLink, rng);
  await siteJsFetch;
  await reloaded;

  expect(assetFetches.some((url) => url.includes("/builtin/site.js"))).toBe(true);
  expect(assetFetches.some((url) => url.includes("/builtin/bulma.min.css"))).toBe(true);
  await expect(page.locator("[data-site-asset-reload]")).toBeVisible();
});

test("admin version appears beside the public footer reload link", async ({
  page,
  harness,
  rng,
}) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: harness.publicRenderFixtures.documentStructurePath,
    expectedPath: harness.publicRenderFixtures.documentStructurePath,
  });

  const footer = page.locator("[data-site-page-footer]");
  await expect(footer).toBeVisible();
  await expect(footer.locator("[data-site-admin-version]")).toContainText("NoPressure");
  await expect(footer.locator("[data-site-asset-reload]")).toHaveText("reload");
});


