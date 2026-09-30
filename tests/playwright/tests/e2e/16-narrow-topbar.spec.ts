// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login } from "../../utils/auth";
import { humanClick, humanType } from "../../utils/humanInput";

const NARROW_WIDTHS = [390, 768, 1024, 1180];

test("narrow top bar shows three controls with conditional structure button", async ({
  page,
  harness,
}) => {
  for (const width of NARROW_WIDTHS) {
    await test.step(`viewport ${width}px`, async () => {
      await page.setViewportSize({ width, height: 844 });
      await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
      await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

      const topbar = page.locator("[data-site-topbar]");
      await expect(topbar).toBeVisible();
      await expect(page.locator("[data-site-topbar-structure]")).toBeVisible();
      await expect(page.locator("[data-site-topbar-menu]")).toBeVisible();
      await expect(page.locator("[data-site-topbar-title]")).toHaveText("NoPressure Playwright");

      const titleBox = await page.locator("[data-site-topbar-title]").boundingBox();
      expect(titleBox).not.toBeNull();
      if (titleBox) {
        expect(Math.abs(titleBox.x + titleBox.width / 2 - width / 2)).toBeLessThanOrEqual(4);
      }

      await expect(page.locator("[data-site-navbar]")).toBeHidden();
      await expect(page.locator("[data-site-mobile-toggle]")).toHaveCount(0);
      await expect(page.locator("[data-site-doc-structure]")).toBeHidden();
    });
  }
});

test("narrow top bar omits structure button without page structure", async ({ page, harness }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.noRepeatedDocumentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Lone Title" })).toBeVisible();

  await expect(page.locator("[data-site-topbar]")).toBeVisible();
  await expect(page.locator("[data-site-topbar-structure]")).toHaveCount(0);
  await expect(page.locator("[data-site-topbar-menu]")).toBeVisible();
});

test("structure drawer slides in from the left and link jumps dismiss it", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const drawer = page.locator("[data-site-structure-drawer]");
  await expect(drawer).toBeHidden();

  await page.locator("[data-site-topbar-structure]").click();
  await expect(drawer).toBeVisible();

  await expect
    .poll(() =>
      page.evaluate(() => {
        const drawerElement = document.querySelector("[data-site-structure-drawer]");
        return drawerElement?.getBoundingClientRect().left ?? -1;
      })
    )
    .toBeLessThanOrEqual(1);
  const geometry = await page.evaluate(() => {
    const links = Array.from(
      document.querySelectorAll("[data-site-structure-drawer] [data-site-doc-structure-link]")
    );
    const lefts = links.map((link) => link.getBoundingClientRect().left);
    return {
      linkCount: links.length,
      aligned: lefts.every((left) => Math.abs(left - lefts[0]) < 1),
    };
  });
  expect(geometry.linkCount).toBeGreaterThan(0);
  expect(geometry.aligned).toBe(true);

  const back = page.locator("[data-site-structure-drawer] [data-site-drawer-back]");
  await expect(back).toHaveAttribute("aria-label", "Back to page");

  await page.locator('[data-site-structure-drawer] [href="#beta-section"]').click();
  await expect(drawer).toBeHidden();
  await expect(page.locator("#beta-section")).toBeInViewport();

  // The jumped-to heading must clear the floating top bar, not hide under it.
  const visibility = await page.evaluate(() => {
    const heading = document.querySelector("#beta-section");
    const topbar = document.querySelector("[data-site-topbar]");
    return {
      headingTop: heading?.getBoundingClientRect().top ?? -1,
      topbarBottom: topbar?.getBoundingClientRect().bottom ?? -1,
    };
  });
  expect(visibility.headingTop).toBeGreaterThanOrEqual(visibility.topbarBottom - 2);
});

test("structure drawer has left margin with centered title and right chevron", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-structure]").click();
  const drawer = page.locator("[data-site-structure-drawer]");
  await expect(drawer).toBeVisible();

  const geometry = await page.evaluate(() => {
    const drawerElement = document.querySelector("[data-site-structure-drawer]");
    const drawerRect = drawerElement?.getBoundingClientRect();
    const back = drawerElement?.querySelector("[data-site-drawer-back]");
    const backRect = back?.getBoundingClientRect();
    const title = drawerElement?.querySelector("[data-site-drawer-topbar] .site-topbar__title");
    const titleRect = title?.getBoundingClientRect();
    const firstLink = drawerElement?.querySelector("[data-site-doc-structure-link]");
    const firstLinkRect = firstLink?.getBoundingClientRect();
    return {
      drawerLeft: drawerRect?.left ?? 0,
      drawerCenter: (drawerRect?.left ?? 0) + (drawerRect?.width ?? 0) / 2,
      titleCenter: (titleRect?.left ?? 0) + (titleRect?.width ?? 0) / 2,
      backLeft: backRect?.left ?? 0,
      firstLinkLeft: firstLinkRect?.left ?? 0,
    };
  });

  expect(geometry.firstLinkLeft - geometry.drawerLeft).toBeGreaterThanOrEqual(16);
  expect(Math.abs(geometry.titleCenter - geometry.drawerCenter)).toBeLessThanOrEqual(4);
  expect(geometry.backLeft).toBeGreaterThan(geometry.drawerCenter);
});

test("menu drawer centers its title with side-by-side action buttons", async ({
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
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-menu]").click();
  const drawer = page.locator("[data-site-menu-drawer]");
  await expect(drawer).toBeVisible();

  const geometry = await page.evaluate(() => {
    const drawerElement = document.querySelector("[data-site-menu-drawer]");
    const drawerRect = drawerElement?.getBoundingClientRect();
    const title = drawerElement?.querySelector("[data-site-drawer-topbar] .site-topbar__title");
    const titleRect = title?.getBoundingClientRect();
    const edit = drawerElement?.querySelector("[data-site-edit-button] a");
    const admin = drawerElement?.querySelector("[data-site-admin-button] a");
    const editRect = edit?.getBoundingClientRect();
    const adminRect = admin?.getBoundingClientRect();
    const profile = drawerElement?.querySelector("[data-site-drawer-profile]");
    const profileStyle = profile ? getComputedStyle(profile) : null;
    const nav = drawerElement?.querySelector("[data-site-drawer-nav]");
    const navStyle = nav ? getComputedStyle(nav) : null;
    const profileToggle = drawerElement?.querySelector(
      "[data-site-drawer-profile] [data-site-expander-toggle]"
    );
    const toggleRect = profileToggle?.getBoundingClientRect();
    const chevron = drawerElement?.querySelector(
      "[data-site-drawer-profile] [data-site-expander-chevron]"
    );
    const chevronRect = chevron?.getBoundingClientRect();
    return {
      drawerCenter: (drawerRect?.left ?? 0) + (drawerRect?.width ?? 0) / 2,
      titleCenter: (titleRect?.left ?? 0) + (titleRect?.width ?? 0) / 2,
      editTop: editRect?.top ?? 0,
      editRight: editRect?.right ?? 0,
      editFontSize: edit ? parseFloat(getComputedStyle(edit).fontSize) : 0,
      adminTop: adminRect?.top ?? 0,
      adminLeft: adminRect?.left ?? 0,
      profileDivider: profileStyle ? parseFloat(profileStyle.borderTopWidth) : 0,
      navDivider: navStyle ? parseFloat(navStyle.borderTopWidth) : 0,
      toggleCenter: (toggleRect?.left ?? 0) + (toggleRect?.width ?? 0) / 2,
      chevronLeft: chevronRect?.left ?? 0,
    };
  });

  expect(Math.abs(geometry.titleCenter - geometry.drawerCenter)).toBeLessThanOrEqual(4);
  expect(Math.abs(geometry.editTop - geometry.adminTop)).toBeLessThanOrEqual(2);
  expect(geometry.adminLeft).toBeGreaterThanOrEqual(geometry.editRight - 1);
  expect(geometry.editFontSize).toBeGreaterThanOrEqual(14);
  expect(geometry.chevronLeft).toBeGreaterThan(geometry.toggleCenter);
  expect(geometry.profileDivider).toBeGreaterThanOrEqual(1);
  expect(geometry.navDivider).toBeGreaterThanOrEqual(1);
});

test("menu drawer sub-menus expand below their parent item", async ({ page, harness, rng }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-menu]").click();
  const expander = page.locator("[data-site-menu-drawer] [data-site-expander]").first();
  await humanClick(expander.locator("[data-site-expander-toggle]"), rng);
  await expect(expander).toHaveClass(/is-open/);

  const geometry = await page.evaluate(() => {
    const item = document.querySelector("[data-site-menu-drawer] [data-site-expander]");
    const toggle = item?.querySelector("[data-site-expander-toggle]");
    const panel = item?.querySelector("[data-site-expander-panel]");
    return {
      toggleBottom: toggle?.getBoundingClientRect().bottom ?? 0,
      panelTop: panel?.getBoundingClientRect().top ?? 0,
    };
  });
  expect(geometry.panelTop).toBeGreaterThanOrEqual(geometry.toggleBottom - 2);
});

test("profile chevron shares geometry with navigation submenu chevrons", async ({
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
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-menu]").click();
  await expect(page.locator("[data-site-menu-drawer]")).toBeVisible();

  const geometry = await page.evaluate(() => {
    const drawerElement = document.querySelector("[data-site-menu-drawer]");
    const drawerRect = drawerElement?.getBoundingClientRect();
    const profileToggle = drawerElement?.querySelector(
      "[data-site-drawer-profile] [data-site-expander-toggle]"
    );
    const profileToggleRect = profileToggle?.getBoundingClientRect();
    const profileChevron = drawerElement?.querySelector(
      "[data-site-drawer-profile] [data-site-expander-chevron]"
    );
    const profileChevronRect = profileChevron?.getBoundingClientRect();
    const navToggle = drawerElement?.querySelector(
      "[data-site-drawer-nav] [data-site-expander-toggle]"
    );
    const navToggleRect = navToggle?.getBoundingClientRect();
    const navChevron = drawerElement?.querySelector(
      "[data-site-drawer-nav] [data-site-expander-chevron]"
    );
    const navChevronRect = navChevron?.getBoundingClientRect();
    return {
      drawerRight: drawerRect?.right ?? 0,
      profileToggleCenterY: (profileToggleRect?.top ?? 0) + (profileToggleRect?.height ?? 0) / 2,
      profileChevronCenterX:
        (profileChevronRect?.left ?? 0) + (profileChevronRect?.width ?? 0) / 2,
      profileChevronCenterY:
        (profileChevronRect?.top ?? 0) + (profileChevronRect?.height ?? 0) / 2,
      profileChevronRight: profileChevronRect?.right ?? 0,
      navToggleCenterY: (navToggleRect?.top ?? 0) + (navToggleRect?.height ?? 0) / 2,
      navChevronCenterX: (navChevronRect?.left ?? 0) + (navChevronRect?.width ?? 0) / 2,
      navChevronCenterY: (navChevronRect?.top ?? 0) + (navChevronRect?.height ?? 0) / 2,
      navChevronRight: navChevronRect?.right ?? 0,
    };
  });

  // Same right inset from the drawer edge.
  expect(
    Math.abs(
      geometry.drawerRight - geometry.profileChevronRight - (geometry.drawerRight - geometry.navChevronRight)
    )
  ).toBeLessThanOrEqual(2);
  // Each chevron vertically centered in its own toggle row.
  expect(Math.abs(geometry.profileChevronCenterY - geometry.profileToggleCenterY)).toBeLessThanOrEqual(2);
  expect(Math.abs(geometry.navChevronCenterY - geometry.navToggleCenterY)).toBeLessThanOrEqual(2);
  // Same chevron size and horizontal center relative to inset.
  expect(Math.abs(geometry.profileChevronCenterX - geometry.navChevronCenterX)).toBeLessThanOrEqual(2);
});

test("edge swipes open the drawers when touch is supported", async ({ page, harness }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const touchSupported = await page.evaluate(
    () => typeof Touch !== "undefined" && typeof TouchEvent !== "undefined"
  );
  test.skip(!touchSupported, "touch events unavailable");

  await page.evaluate(() => {
    const stroke = (type: string, x: number, y: number, active: boolean) => {
      const touch = new Touch({ identifier: 7, target: document.body, clientX: x, clientY: y });
      document.dispatchEvent(
        new TouchEvent(type, {
          touches: active ? [touch] : [],
          changedTouches: [touch],
          bubbles: true,
          cancelable: true,
        })
      );
    };
    stroke("touchstart", 20, 400, true);
    stroke("touchend", 160, 400, false);
  });
  await expect(page.locator("[data-site-structure-drawer]")).toBeVisible();
  await page.locator("[data-site-structure-drawer] [data-site-drawer-back]").click();
  await expect(page.locator("[data-site-structure-drawer]")).toBeHidden();

  await page.evaluate(() => {
    const stroke = (type: string, x: number, y: number, active: boolean) => {
      const touch = new Touch({ identifier: 9, target: document.body, clientX: x, clientY: y });
      document.dispatchEvent(
        new TouchEvent(type, {
          touches: active ? [touch] : [],
          changedTouches: [touch],
          bubbles: true,
          cancelable: true,
        })
      );
    };
    stroke("touchstart", 370, 400, true);
    stroke("touchend", 230, 400, false);
  });
  await expect(page.locator("[data-site-menu-drawer]")).toBeVisible();
});

test("opposite swipes close the drawers when touch is supported", async ({ page, harness }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const touchSupported = await page.evaluate(
    () => typeof Touch !== "undefined" && typeof TouchEvent !== "undefined"
  );
  test.skip(!touchSupported, "touch events unavailable");

  const stroke = (identifier: number, fromX: number, toX: number) =>
    page.evaluate(
      ({ identifier, fromX, toX }) => {
        const stroke = (type: string, x: number, active: boolean) => {
          const touch = new Touch({ identifier, target: document.body, clientX: x, clientY: 400 });
          document.dispatchEvent(
            new TouchEvent(type, {
              touches: active ? [touch] : [],
              changedTouches: [touch],
              bubbles: true,
              cancelable: true,
            })
          );
        };
        stroke("touchstart", fromX, true);
        stroke("touchend", toX, false);
      },
      { identifier, fromX, toX }
    );

  // Structure drawer: a further open-direction swipe keeps it open ...
  await page.locator("[data-site-topbar-structure]").click();
  await expect(page.locator("[data-site-structure-drawer]")).toBeVisible();
  await stroke(21, 20, 160);
  await expect(page.locator("[data-site-structure-drawer]")).toBeVisible();

  // ... while the opposite swipe closes it.
  await stroke(22, 160, 20);
  await expect(page.locator("[data-site-structure-drawer]")).toBeHidden();

  // Menu drawer: the opposite swipe closes it too.
  await page.locator("[data-site-topbar-menu]").click();
  await expect(page.locator("[data-site-menu-drawer]")).toBeVisible();
  await stroke(23, 230, 370);
  await expect(page.locator("[data-site-menu-drawer]")).toBeHidden();
});

test("opening swipes are suppressed on horizontal overflow but closes still work", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const touchSupported = await page.evaluate(
    () => typeof Touch !== "undefined" && typeof TouchEvent !== "undefined"
  );
  test.skip(!touchSupported, "touch events unavailable");

  // Swipe starting inside the scroller dispatches on the scroller so the
  // handler sees it as the gesture origin.
  const strokeOn = (target: string, identifier: number, fromX: number, toX: number) =>
    page.evaluate(
      ({ target, identifier, fromX, toX }) => {
        const origin =
          target === "document" ? document : document.querySelector(target);
        if (!(origin instanceof EventTarget)) {
          return;
        }
        const inner = document.querySelector("#swipe-overflow-inner");
        const stroke = (type: string, x: number, active: boolean) => {
          const touch = new Touch({
            identifier,
            target: inner instanceof Element ? inner : document.body,
            clientX: x,
            clientY: 400,
          });
          origin.dispatchEvent(
            new TouchEvent(type, {
              touches: active ? [touch] : [],
              changedTouches: [touch],
              bubbles: true,
              cancelable: true,
            })
          );
        };
        stroke("touchstart", fromX, true);
        stroke("touchend", toX, false);
      },
      { target, identifier, fromX, toX }
    );

  // Page-level overflow suppresses opening ...
  await page.evaluate(() => {
    const wide = document.createElement("div");
    wide.id = "swipe-overflow-page";
    wide.style.width = "200vw";
    wide.style.height = "10px";
    document.body.appendChild(wide);
  });
  await strokeOn("document", 31, 20, 160);
  await expect(page.locator("[data-site-structure-drawer]")).toBeHidden();

  // ... but closing still works.
  await page.locator("[data-site-topbar-structure]").click();
  await expect(page.locator("[data-site-structure-drawer]")).toBeVisible();
  await strokeOn("document", 32, 160, 20);
  await expect(page.locator("[data-site-structure-drawer]")).toBeHidden();
  await page.evaluate(() => {
    document.querySelector("#swipe-overflow-page")?.remove();
  });

  // Nested horizontal scroller suppresses opening from inside it ...
  await page.evaluate(() => {
    const scroller = document.createElement("div");
    scroller.id = "swipe-overflow-scroller";
    scroller.style.overflowX = "auto";
    scroller.style.width = "100%";
    const inner = document.createElement("div");
    inner.id = "swipe-overflow-inner";
    inner.style.width = "200vw";
    inner.style.height = "10px";
    scroller.appendChild(inner);
    document.body.appendChild(scroller);
  });
  await strokeOn("#swipe-overflow-scroller", 33, 20, 160);
  await expect(page.locator("[data-site-structure-drawer]")).toBeHidden();

  // ... while swipes starting outside it still open.
  await strokeOn("document", 34, 20, 160);
  await expect(page.locator("[data-site-structure-drawer]")).toBeVisible();
});

test("narrow titles link home like the desktop brand", async ({ page, harness }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const fixture = `${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`;
  const home = `${harness.baseUrl}/`;
  await page.goto(fixture);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await expect(page.locator("[data-site-topbar-title]")).toHaveAttribute("href", "/");
  await page.locator("[data-site-topbar-title]").click();
  await expect(page).toHaveURL(home);

  await page.goto(fixture);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();
  await page.locator("[data-site-topbar-structure]").click();
  const structureTitle = page.locator(
    "[data-site-structure-drawer] [data-site-drawer-topbar] .site-topbar__title"
  );
  await expect(structureTitle).toHaveAttribute("href", "/");
  await structureTitle.click();
  await expect(page).toHaveURL(home);

  await page.goto(fixture);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();
  await page.locator("[data-site-topbar-menu]").click();
  const menuTitle = page.locator(
    "[data-site-menu-drawer] [data-site-drawer-topbar] .site-topbar__title"
  );
  await expect(menuTitle).toHaveAttribute("href", "/");
  await menuTitle.click();
  await expect(page).toHaveURL(home);
});

test("menu drawer slides in from the right with search field first", async ({
  page,
  harness,
  rng,
}) => {
  await page.route("**/api/search**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        { id: "0000000000000001", alias: "docs/search-alpha", title: "Search Alpha" },
      ]),
    });
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const drawer = page.locator("[data-site-menu-drawer]");
  await expect(drawer).toBeHidden();

  await page.locator("[data-site-topbar-menu]").click();
  await expect(drawer).toBeVisible();

  await expect
    .poll(() =>
      page.evaluate(() => {
        const rect = document
          .querySelector("[data-site-menu-drawer]")
          ?.getBoundingClientRect();
        return Math.abs((rect?.right ?? -1) - window.innerWidth);
      })
    )
    .toBeLessThanOrEqual(1);

  const rows = page.locator("[data-site-menu-drawer] > *");
  await expect(rows.nth(0)).toHaveAttribute("data-site-drawer-topbar", "");
  await expect(rows.nth(1)).toHaveAttribute("data-site-drawer-search", "");
  await expect(page.locator("[data-site-menu-drawer] [data-site-drawer-nav]")).toBeVisible();
  await expect(
    page.locator("[data-site-menu-drawer] [data-site-drawer-nav] a[href]").first()
  ).toBeVisible();

  const input = page.locator("[data-site-menu-drawer] [data-site-drawer-search-input]");
  await humanType(input, "search", rng);
  await expect(page.locator("[data-site-menu-drawer] .site-search-result")).toHaveCount(1);

  await page.locator("[data-site-menu-drawer] [data-site-drawer-back]").click();
  await expect(drawer).toBeHidden();
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();
});

test("menu drawer orders controls for logged-in admin", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: harness.publicRenderFixtures.documentStructurePath,
    expectedPath: harness.publicRenderFixtures.documentStructurePath,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-menu]").click();
  const drawer = page.locator("[data-site-menu-drawer]");
  await expect(drawer).toBeVisible();

  const order = await page.evaluate(() => {
    const markers = [
      "[data-site-drawer-search]",
      "[data-site-edit-button]",
      "[data-site-admin-button]",
      "[data-site-drawer-profile]",
      "[data-site-drawer-nav]",
    ];
    const positions = markers.map((selector) => {
      const element = document.querySelector(`[data-site-menu-drawer] ${selector}`);
      if (!element) {
        return -1;
      }
      return Array.from(document.querySelectorAll("[data-site-menu-drawer] *")).indexOf(element);
    });
    return positions;
  });
  expect(order.every((position) => position >= 0)).toBe(true);
  const sorted = [...order].sort((a, b) => a - b);
  expect(order).toEqual(sorted);
});

test("expander chevrons point right collapsed and down open", async ({
  page,
  harness,
  rng,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-menu]").click();
  const expander = page.locator("[data-site-menu-drawer] [data-site-expander]").first();
  const toggle = expander.locator("[data-site-expander-toggle]");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(expander).not.toHaveClass(/is-open/);

  await humanClick(toggle, rng);
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(expander).toHaveClass(/is-open/);

  await humanClick(toggle, rng);
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(expander).not.toHaveClass(/is-open/);
});

test("tall menu drawer scrolls internally without shifting content", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 390, height: 360 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-menu]").click();
  const drawer = page.locator("[data-site-menu-drawer]");
  await expect(drawer).toBeVisible();

  await page.evaluate(() => {
    const nav = document.querySelector("[data-site-menu-drawer] [data-site-drawer-nav]");
    if (!nav) {
      return;
    }
    for (let index = 1; index <= 12; index += 1) {
      const link = document.createElement("a");
      link.className = "navbar-item";
      link.href = "#";
      link.textContent = `Overflow Menu ${index}`;
      nav.appendChild(link);
    }
  });

  const contentTop = await page.evaluate(() => {
    const content = document.querySelector(".content-wrapper");
    const rect = content?.getBoundingClientRect();
    return rect ? Math.round(window.scrollY + rect.top) : -1;
  });

  await expect
    .poll(() =>
      drawer.evaluate((element) => {
        const style = getComputedStyle(element);
        return {
          overflowY: style.overflowY,
          scrollable: element.scrollHeight > element.clientHeight,
        };
      })
    )
    .toEqual({ overflowY: "auto", scrollable: true });

  expect(
    await page.evaluate(() => {
      const content = document.querySelector(".content-wrapper");
      const rect = content?.getBoundingClientRect();
      return rect ? Math.round(window.scrollY + rect.top) : -1;
    })
  ).toBe(contentTop);

  await page.locator("[data-site-menu-drawer] [data-site-drawer-back]").click();
  await expect(drawer).toBeHidden();
});

test("structure drawer top and bottom entries jump to the absolute page ends", async ({
  page,
  harness,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  await page.locator("[data-site-topbar-structure]").click();
  const drawer = page.locator("[data-site-structure-drawer]");
  await expect(drawer).toBeVisible();

  const top = drawer.locator("[data-site-doc-structure-top]");
  await expect(top).toHaveText("Render Document Structure");
  await expect(top).toHaveAttribute("aria-label", "Go to top");
  await expect(drawer.locator("[data-site-doc-structure-bottom]")).toHaveAttribute(
    "aria-label",
    "Go to bottom"
  );

  await drawer.locator("[data-site-doc-structure-bottom]").click();
  await expect(drawer).toBeHidden();
  await expect
    .poll(() =>
      page.evaluate(
        () => window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2
      )
    )
    .toBe(true);

  await page.locator("[data-site-topbar-structure]").click();
  await expect(drawer).toBeVisible();
  await drawer.locator("[data-site-doc-structure-top]").click();
  await expect(drawer).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
});

test("structure top entry without a page title is icon-only", async ({ page, harness }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.noH1DocumentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Alpha Without H1" })).toBeVisible();

  await page.evaluate(() => window.scrollTo(0, 500));
  await page.locator("[data-site-topbar-structure]").click();
  const drawer = page.locator("[data-site-structure-drawer]");
  await expect(drawer).toBeVisible();

  const top = drawer.locator("[data-site-doc-structure-top]");
  await expect(top).toHaveAttribute("aria-label", "Go to top");
  await expect(top.locator("svg")).toHaveCount(1);

  await top.click();
  await expect(drawer).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
});

test("desktop structure panel jumps to the absolute page ends", async ({ page, harness }) => {
  await page.setViewportSize({ width: 1400, height: 900 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

  const panel = page.locator("[data-site-doc-structure]");
  await expect(panel).toBeVisible();
  await expect(panel.locator("[data-site-doc-structure-top]")).toHaveText(
    "Render Document Structure"
  );

  await panel.locator("[data-site-doc-structure-bottom]").click();
  await expect
    .poll(() =>
      page.evaluate(
        () => window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2
      )
    )
    .toBe(true);

  await panel.locator("[data-site-doc-structure-top]").click();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
});

test("desktop structure panel eases to a heading instead of jumping", async ({ page, harness }) => {
  await page.setViewportSize({ width: 1400, height: 900 });
  await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
  await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();
  await expect(page.locator("[data-site-doc-structure]")).toBeVisible();

  const distinctPositions = async () => {
    const samples = await page.evaluate(() => {
      const recorded = (window as Window & { __scrollSamples?: number[] }).__scrollSamples ?? [];
      return recorded;
    });
    const positions: number[] = [];
    for (const sample of samples) {
      const previous = positions[positions.length - 1];
      if (previous === undefined || Math.abs(sample - previous) > 1) {
        positions.push(sample);
      }
    }
    return positions;
  };

  const armSampler = () =>
    page.evaluate(() => {
      const recorded: number[] = [];
      const host = window as Window & {
        __scrollSamples?: number[];
        __stopScrollSamples?: () => void;
      };
      host.__stopScrollSamples?.();
      recorded.push(window.scrollY);
      const onScroll = () => {
        recorded.push(window.scrollY);
      };
      window.addEventListener("scroll", onScroll);
      host.__scrollSamples = recorded;
      host.__stopScrollSamples = () => window.removeEventListener("scroll", onScroll);
    });

  await armSampler();
  await page.locator('[data-site-doc-structure] [href="#beta-section"]').click();
  await expect.poll(() => page.evaluate(() => window.location.hash)).toBe("");
  await expect
    .poll(() =>
      page.evaluate(() => {
        const heading = document.querySelector("#beta-section");
        return heading ? Math.abs(heading.getBoundingClientRect().top) : 999;
      })
    )
    .toBeLessThan(3);

  const downward = await distinctPositions();
  expect(downward.length).toBeGreaterThan(4);
  expect(downward[1]).toBeLessThan(downward[downward.length - 1] - 40);
  expect(downward[downward.length - 1]).toBeGreaterThan(80);

  await armSampler();
  await page.locator("[data-site-doc-structure] [data-site-doc-structure-top]").click();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  const upward = await distinctPositions();
  expect(upward.length).toBeGreaterThan(4);
  expect(upward[upward.length - 1]).toBeLessThan(2);
  expect(upward[1]).toBeGreaterThan(upward[upward.length - 1] + 40);
  expect(upward[1]).toBeLessThan(upward[0]);
});

test("narrow layout has no horizontal overflow and instant drawers under reduced motion", async ({
  page,
  harness,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  for (const width of [390, 768, 1024, 1180]) {
    await test.step(`viewport ${width}px`, async () => {
      await page.setViewportSize({ width, height: 844 });
      await page.goto(`${harness.baseUrl}${harness.publicRenderFixtures.documentStructurePath}`);
      await expect(page.getByRole("heading", { name: "Render Document Structure" })).toBeVisible();

      const overflow = await page.evaluate(() => document.documentElement.scrollWidth);
      expect(overflow).toBeLessThanOrEqual(width + 1);

      await page.locator("[data-site-topbar-menu]").click();
      const drawer = page.locator("[data-site-menu-drawer]");
      await expect(drawer).toBeVisible();
      const duration = await drawer.evaluate(
        (element) => getComputedStyle(element).transitionDuration
      );
      expect(duration === "0s" || duration === "0s, 0s").toBe(true);
      await page.locator("[data-site-menu-drawer] [data-site-drawer-back]").click();
      await expect(drawer).toBeHidden();
    });
  }
});
