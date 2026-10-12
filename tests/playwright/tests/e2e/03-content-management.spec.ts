// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { test, expect } from "../../fixtures";
import { login } from "../../utils/auth";
import { humanClick, humanClearAndType, humanType } from "../../utils/humanInput";

test("content management list, edit, and upload", async ({ page, harness, rng }) => {
  test.setTimeout(120000);
  if (process.env.PW_TRACE_WS === "1") {
    page.on("websocket", (socket) => {
      if (!socket.url().includes("/admin/ws")) {
        return;
      }
      socket.on("framesent", (frame) => {
        const size =
          typeof frame.payload === "string" ? frame.payload.length : frame.payload.byteLength;
        console.log(`[pw-ws] sent ${size} bytes`);
      });
      socket.on("framereceived", (frame) => {
        const size =
          typeof frame.payload === "string" ? frame.payload.length : frame.payload.byteLength;
        console.log(`[pw-ws] recv ${size} bytes`);
      });
      socket.on("close", () => {
        console.log("[pw-ws] closed");
      });
      socket.on("socketerror", (error) => {
        console.log("[pw-ws] error", error);
      });
    });
  }
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  const ensureDetailsOpen = async () => {
    const expandButton = page.getByRole("button", { name: "Expand details" });
    if (await expandButton.isVisible()) {
      await humanClick(expandButton, rng);
    }
  };

  const dismissNotifications = async () => {
    const closeButtons = page.getByRole("button", { name: "Dismiss notification" });
    let count = await closeButtons.count();
    while (count > 0) {
      const button = closeButtons.first();
      if (await button.isVisible()) {
        await humanClick(button, rng);
      }
      count = await closeButtons.count();
    }
  };
  const openContentByTitle = async (title: string) => {
    const mobileButton = page.getByRole("button", { name: title }).first();
    if (await mobileButton.isVisible()) {
      await humanClick(mobileButton, rng);
      return;
    }
    const row = page.locator("tbody tr", { hasText: title }).first();
    await expect(row).toBeVisible();
    await humanClick(row, rng);
  };

  const tagsToCreate = [
    { id: "docs", name: "Docs" },
    { id: "ui", name: "UI" },
    { id: "featured", name: "Featured" },
  ];

  await humanClick(page.getByRole("link", { name: "Tags" }), rng);
  await expect(page.getByRole("heading", { name: "Tag Catalog" })).toBeVisible();

  for (const tag of tagsToCreate) {
    await humanClick(page.getByRole("button", { name: "New Tag" }), rng);
    await expect(page.getByRole("heading", { name: "Create Tag" })).toBeVisible();
    await humanType(page.locator("#tag-id"), tag.id, rng);
    await humanType(page.locator("#tag-name"), tag.name, rng);
    await humanClick(page.getByRole("button", { name: "Save" }), rng);
    await page.waitForURL(/\/admin\/tags/);
  }

  await humanClick(page.getByRole("link", { name: "Content" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "New Page" }), rng);
  await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();

  await ensureDetailsOpen();
  await humanType(page.locator("#content-alias"), "Docs/UI-Test", rng);
  await humanType(page.locator("#content-title"), "UI Test", rng);
  // Three short tags fit in a single row, so the selector collapses with no filter field.
  await expect(page.locator("#content-tags")).toHaveCount(0);
  await humanClick(page.getByRole("button", { name: "Add docs" }), rng);
  await expect(page.locator('[aria-label="Remove docs"]')).toBeVisible();
  await humanClick(page.getByRole("button", { name: "Add ui" }), rng);
  await expect(page.locator('[aria-label="Remove ui"]')).toBeVisible();

  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );
  await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    editor.setValue("# UI Test\n\nHello from Playwright. See https://example.com/docs\n");
    editor.clearSelection();
  });

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/pages\/edit/);

  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
  await ensureDetailsOpen();
  const pageAlias = "docs/ui-test";
  const pageAliasRegex = pageAlias.replace("/", "\\/");
  await expect(page.locator("#content-alias")).toHaveValue(pageAlias);
  await expect(page.getByRole("link", { name: "View Page" })).toHaveAttribute(
    "href",
    `/${pageAlias}`
  );
  await expect(page.locator("#content-title")).toHaveValue("UI Test");
  await expect(page.getByText("Navbar state")).toHaveCount(0);
  await expect(page.getByText("Content width")).toHaveCount(0);

  const navbarToggle = page.getByRole("button", { name: "Navbar Enabled" });
  const widthToggle = page.getByRole("button", { name: "Auto Width" });
  const autoLinksToggle = page.getByRole("button", { name: "Auto Links" });
  await expect(navbarToggle).toBeVisible();
  await expect(widthToggle).toBeVisible();
  await expect(autoLinksToggle).toBeVisible();

  const navbarBox = await navbarToggle.boundingBox();
  const widthBox = await widthToggle.boundingBox();
  expect(navbarBox).not.toBeNull();
  expect(widthBox).not.toBeNull();
  expect(Math.abs((navbarBox?.y ?? 0) - (widthBox?.y ?? 0))).toBeLessThan(4);
  expect(widthBox?.x ?? 0).toBeGreaterThan(navbarBox?.x ?? 0);

  const navbarToggleStyle = await navbarToggle.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      backgroundColor: style.backgroundColor,
      borderColor: style.borderTopColor,
      color: style.color,
    };
  });
  expect(navbarToggleStyle.backgroundColor).toBe("rgba(0, 0, 0, 0)");
  expect(navbarToggleStyle.borderColor).toBe(navbarToggleStyle.color);

  await humanClick(page.getByRole("button", { name: "Add featured" }), rng);
  await expect(page.locator('[aria-label="Remove featured"]')).toBeVisible();
  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await expect(page.getByText("Content saved").last()).toBeVisible();

  await humanClearAndType(page.locator("#content-title"), "UI Test Updated", rng);
  const saveShortcut = process.platform === "darwin" ? "Meta+S" : "Control+S";
  await page.keyboard.press(saveShortcut);
  await expect(page.getByText("Content saved").last()).toBeVisible();
  await dismissNotifications();

  const publicUrl = new URL(`/${pageAlias}`, harness.baseUrl).toString();
  await page.goto(publicUrl);
  await expect(page.getByRole("heading", { name: "UI Test" })).toBeVisible();
  await expect(page).toHaveTitle("UI Test Updated");
  await expect(
    page.getByRole("link", { name: "https://example.com/docs", exact: true })
  ).toHaveAttribute("href", "https://example.com/docs");

  const editLink = page.getByRole("link", { name: "Edit" });
  await expect(editLink).toBeVisible();
  await expect(editLink).toHaveAttribute("href", /\/admin\/pages\/edit\//);

  await Promise.all([page.waitForURL(/\/admin\/pages\/edit\//), humanClick(editLink, rng)]);
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "Upload", exact: true }), rng);
  const editorOverlay = page.getByRole("dialog", { name: "Drop files to upload" });
  await expect(editorOverlay).toBeVisible();
  await editorOverlay.locator('input[type="file"]').setInputFiles({
    name: "example.png",
    mimeType: "image/png",
    buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  });

  const editorUploadModal = page.getByRole("dialog", { name: "Upload Asset" });
  await expect(editorUploadModal).toBeVisible();
  await expect(editorUploadModal.locator('input[id^="upload-alias-"]').first()).toHaveValue(
    new RegExp(`${pageAliasRegex}\\/example\\.png`)
  );
  await expect(editorUploadModal.getByRole("button", { name: "Save all" })).toHaveCount(0);

  await humanClick(editorUploadModal.getByRole("button", { name: "Save" }), rng);
  await expect(page.getByText("Upload complete").last()).toBeVisible();
  await dismissNotifications();

  const updatedContent = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(updatedContent).toContain(`/${pageAlias}/example.png`);
  expect(updatedContent).toContain("![");

  await humanClick(page.getByRole("button", { name: "Upload", exact: true }), rng);
  const largeOverlay = page.getByRole("dialog", { name: "Drop files to upload" });
  await expect(largeOverlay).toBeVisible();
  const largeBuffer = Buffer.alloc(3 * 1024 * 1024, 0x61);
  await largeOverlay.locator('input[type="file"]').setInputFiles({
    name: "large.pdf",
    mimeType: "application/pdf",
    buffer: largeBuffer,
  });

  const largeUploadModal = page.getByRole("dialog", { name: "Upload Asset" });
  await expect(largeUploadModal).toBeVisible();
  const largeAliasInput = largeUploadModal.locator('input[id^="upload-alias-"]').first();
  await humanClearAndType(largeAliasInput, "", rng);
  await humanClick(largeUploadModal.getByRole("button", { name: "Save" }), rng);
  await expect(page.getByText("Upload complete").last()).toBeVisible({ timeout: 120000 });
  await dismissNotifications();

  const contentAfterLargeUpload = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(contentAfterLargeUpload).toContain("/id/");
  expect(contentAfterLargeUpload).toMatch(/\[large\]\(\/id\//);

  const idMatch = contentAfterLargeUpload.match(/\/id\/([0-9a-f]{16})/);
  expect(idMatch).not.toBeNull();
  const largeResponse = await page.request.get(`${harness.baseUrl}/id/${idMatch?.[1]}`);
  expect(largeResponse.ok()).toBe(true);
  const largeBody = await largeResponse.body();
  expect(largeBody.length).toBe(largeBuffer.length);
  expect(largeBody[0]).toBe(0x61);
  expect(largeBody[largeBody.length - 1]).toBe(0x61);

  await page.evaluate(() => {
    const dropTarget = document.querySelector(".ace_editor")?.parentElement;
    if (!dropTarget) {
      throw new Error("Drop target not found");
    }
    const dataTransfer = new DataTransfer();
    const pdfFile = new File(
      [new Uint8Array([0x25, 0x50, 0x44, 0x46])],
      "manual.pdf",
      { type: "application/pdf" }
    );
    const imageFile = new File(
      [new Uint8Array([0x89, 0x50, 0x4e, 0x47])],
      "diagram.png",
      { type: "image/png" }
    );
    const videoFile = new File(
      [new Uint8Array([0x00, 0x00, 0x00, 0x18])],
      "clip.mp4",
      { type: "video/mp4" }
    );
    dataTransfer.items.add(pdfFile);
    dataTransfer.items.add(imageFile);
    dataTransfer.items.add(videoFile);
    const event = new DragEvent("dragenter", { dataTransfer, bubbles: true });
    dropTarget.dispatchEvent(event);
  });
  await expect(page.getByText("Drop files to upload")).toBeVisible();

  await page.evaluate(() => {
    const dropTarget = document.querySelector(".ace_editor")?.parentElement;
    if (!dropTarget) {
      throw new Error("Drop target not found");
    }
    const dataTransfer = new DataTransfer();
    const pdfFile = new File(
      [new Uint8Array([0x25, 0x50, 0x44, 0x46])],
      "manual.pdf",
      { type: "application/pdf" }
    );
    const imageFile = new File(
      [new Uint8Array([0x89, 0x50, 0x4e, 0x47])],
      "diagram.png",
      { type: "image/png" }
    );
    const videoFile = new File(
      [new Uint8Array([0x00, 0x00, 0x00, 0x18])],
      "clip.mp4",
      { type: "video/mp4" }
    );
    dataTransfer.items.add(pdfFile);
    dataTransfer.items.add(imageFile);
    dataTransfer.items.add(videoFile);
    const event = new DragEvent("drop", { dataTransfer, bubbles: true });
    dropTarget.dispatchEvent(event);
  });
  await expect(page.getByText("Drop files to upload")).toHaveCount(0);
  const multiUploadModal = page.getByRole("dialog", { name: "Upload Asset" });
  await expect(multiUploadModal).toBeVisible();
  await expect(multiUploadModal.locator('input[id^="upload-alias-"]')).toHaveCount(3);
  await expect(multiUploadModal.getByRole("button", { name: "Save all" })).toHaveCount(2);

  await humanClick(multiUploadModal.getByRole("button", { name: "Save all" }).first(), rng);
  await expect(page.getByText("Upload complete").last()).toBeVisible();
  await dismissNotifications();

  await page.waitForFunction((expectedAlias: string) => {
    const ace = (window as Window & { ace?: any }).ace;
    if (!ace) {
      return false;
    }
    const editor = ace.edit(document.querySelector(".ace_editor"));
    const value = editor.getValue();
    const hasImage = value.includes(`/${expectedAlias}/diagram.png`);
    const hasPdf = value.includes(`/${expectedAlias}/manual.pdf`) || /\/id\//.test(value);
    const hasVideo = value.includes(`/${expectedAlias}/clip.mp4`);
    return hasImage && hasPdf && hasVideo;
  }, pageAlias);

  const updatedContentAfterDrop = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(updatedContentAfterDrop).toMatch(
    new RegExp(`/(?:${pageAliasRegex}\\/manual\\.pdf|id/)`)
  );
  expect(updatedContentAfterDrop).toContain(`/${pageAlias}/diagram.png`);
  expect(updatedContentAfterDrop).toContain(`/${pageAlias}/clip.mp4`);

  const insertShortcut = process.platform === "darwin" ? "Meta+Shift+I" : "Control+Shift+I";
  await page.keyboard.press(insertShortcut);
  const insertModal = page.getByRole("dialog", { name: "Insert content" });
  await expect(insertModal).toBeVisible();
  await expect(insertModal.locator("#insert-tag")).toHaveValue("docs");

  await humanClearAndType(insertModal.locator("#insert-search"), "UI Test", rng);
  await expect(insertModal.getByRole("option", { name: /UI Test/ })).toBeVisible();
  await humanClick(insertModal.getByRole("option", { name: /UI Test/ }), rng);
  await expect(insertModal.getByRole("radio", { name: "Link" })).toBeDisabled();
  await page.keyboard.press("Enter");
  await expect(insertModal).toHaveCount(0);

  const contentAfterInsert = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(contentAfterInsert).toContain("[UI Test Updated](/docs/ui-test)");

  const insertedLinkMarkdown = "[UI Test Updated](/docs/ui-test)";
  await page.evaluate((target: string) => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    const value = editor.getValue();
    const start = value.lastIndexOf(target);
    if (start === -1) {
      throw new Error("Inserted markdown link was not found");
    }
    const aceDocument = editor.session.getDocument();
    editor.selection.setRange({
      start: aceDocument.indexToPosition(start, 0),
      end: aceDocument.indexToPosition(start + target.length, 0),
    });
  }, insertedLinkMarkdown);
  await humanClick(page.getByRole("button", { name: "Link-Card" }), rng);
  const contentAfterLinkCard = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(contentAfterLinkCard).not.toContain(insertedLinkMarkdown);
  expect(contentAfterLinkCard).toContain(
    '((link-card title="UI Test Updated" link="/docs/ui-test" noblank))'
  );

  await page.keyboard.press(insertShortcut);
  const imageInsertModal = page.getByRole("dialog", { name: "Insert content" });
  await expect(imageInsertModal).toBeVisible();
  await imageInsertModal.locator("#insert-tag").selectOption("");
  await humanClearAndType(imageInsertModal.locator("#insert-search"), "diagram", rng);
  const diagramOption = imageInsertModal.getByRole("option", { name: /diagram/ });
  await expect(diagramOption).toBeVisible();
  await humanClick(diagramOption, rng);
  await expect(diagramOption).toHaveAttribute("aria-selected", "true");
  const modeToggle = imageInsertModal.getByRole("radiogroup", { name: "Insertion type" });
  await modeToggle.focus();
  await expect(imageInsertModal.getByRole("radio", { name: "Image" })).toHaveAttribute(
    "aria-checked",
    "true"
  );
  await page.keyboard.press("ArrowRight");
  await expect(imageInsertModal.getByRole("radio", { name: "Hero" })).toHaveAttribute(
    "aria-checked",
    "true"
  );
  await page.keyboard.press("ArrowRight");
  await expect(imageInsertModal.getByRole("radio", { name: "Link" })).toHaveAttribute(
    "aria-checked",
    "true"
  );
  await page.keyboard.press("ArrowLeft");
  await expect(imageInsertModal.getByRole("radio", { name: "Hero" })).toHaveAttribute(
    "aria-checked",
    "true"
  );
  await page.keyboard.press("ArrowLeft");
  await expect(imageInsertModal.getByRole("radio", { name: "Image" })).toHaveAttribute(
    "aria-checked",
    "true"
  );
  const imageInsertButton = imageInsertModal.getByRole("button", { name: "Insert" });
  await expect(imageInsertButton).toBeEnabled();
  await humanClick(imageInsertButton, rng);
  await expect(imageInsertModal).toHaveCount(0);

  const contentAfterImageInsert = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(contentAfterImageInsert).toContain(`![diagram](/${pageAlias}/diagram.png)`);

  await page.keyboard.press(insertShortcut);
  const videoInsertModal = page.getByRole("dialog", { name: "Insert content" });
  await expect(videoInsertModal).toBeVisible();
  await videoInsertModal.locator("#insert-tag").selectOption("");
  await humanClearAndType(videoInsertModal.locator("#insert-search"), "clip", rng);
  const clipOption = videoInsertModal.getByRole("option", { name: /clip/ });
  await expect(clipOption).toBeVisible();
  await humanClick(clipOption, rng);
  await expect(clipOption).toHaveAttribute("aria-selected", "true");
  await expect(videoInsertModal.getByRole("radio", { name: "Video" })).toHaveAttribute(
    "aria-checked",
    "true"
  );
  const videoInsertButton = videoInsertModal.getByRole("button", { name: "Insert" });
  await expect(videoInsertButton).toBeEnabled();
  await humanClick(videoInsertButton, rng);
  await expect(videoInsertModal).toHaveCount(0);

  const contentAfterVideoInsert = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(contentAfterVideoInsert).toContain(`((video src="/${pageAlias}/clip.mp4"))`);

  const menuButton = page.getByRole("button", { name: "Menu" });
  if (await menuButton.isVisible()) {
    await humanClick(menuButton, rng);
  }
  await humanClick(page.getByRole("link", { name: "Content" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  await humanClick(page.getByRole("button", { name: "Upload", exact: true }), rng);
  const rejectOverlay = page.getByRole("dialog", { name: "Drop files to upload" });
  await expect(rejectOverlay).toBeVisible();
  await rejectOverlay.locator('input[type="file"]').setInputFiles({
    name: "noextension",
    mimeType: "application/octet-stream",
    buffer: Buffer.from([0x00]),
  });
  const rejectModal = page.getByRole("dialog", { name: "Upload Content" });
  await expect(rejectModal).toBeVisible();
  await expect(rejectModal.getByText("Filename must include an extension")).toBeVisible();
  await expect(rejectModal.locator('input[id^="upload-alias-"]')).toHaveCount(0);
  await humanClick(rejectModal.getByRole("button", { name: "Remove" }), rng);

  const tagFilter = page.locator("#content-tags-filter");
  await humanClick(tagFilter, rng);
  await humanClick(page.getByRole("button", { name: "featured", exact: true }), rng);
  await humanClick(tagFilter, rng);
  await dismissNotifications();
  await humanClick(page.getByRole("button", { name: "Upload", exact: true }), rng);
  const listOverlay = page.getByRole("dialog", { name: "Drop files to upload" });
  await expect(listOverlay).toBeVisible();
  await listOverlay.locator('input[type="file"]').setInputFiles([
    {
      name: "list-upload.pdf",
      mimeType: "application/pdf",
      buffer: Buffer.from([0x25, 0x50, 0x44, 0x46]),
    },
  ]);

  const listUploadModal = page.getByRole("dialog", { name: "Upload Content" });
  await expect(listUploadModal).toBeVisible();
  await expect(listUploadModal.locator('button[id^="upload-tags-"]').first()).toHaveText(
    /featured/
  );
  await humanClick(listUploadModal.getByRole("button", { name: "Save" }), rng);
  await expect(page.getByText("Upload complete").last()).toBeVisible();
  await dismissNotifications();

  await dismissNotifications();
  await humanClick(page.getByRole("button", { name: "Upload", exact: true }), rng);
  const listOverlayMulti = page.getByRole("dialog", { name: "Drop files to upload" });
  await expect(listOverlayMulti).toBeVisible();
  await listOverlayMulti.locator('input[type="file"]').setInputFiles([
    {
      name: "list-multi-one.png",
      mimeType: "image/png",
      buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47]),
    },
    {
      name: "list-multi-two.pdf",
      mimeType: "application/pdf",
      buffer: Buffer.from([0x25, 0x50, 0x44, 0x46]),
    },
  ]);

  const listMultiModal = page.getByRole("dialog", { name: "Upload Content" });
  await expect(listMultiModal).toBeVisible();
  await expect(listMultiModal.locator('input[id^="upload-alias-"]')).toHaveCount(2);
  await expect(listMultiModal.locator('button[id^="upload-tags-"]').first()).toHaveText(
    /featured/
  );
  await expect(listMultiModal.getByRole("button", { name: "Save all" })).toHaveCount(2);
  await humanClick(listMultiModal.getByRole("button", { name: "Save all" }).first(), rng);
  await expect(page.getByText("Upload complete").last()).toBeVisible();
  await dismissNotifications();

  await humanClearAndType(
    page.getByPlaceholder("Search"),
    "list-upload",
    rng
  );
  await expect(page.locator("tr", { hasText: "list-upload" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search"),
    "list-multi-one",
    rng
  );
  await expect(page.locator("tr", { hasText: "list-multi-one" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search"),
    "list-multi-two",
    rng
  );
  await expect(page.locator("tr", { hasText: "list-multi-two" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search"),
    "UI Test",
    rng
  );
  await openContentByTitle("UI Test");
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();

  const navMenuButtonAfterEdit = page.getByRole("button", { name: "Menu" });
  if (await navMenuButtonAfterEdit.isVisible()) {
    await humanClick(navMenuButtonAfterEdit, rng);
  }
  await humanClick(page.getByRole("link", { name: "Content" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();
  await expect(page.locator("#content-tags-filter")).toContainText("featured");

  await openContentByTitle("UI Test");
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
  await humanClearAndType(page.locator("#content-title"), "UI Test Draft", rng);

  await page.keyboard.press("Escape");
  const discardModal = page.getByRole("dialog", { name: "Unsaved changes" });
  await expect(discardModal).toBeVisible();
  await humanClick(discardModal.getByRole("button", { name: "Discard" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();
  await expect(page.getByPlaceholder("Search")).toHaveValue("UI Test");
});

test("large markdown editor load and save roundtrip", async ({ page, harness, rng }) => {
  test.setTimeout(120000);

  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  const ensureDetailsOpen = async () => {
    const expandButton = page.getByRole("button", { name: "Expand details" });
    if (await expandButton.isVisible()) {
      await humanClick(expandButton, rng);
    }
  };

  const largeMarkdown =
    "# Large Stream\r\n\r\n" +
    "a".repeat(72 * 1024) +
    "\r\nEuro boundary: €\r\nFinal CRLF line.\r\n";

  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();
  await humanClick(page.getByRole("button", { name: "New Page" }), rng);
  await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();
  await ensureDetailsOpen();
  await humanType(page.locator("#content-alias"), "Docs/Large-Stream", rng);
  await humanType(page.locator("#content-title"), "Large Stream", rng);
  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );
  await page.evaluate((content) => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    editor.setValue(content);
    editor.clearSelection();
  }, largeMarkdown);

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/pages\/edit\//);
  const editUrl = page.url();

  await page.goto(editUrl);
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );
  const loadedMarkdown = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(loadedMarkdown).toBe(largeMarkdown);

  const updatedMarkdown = `${largeMarkdown}\r\nSaved again.\r\n`;
  await page.evaluate((content) => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    editor.setValue(content);
    editor.clearSelection();
  }, updatedMarkdown);
  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await expect(page.getByText("Content saved").last()).toBeVisible({ timeout: 10000 });

  await page.goto(editUrl);
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );
  const reloadedMarkdown = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(reloadedMarkdown).toBe(updatedMarkdown);
});

test("content editor unsaved changes modal", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  const ensureDetailsOpen = async () => {
    const expandButton = page.getByRole("button", { name: "Expand details" });
    if (await expandButton.isVisible()) {
      await humanClick(expandButton, rng);
    }
  };

  await humanClick(page.getByRole("button", { name: "New Page" }), rng);
  await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();

  await ensureDetailsOpen();
  await humanType(page.locator("#content-alias"), "unsaved-close-test", rng);
  await humanType(page.locator("#content-title"), "Unsaved Close Test", rng);

  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );
  await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    editor.setValue("# Unsaved Close Test\n\nContent.\n");
    editor.clearSelection();
  });

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/pages\/edit/);

  await expect(page.getByRole("button", { name: "Close" })).toBeVisible();

  await humanClearAndType(page.locator("#content-title"), "Unsaved Close Test Draft", rng);
  await expect(page.getByRole("button", { name: "Cancel" })).toBeVisible();

  await page.keyboard.press("Escape");
  const escapeModal = page.getByRole("dialog", { name: "Unsaved changes" });
  await expect(escapeModal).toBeVisible();
  await humanClick(escapeModal.getByRole("button", { name: "Cancel" }), rng);
  await expect(escapeModal).toHaveCount(0);

  await humanClick(page.getByRole("button", { name: "Cancel" }), rng);
  const discardModal = page.getByRole("dialog", { name: "Unsaved changes" });
  await expect(discardModal).toBeVisible();
  await humanClick(discardModal.getByRole("button", { name: "Discard" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search"),
    "Unsaved Close Test",
    rng
  );
  const originalRow = page.locator("tr", { hasText: "Unsaved Close Test" }).first();
  await expect(originalRow).toBeVisible();
  await humanClick(originalRow, rng);
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
  await expect(page.locator("#content-title")).toHaveValue("Unsaved Close Test");

  await humanClearAndType(page.locator("#content-title"), "Unsaved Close Test Saved", rng);
  await humanClick(page.getByRole("button", { name: "Cancel" }), rng);
  const saveModal = page.getByRole("dialog", { name: "Unsaved changes" });
  await expect(saveModal).toBeVisible();
  await humanClick(saveModal.getByRole("button", { name: "Save" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search"),
    "Unsaved Close Test Saved",
    rng
  );
  await expect(page.locator("tr", { hasText: "Unsaved Close Test Saved" })).toBeVisible();
});

test("content upload versions repeated font aliases", async ({ page, harness, rng }) => {
  test.setTimeout(90000);
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  const uploadFont = async (buffer: Buffer, expectPendingVersion: boolean) => {
    await humanClick(page.getByRole("button", { name: "Upload", exact: true }), rng);
    const overlay = page.getByRole("dialog", { name: "Drop files to upload" });
    await expect(overlay).toBeVisible();
    await overlay.locator('input[type="file"]').setInputFiles({
      name: "Brand Font.woff2",
      mimeType: "font/woff2",
      buffer,
    });

    const uploadModal = page.getByRole("dialog", { name: "Upload Content" });
    await expect(uploadModal).toBeVisible();
    await expect(uploadModal.locator('input[id^="upload-alias-"]').first()).toHaveValue(
      "fonts/brand-font.woff2",
    );
    if (expectPendingVersion) {
      await expect(uploadModal.getByText(/New version of .* v2/)).toBeVisible();
    }
    await humanClick(uploadModal.getByRole("button", { name: "Save" }), rng);
    await expect(uploadModal).toBeHidden();
  };

  await uploadFont(Buffer.from("font-v1"), false);
  await uploadFont(Buffer.from("font-v2"), true);

  const fontResponse = await page.request.get(`${harness.baseUrl}/fonts/brand-font.woff2`);
  expect(fontResponse.ok()).toBeTruthy();
  expect(await fontResponse.body()).toEqual(Buffer.from("font-v2"));
});

test("content list sorting", async ({ page, harness, rng }) => {
  test.setTimeout(120000);

  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();

  const ensureDetailsOpen = async () => {
    const expandButton = page.getByRole("button", { name: "Expand details" });
    if (await expandButton.isVisible()) {
      await humanClick(expandButton, rng);
    }
  };

  const goToContentList = async () => {
    await humanClick(page.getByRole("link", { name: "Content" }), rng);
    await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();
  };

  const createTag = async (id: string, name: string) => {
    await humanClick(page.getByRole("link", { name: "Tags" }), rng);
    await expect(page.getByRole("heading", { name: "Tag Catalog" })).toBeVisible();
    await humanClick(page.getByRole("button", { name: "New Tag" }), rng);
    await expect(page.getByRole("heading", { name: "Create Tag" })).toBeVisible();
    await humanType(page.locator("#tag-id"), id, rng);
    await humanType(page.locator("#tag-name"), name, rng);
    await humanClick(page.getByRole("button", { name: "Save" }), rng);
    await page.waitForURL(/\/admin\/tags/);
  };

  const createPage = async (options: {
    alias: string;
    title: string;
    tags: string[];
    navTitle?: string;
  }): Promise<string> => {
    await goToContentList();
    await humanClick(page.getByRole("button", { name: "New Page" }), rng);
    await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();
    await ensureDetailsOpen();
    await humanClearAndType(page.locator("#content-alias"), options.alias, rng);
    await humanClearAndType(page.locator("#content-title"), options.title, rng);
    for (const tag of options.tags) {
      await humanClick(page.getByRole("button", { name: `Add ${tag}` }), rng);
    }
    if (options.navTitle) {
      await humanClearAndType(page.locator("#content-nav-title"), options.navTitle, rng);
    }
    await page.waitForFunction(
      () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
    );
    await page.evaluate((content) => {
      const ace = (window as Window & { ace?: any }).ace;
      const editor = ace.edit(document.querySelector(".ace_editor"));
      editor.setValue(content);
      editor.clearSelection();
    }, `# ${options.title}\n\nPlaywright sort test.\n`);
    await humanClick(page.getByRole("button", { name: "Save" }), rng);
    await page.waitForURL(/\/admin\/pages\/edit/);
    const id = new URL(page.url()).pathname.split("/").pop() ?? "";
    await expect(id).not.toBe("");
    await goToContentList();
    return id;
  };

  const uploadBinary = async (options: {
    filename: string;
    mimeType: string;
    buffer: Buffer;
    alias: string;
    title: string;
    tags: string[];
  }) => {
    await goToContentList();
    await humanClick(page.getByRole("button", { name: "Upload", exact: true }), rng);
    const overlay = page.getByRole("dialog", { name: "Drop files to upload" });
    await expect(overlay).toBeVisible();
    await overlay.locator('input[type="file"]').setInputFiles({
      name: options.filename,
      mimeType: options.mimeType,
      buffer: options.buffer,
    });

    const uploadModal = page.getByRole("dialog", { name: "Upload Content" });
    await expect(uploadModal).toBeVisible();
    const aliasInput = uploadModal.locator('input[id^="upload-alias-"]').first();
    const titleInput = uploadModal.locator('input[id^="upload-title-"]').first();
    await humanClearAndType(aliasInput, options.alias, rng);
    await humanClearAndType(titleInput, options.title, rng);
    if (options.tags.length > 0) {
      const tagsButton = uploadModal.locator('button[id^="upload-tags-"]').first();
      await humanClick(tagsButton, rng);
      for (const tag of options.tags) {
        await humanClick(uploadModal.getByRole("button", { name: tag, exact: true }), rng);
      }
      await humanClick(tagsButton, rng);
    }
    await humanClick(uploadModal.getByRole("button", { name: "Save" }), rng);
    await expect(page.getByText("Upload complete").last()).toBeVisible();
  };

  await createTag("alpha", "Alpha");
  await createTag("beta", "Beta");
  await createTag("gamma", "Gamma");

  await createPage({
    alias: "sort-base-alpha",
    title: "Sort Base Alpha",
    tags: ["alpha"],
    navTitle: "Nav Alpha",
  });
  await createPage({
    alias: "sort-base-beta",
    title: "Sort Base Beta",
    tags: ["beta"],
    navTitle: "Nav Beta",
  });
  await createPage({
    alias: "sort-base-empty",
    title: "Sort Base Empty",
    tags: [],
  });

  const tieIds: Record<string, string> = {};
  tieIds["sort-tie-a"] = await createPage({
    alias: "sort-tie-a",
    title: "Sort Tie",
    tags: ["alpha"],
  });
  tieIds["sort-tie-b"] = await createPage({
    alias: "sort-tie-b",
    title: "Sort Tie",
    tags: ["alpha"],
  });

  await uploadBinary({
    filename: "sort-image.png",
    mimeType: "image/png",
    buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    alias: "images/sort-base-image",
    title: "Sort Base Image",
    tags: ["gamma"],
  });

  await goToContentList();
  const searchInput = page.locator('input[placeholder="Search"]');
  await humanClearAndType(searchInput, "Sort Base", rng);

  const table = page.locator("table");
  const rows = table.locator("tbody tr");
  await expect(rows).toHaveCount(6);

  const normalizeText = (value: string) => value.replace(/\s+/g, " ").trim();
  const getColumnTexts = async (index: number) => {
    const count = await rows.count();
    const values = [];
    for (let i = 0; i < count; i += 1) {
      const text = await rows.nth(i).locator("td").nth(index).innerText();
      values.push(normalizeText(text));
    }
    return values;
  };
  const getRowData = async () => {
    const count = await rows.count();
    const values = [];
    for (let i = 0; i < count; i += 1) {
      const cells = rows.nth(i).locator("td");
      const title = normalizeText(await cells.nth(0).innerText());
      const alias = normalizeText(await cells.nth(1).innerText());
      values.push({ title, alias });
    }
    return values;
  };

  const expectColumnOrder = async (index: number, expected: string[]) => {
    await expect.poll(() => getColumnTexts(index)).toEqual(expected);
  };

  const sortAndExpect = async (
    header: string,
    index: number,
    asc: string[],
    desc: string[],
  ) => {
    const button = table.locator("thead").getByRole("button", { name: header });
    await humanClick(button, rng);
    await expectColumnOrder(index, asc);
    await humanClick(button, rng);
    await expectColumnOrder(index, desc);
  };

  await expectColumnOrder(0, [
    "Sort Base Alpha",
    "Sort Base Beta",
    "Sort Base Empty",
    "Sort Base Image",
    "Sort Tie",
    "Sort Tie",
  ]);

  const titleButton = table.locator("thead").getByRole("button", { name: "Title" });
  await humanClick(titleButton, rng);
  await expectColumnOrder(0, [
    "Sort Tie",
    "Sort Tie",
    "Sort Base Image",
    "Sort Base Empty",
    "Sort Base Beta",
    "Sort Base Alpha",
  ]);

  await sortAndExpect(
    "Alias",
    1,
    [
      "/images/sort-base-image",
      "/sort-base-alpha",
      "/sort-base-beta",
      "/sort-base-empty",
      "/sort-tie-a",
      "/sort-tie-b",
    ],
    [
      "/sort-tie-b",
      "/sort-tie-a",
      "/sort-base-empty",
      "/sort-base-beta",
      "/sort-base-alpha",
      "/images/sort-base-image",
    ],
  );

  await sortAndExpect(
    "Tags",
    2,
    ["alpha", "alpha", "alpha", "beta", "gamma", "—"],
    ["gamma", "beta", "alpha", "alpha", "alpha", "—"],
  );

  const typeButton = table.locator("thead").getByRole("button", { name: "Type" });
  await humanClick(typeButton, rng);
  await expect.poll(async () => {
    const values = await getColumnTexts(3);
    return { first: values[0], last: values[values.length - 1] };
  }).toEqual({ first: "image/png", last: "text/markdown" });

  await humanClick(typeButton, rng);
  await expect.poll(async () => {
    const values = await getColumnTexts(3);
    return { first: values[0], last: values[values.length - 1] };
  }).toEqual({ first: "text/markdown", last: "image/png" });

  await sortAndExpect(
    "Nav",
    4,
    ["Nav Alpha", "Nav Beta", "—", "—", "—", "—"],
    ["Nav Beta", "Nav Alpha", "—", "—", "—", "—"],
  );

  await humanClearAndType(searchInput, "Sort Tie", rng);
  await expect(rows).toHaveCount(5);
  await humanClick(titleButton, rng);

  const expectedTieAliases = Object.entries(tieIds)
    .sort((left, right) => left[1].localeCompare(right[1]))
    .map(([alias]) => alias);
  await expect
    .poll(async () => {
      const rowsData = await getRowData();
      return rowsData
        .filter((row) => row.title === "Sort Tie")
        .map((row) => row.alias.replace(/^\//, ""));
    })
    .toEqual(expectedTieAliases);
});

test("content editor tag selector filters and ranks by usage", async ({
  page,
  harness,
  rng,
}) => {
  test.setTimeout(180000);

  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/tags",
    expectedPath: "/admin/tags",
  });
  await expect(page.getByRole("heading", { name: "Tag Catalog" })).toBeVisible();

  // "docs" is referenced by two seeded contents, so registering it yields usage 2.
  // The long filler names overflow a single row and force the expanded selector.
  const tagsToCreate = [
    { id: "docs", name: "Docs" },
    { id: "zz", name: "Zz" },
    ...Array.from({ length: 12 }, (_, index) => ({
      id: `filler-tag-number-${String(index + 1).padStart(2, "0")}`,
      name: `Filler ${index + 1}`,
    })),
  ];
  for (const tag of tagsToCreate) {
    await humanClick(page.getByRole("button", { name: "New Tag" }), rng);
    await expect(page.getByRole("heading", { name: "Create Tag" })).toBeVisible();
    await humanType(page.locator("#tag-id"), tag.id, rng);
    await humanType(page.locator("#tag-name"), tag.name, rng);
    await humanClick(page.getByRole("button", { name: "Save" }), rng);
    await page.waitForURL(/\/admin\/tags/);
  }

  await humanClick(page.getByRole("link", { name: "Content" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();
  await humanClick(page.getByRole("button", { name: "New Page" }), rng);
  await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();

  const expandButton = page.getByRole("button", { name: "Expand details" });
  if (await expandButton.isVisible()) {
    await humanClick(expandButton, rng);
  }

  // Expanded: the labelled filter field is present.
  const filter = page.locator("#content-tags");
  await expect(filter).toBeVisible();
  await expect(page.getByLabel("Tags")).toBeVisible();

  // "docs" leads the top row and also appears in the alphabetical row.
  await expect(page.getByRole("button", { name: "Add docs" })).toHaveCount(2);
  const firstAdd = page.locator('button[aria-label^="Add "]').first();
  await expect(firstAdd).toHaveAttribute("aria-label", "Add docs");

  // Filler tags are unused, so they only appear in the alphabetical row, which
  // scrolls horizontally.
  const alphaRow = page.locator("div.overflow-x-auto", {
    has: page.getByRole("button", { name: "Add filler-tag-number-01" }),
  });
  await expect(alphaRow).toBeVisible();
  expect(await alphaRow.evaluate((row) => row.scrollWidth > row.clientWidth)).toBe(true);

  // Below `md`, the details grid used to size to the chip strip and stretch the form.
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(alphaRow).toBeVisible();
  const narrowMetrics = await page.evaluate(() => {
    const row = document.querySelector("div.overflow-x-auto");
    const title = document.querySelector("#content-title");
    const alias = document.querySelector("#content-alias");
    if (!(row instanceof HTMLElement) || !(title instanceof HTMLElement) || !(alias instanceof HTMLElement)) {
      throw new Error("narrow layout probes missing");
    }
    return {
      documentWidth: document.documentElement.scrollWidth,
      viewport: window.innerWidth,
      rowClient: row.clientWidth,
      rowScroll: row.scrollWidth,
      titleWidth: title.getBoundingClientRect().width,
      aliasWidth: alias.getBoundingClientRect().width,
    };
  });
  expect(narrowMetrics.rowScroll).toBeGreaterThan(narrowMetrics.rowClient);
  expect(narrowMetrics.rowClient).toBeLessThanOrEqual(narrowMetrics.viewport);
  expect(narrowMetrics.titleWidth).toBeLessThan(narrowMetrics.viewport);
  expect(narrowMetrics.aliasWidth).toBeLessThan(narrowMetrics.viewport);
  expect(narrowMetrics.documentWidth).toBeLessThan(narrowMetrics.rowScroll);

  const insertButton = page.getByRole("button", { name: "Insert" });
  const sizeLabel = page.getByText("Size", { exact: true });
  const insertBox = await insertButton.boundingBox();
  const sizeBox = await sizeLabel.boundingBox();
  if (!insertBox || !sizeBox) {
    throw new Error("editor toolbar controls have no bounding box");
  }
  expect(insertBox.y).toBeLessThan(sizeBox.y);
  expect(insertBox.x + insertBox.width).toBeLessThanOrEqual(390);
  expect(sizeBox.x + sizeBox.width).toBeLessThanOrEqual(390);
  expect(
    await insertButton.evaluate((button) => button.parentElement?.classList.contains("flex-wrap")),
  ).toBe(true);
  await expect(page.getByText("or drop file(s) on the editor")).toBeHidden();

  await page.setViewportSize({ width: 1280, height: 720 });
  await expect(filter).toBeVisible();
  await expect(page.getByText("or drop file(s) on the editor")).toBeVisible();

  // Visual: the filter field matches chip height and neither row clips chips.
  const filterBox = await filter.boundingBox();
  const chipBox = await firstAdd.boundingBox();
  if (!filterBox || !chipBox) {
    throw new Error("filter field or chip has no bounding box");
  }
  expect(Math.abs(filterBox.height - chipBox.height)).toBeLessThanOrEqual(1);
  expect(
    await alphaRow.evaluate((row) => row.scrollHeight - row.clientHeight)
  ).toBeLessThanOrEqual(1);
  const topRow = page.locator("div.overflow-hidden", {
    has: page.getByRole("button", { name: "Add docs" }),
  });
  expect(await topRow.evaluate((row) => row.scrollHeight - row.clientHeight)).toBeLessThanOrEqual(
    1
  );

  // Filtering narrows to matches and hides the top row.
  await humanType(filter, "zz", rng);
  await expect(page.getByRole("button", { name: /^Add / })).toHaveCount(1);

  // Selecting keeps the filter text.
  await humanClick(page.getByRole("button", { name: "Add zz" }), rng);
  await expect(page.locator('[aria-label="Remove zz"]')).toBeVisible();
  await expect(filter).toHaveValue("zz");
  await expect(page.getByText("No matches")).toBeVisible();

  // Clearing restores the full list.
  await humanClick(page.getByRole("button", { name: "Clear search" }), rng);
  await expect(filter).toHaveValue("");
  await expect(page.getByRole("button", { name: "Add docs" })).toHaveCount(2);

  // Save the page tagged "zz" so it gains usage 1, then check top-row order.
  await humanType(page.locator("#content-alias"), "selector/probe", rng);
  await humanType(page.locator("#content-title"), "Selector Probe", rng);
  await page.waitForFunction(
    () => (window as Window & { ace?: unknown }).ace && document.querySelector(".ace_editor"),
  );
  await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    editor.setValue("# Selector Probe\n\nPlaywright selector test.\n");
    editor.clearSelection();
  });
  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/pages\/edit/);

  await humanClick(page.getByRole("link", { name: "Content" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();
  await humanClick(page.getByRole("button", { name: "New Page" }), rng);
  await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();
  const expandAgain = page.getByRole("button", { name: "Expand details" });
  if (await expandAgain.isVisible()) {
    await humanClick(expandAgain, rng);
  }
  await expect(page.locator("#content-tags")).toBeVisible();

  const labels = await page
    .locator('button[aria-label^="Add "]')
    .evaluateAll((buttons) => buttons.map((button) => button.getAttribute("aria-label")));
  expect(labels.slice(0, 2)).toEqual(["Add docs", "Add zz"]);
});

test("content editor inserts title as page heading", async ({ page, harness, rng }) => {
  await login({
    page,
    baseUrl: harness.baseUrl,
    user: harness.users.admin,
    rng,
    returnPath: "/admin/pages",
    expectedPath: "/admin/pages",
  });

  await humanClick(page.getByRole("button", { name: "New Page" }), rng);
  await expect(page.getByRole("heading", { name: "Create Content" })).toBeVisible();

  const titleInput = page.locator("#content-title");
  const insertTitle = page.getByRole("button", { name: "Insert title to page" });
  await expect(insertTitle).toBeVisible();
  await expect(insertTitle).toBeDisabled();

  const titleBox = await titleInput.boundingBox();
  const buttonBox = await insertTitle.boundingBox();
  expect(titleBox).not.toBeNull();
  expect(buttonBox).not.toBeNull();
  expect(buttonBox?.x ?? 0).toBeGreaterThan(titleBox?.x ?? 0);
  expect((buttonBox?.x ?? 0) + (buttonBox?.width ?? 0)).toBeLessThanOrEqual(
    (titleBox?.x ?? 0) + (titleBox?.width ?? 0) + 1
  );
  expect(buttonBox?.y ?? 0).toBeGreaterThanOrEqual((titleBox?.y ?? 0) - 2);
  expect((buttonBox?.y ?? 0) + (buttonBox?.height ?? 0)).toBeLessThanOrEqual(
    (titleBox?.y ?? 0) + (titleBox?.height ?? 0) + 2
  );

  await humanType(titleInput, "Getting Started", rng);
  await expect(insertTitle).toBeEnabled();

  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );

  await humanClick(insertTitle, rng);
  await expect.poll(async () => {
    return page.evaluate(() => {
      const ace = (window as Window & { ace?: any }).ace;
      const editor = ace.edit(document.querySelector(".ace_editor"));
      return editor.getValue();
    });
  }).toBe("# Getting Started\n");

  let cursor = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getCursorPosition();
  });
  expect(cursor).toEqual({ row: 1, column: 0 });

  await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    editor.setValue("\n\nBody only.\n");
    editor.clearSelection();
  });
  await humanClick(insertTitle, rng);
  await expect.poll(async () => {
    return page.evaluate(() => {
      const ace = (window as Window & { ace?: any }).ace;
      const editor = ace.edit(document.querySelector(".ace_editor"));
      return editor.getValue();
    });
  }).toBe("# Getting Started\n\nBody only.\n");
  cursor = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getCursorPosition();
  });
  expect(cursor).toEqual({ row: 2, column: 0 });

  await humanClearAndType(titleInput, "Updated Title", rng);
  await humanClick(insertTitle, rng);
  await expect.poll(async () => {
    return page.evaluate(() => {
      const ace = (window as Window & { ace?: any }).ace;
      const editor = ace.edit(document.querySelector(".ace_editor"));
      return editor.getValue();
    });
  }).toBe("# Updated Title\n\nBody only.\n");
  cursor = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getCursorPosition();
  });
  expect(cursor).toEqual({ row: 2, column: 0 });
});
