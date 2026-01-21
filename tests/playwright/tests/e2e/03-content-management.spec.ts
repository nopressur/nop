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
  const tagSelect = page.locator("#content-tags");
  await expect(tagSelect.locator('option[value="docs"]')).toHaveCount(1);
  await tagSelect.selectOption("docs");
  await tagSelect.selectOption("ui");

  await page.waitForFunction(
    () => (window as Window & { ace?: any }).ace && document.querySelector(".ace_editor")
  );
  await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    editor.setValue("# UI Test\n\nHello from Playwright.\n");
    editor.clearSelection();
  });

  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await page.waitForURL(/\/admin\/pages\/edit/);

  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
  await ensureDetailsOpen();
  await expect(page.locator("#content-alias")).toHaveValue("docs/ui-test");
  await expect(page.locator("#content-title")).toHaveValue("UI Test");

  await tagSelect.selectOption("featured");
  await humanClick(page.getByRole("button", { name: "Save" }), rng);
  await expect(page.getByText("Content saved").last()).toBeVisible();

  await humanClearAndType(page.locator("#content-title"), "UI Test Updated", rng);
  const saveShortcut = process.platform === "darwin" ? "Meta+S" : "Control+S";
  await page.keyboard.press(saveShortcut);
  await expect(page.getByText("Content saved").last()).toBeVisible();
  await dismissNotifications();

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
    /images\/example\.png/
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
  expect(updatedContent).toContain("/images/example.png");
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

  await page.waitForFunction(() => {
    const ace = (window as Window & { ace?: any }).ace;
    if (!ace) {
      return false;
    }
    const editor = ace.edit(document.querySelector(".ace_editor"));
    const value = editor.getValue();
    const hasImage = value.includes("/images/diagram.png");
    const hasPdf = value.includes("/files/manual.pdf") || /\/id\//.test(value);
    const hasVideo = value.includes("/videos/clip.mp4");
    return hasImage && hasPdf && hasVideo;
  });

  const updatedContentAfterDrop = await page.evaluate(() => {
    const ace = (window as Window & { ace?: any }).ace;
    const editor = ace.edit(document.querySelector(".ace_editor"));
    return editor.getValue();
  });
  expect(updatedContentAfterDrop).toMatch(/\/files\/manual\.pdf|\/id\//);
  expect(updatedContentAfterDrop).toContain("/images/diagram.png");
  expect(updatedContentAfterDrop).toContain("/videos/clip.mp4");

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
  await expect(imageInsertModal.getByRole("radio", { name: "Link" })).toHaveAttribute(
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
  expect(contentAfterImageInsert).toContain("![diagram](/images/diagram.png)");

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
  expect(contentAfterVideoInsert).toContain('((video src="/videos/clip.mp4"))');

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
    page.getByPlaceholder("Search titles"),
    "list-upload",
    rng
  );
  await expect(page.locator("tr", { hasText: "list-upload" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search titles"),
    "list-multi-one",
    rng
  );
  await expect(page.locator("tr", { hasText: "list-multi-one" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search titles"),
    "list-multi-two",
    rng
  );
  await expect(page.locator("tr", { hasText: "list-multi-two" })).toBeVisible();

  await humanClearAndType(
    page.getByPlaceholder("Search titles"),
    "UI Test",
    rng
  );
  await expect(page.locator("tr", { hasText: "UI Test" })).toBeVisible();
  await humanClick(page.locator("tr", { hasText: "UI Test" }).getByText("docs/ui-test"), rng);
  await expect(page.getByRole("heading", { name: "Edit Content" })).toBeVisible();
  await humanClearAndType(page.locator("#content-title"), "UI Test Draft", rng);

  await page.keyboard.press("Escape");
  const discardModal = page.getByRole("dialog", { name: "Unsaved changes" });
  await expect(discardModal).toBeVisible();
  await humanClick(discardModal.getByRole("button", { name: "Discard" }), rng);
  await expect(page.getByRole("heading", { name: "Content Library" })).toBeVisible();
  await expect(page.getByPlaceholder("Search titles")).toHaveValue("UI Test");
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
    page.getByPlaceholder("Search titles"),
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
    page.getByPlaceholder("Search titles"),
    "Unsaved Close Test Saved",
    rng
  );
  await expect(page.locator("tr", { hasText: "Unsaved Close Test Saved" })).toBeVisible();
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
    if (options.tags.length > 0) {
      await page.locator("#content-tags").selectOption(options.tags);
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
  const searchInput = page.locator('input[placeholder="Search titles"]');
  await humanClearAndType(searchInput, "Sort Base", rng);

  const table = page.locator("table");
  const rows = table.locator("tbody tr");
  await expect(rows).toHaveCount(4);

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
  ]);

  const titleButton = table.locator("thead").getByRole("button", { name: "Title" });
  await humanClick(titleButton, rng);
  await expectColumnOrder(0, [
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
    ],
    [
      "/sort-base-empty",
      "/sort-base-beta",
      "/sort-base-alpha",
      "/images/sort-base-image",
    ],
  );

  await sortAndExpect(
    "Tags",
    2,
    ["alpha", "beta", "gamma", "—"],
    ["gamma", "beta", "alpha", "—"],
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
    ["Nav Alpha", "Nav Beta", "—", "—"],
    ["Nav Beta", "Nav Alpha", "—", "—"],
  );

  await humanClearAndType(searchInput, "Sort Tie", rng);
  await expect(rows).toHaveCount(2);
  await humanClick(titleButton, rng);

  const expectedTieAliases = Object.entries(tieIds)
    .sort((left, right) => left[1].localeCompare(right[1]))
    .map(([alias]) => alias);
  await expect
    .poll(async () => {
      const aliases = await getColumnTexts(1);
      return aliases.map((alias) => alias.replace(/^\//, ""));
    })
    .toEqual(expectedTieAliases);
});
