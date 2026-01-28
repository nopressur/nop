// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ContentEditorView from "./ContentEditorView.svelte";
import { pushNotification } from "../stores/notifications";
import {
  clearAdminRuntimeConfig,
  setAdminRuntimeConfig,
} from "../config/runtime";
import {
  resetContentListState,
  setContentListState,
} from "../stores/contentListState";

type RouteState = {
  path: string;
  query: URLSearchParams;
  fullPath: string;
};

const routerMocks = vi.hoisted(() => {
  let value: RouteState = {
    path: "/pages/edit/test-id",
    query: new URLSearchParams(),
    fullPath: "/admin/pages/edit/test-id",
  };
  const subscribers = new Set<(next: RouteState) => void>();
  const route = {
    subscribe(fn: (next: RouteState) => void) {
      fn(value);
      subscribers.add(fn);
      return () => subscribers.delete(fn);
    },
    set(next: RouteState) {
      value = next;
      subscribers.forEach((fn) => fn(value));
    },
  };
  return {
    route,
    navigate: vi.fn(),
  };
});

const contentMocks = vi.hoisted(() => ({
  buildInsertSnippet: vi.fn(),
  createMarkdownStream: vi.fn(),
  defaultAliasForFile: vi.fn(),
  deleteContent: vi.fn(),
  listContent: vi.fn().mockResolvedValue({ items: [], total: 0, page: 1 }),
  listNavIndex: vi.fn().mockResolvedValue([]),
  parseContentTags: vi.fn().mockReturnValue({ tags: [], error: null }),
  prevalidateBinaryUpload: vi.fn(),
  readContent: vi.fn(),
  updateContent: vi.fn().mockResolvedValue(undefined),
  updateMarkdownStream: vi.fn().mockResolvedValue(undefined),
  uploadBinaryFile: vi.fn(),
}));

const browserMocks = vi.hoisted(() => ({
  getLocationOrigin: vi.fn().mockReturnValue("https://example.test"),
  openNewTab: vi.fn(),
  writeClipboardText: vi.fn().mockResolvedValue(true),
}));

vi.mock("../services/browser", async () => {
  const actual = await vi.importActual<typeof import("../services/browser")>(
    "../services/browser",
  );
  return {
    ...actual,
    getLocationOrigin: browserMocks.getLocationOrigin,
    openNewTab: browserMocks.openNewTab,
    writeClipboardText: browserMocks.writeClipboardText,
  };
});

vi.mock("../stores/router", () => ({
  route: routerMocks.route,
  navigate: routerMocks.navigate,
}));

vi.mock("../services/content", async () => {
  const actual = await vi.importActual<typeof import("../services/content")>(
    "../services/content",
  );
  return {
    ...actual,
    buildInsertSnippet: contentMocks.buildInsertSnippet,
    createMarkdownStream: contentMocks.createMarkdownStream,
    defaultAliasForFile: contentMocks.defaultAliasForFile,
    deleteContent: contentMocks.deleteContent,
    listContent: contentMocks.listContent,
    listNavIndex: contentMocks.listNavIndex,
    parseContentTags: contentMocks.parseContentTags,
    prevalidateBinaryUpload: contentMocks.prevalidateBinaryUpload,
    readContent: contentMocks.readContent,
    updateContent: contentMocks.updateContent,
    updateMarkdownStream: contentMocks.updateMarkdownStream,
    uploadBinaryFile: contentMocks.uploadBinaryFile,
  };
});

const tagMocks = vi.hoisted(() => ({
  listTags: vi.fn(),
}));

vi.mock("../services/tags", () => ({
  listTags: tagMocks.listTags,
}));

vi.mock("../services/themes", () => ({
  listThemes: vi.fn().mockResolvedValue([]),
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

const notificationMocks = {
  pushNotification: vi.mocked(pushNotification),
};

async function getLoadedTitleInput(
  findByLabelText: (text: string) => Promise<HTMLElement>,
  expectedValue = "Original title",
): Promise<HTMLElement> {
  const titleInput = await findByLabelText("Title");
  await waitFor(() => {
    expect((titleInput as HTMLInputElement).value).toBe(expectedValue);
  });
  return titleInput;
}

describe("ContentEditorView", () => {
  afterEach(() => {
    cleanup();
    clearAdminRuntimeConfig();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    resetContentListState();
    setAdminRuntimeConfig({
      adminPath: "/admin",
      appName: "NoPressure",
      csrfTokenPath: "/admin/csrf-token-api",
      wsPath: "/admin/ws",
      wsTicketPath: "/admin/ws-ticket",
      userManagementEnabled: true,
      passwordFrontEnd: {
        memoryKib: 64,
        iterations: 3,
        parallelism: 1,
        outputLen: 32,
        saltLen: 16,
      },
    });
    contentMocks.parseContentTags.mockReturnValue({ tags: [], error: null });
    contentMocks.defaultAliasForFile.mockImplementation((file: File, basePrefix?: string | null) => {
      if (basePrefix) {
        return `${basePrefix}/${file.name}`;
      }
      return `files/${file.name}`;
    });
    contentMocks.readContent.mockResolvedValue({
      id: "test-id",
      alias: "",
      title: "Original title",
      navTitle: "",
      navParentId: "",
      navOrder: null,
      theme: "",
      mime: "application/pdf",
      originalFilename: "file.pdf",
      content: "",
      tags: [],
    });
    contentMocks.prevalidateBinaryUpload.mockResolvedValue({
      accepted: true,
      message: "",
    });
    tagMocks.listTags.mockResolvedValue([]);
    routerMocks.route.set({
      path: "/pages/edit/test-id",
      query: new URLSearchParams(),
      fullPath: "/admin/pages/edit/test-id",
    });
  });

  it("shows Close when clean and Cancel when dirty", async () => {
    const { findByLabelText, getByRole, queryByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    const titleInput = await getLoadedTitleInput(findByLabelText);
    expect(getByRole("button", { name: "Close" })).toBeInTheDocument();
    expect(queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();

    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, "Updated title");

    expect(getByRole("button", { name: "Cancel" })).toBeInTheDocument();
  });

  it("keeps the editor open when modal cancel is selected", async () => {
    const { findByLabelText, getByRole, queryByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());

    const titleInput = await getLoadedTitleInput(findByLabelText);
    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, "Updated title");

    await userEvent.click(getByRole("button", { name: "Cancel" }));
    const dialog = getByRole("dialog", { name: "Unsaved changes" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(queryByRole("dialog", { name: "Unsaved changes" })).not.toBeInTheDocument();
    expect(routerMocks.navigate).not.toHaveBeenCalled();
  });

  it("navigates away when discard is selected", async () => {
    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());

    const titleInput = await getLoadedTitleInput(findByLabelText);
    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, "Updated title");

    await userEvent.click(getByRole("button", { name: "Cancel" }));
    const dialog = getByRole("dialog", { name: "Unsaved changes" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Discard" }));

    expect(routerMocks.navigate).toHaveBeenCalledWith("/pages");
  });

  it("saves and navigates away when save is selected", async () => {
    const { findByLabelText, getByRole, queryByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());

    const titleInput = await getLoadedTitleInput(findByLabelText);
    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, "Updated title");

    await userEvent.click(getByRole("button", { name: "Cancel" }));
    const dialog = getByRole("dialog", { name: "Unsaved changes" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() => expect(contentMocks.updateContent).toHaveBeenCalled());
    await waitFor(() => expect(routerMocks.navigate).toHaveBeenCalledWith("/pages"));
    expect(queryByRole("dialog", { name: "Unsaved changes" })).not.toBeInTheDocument();
  });

  it("closes the unsaved changes modal on Escape", async () => {
    const { findByLabelText, getByRole, queryByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());

    const titleInput = await getLoadedTitleInput(findByLabelText);
    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, "Updated title");

    await userEvent.click(getByRole("button", { name: "Cancel" }));
    const dialog = getByRole("dialog", { name: "Unsaved changes" });
    dialog.focus();
    await userEvent.keyboard("{Escape}");

    expect(queryByRole("dialog", { name: "Unsaved changes" })).not.toBeInTheDocument();
    expect(routerMocks.navigate).not.toHaveBeenCalled();
  });

  it("discards changes when D is pressed", async () => {
    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());

    const titleInput = await getLoadedTitleInput(findByLabelText);
    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, "Updated title");

    await userEvent.click(getByRole("button", { name: "Cancel" }));
    const dialog = getByRole("dialog", { name: "Unsaved changes" });
    dialog.focus();
    await userEvent.keyboard("d");

    expect(routerMocks.navigate).toHaveBeenCalledWith("/pages");
  });

  it("saves changes when Enter is pressed", async () => {
    const { findByLabelText, getByRole, queryByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());

    const titleInput = await getLoadedTitleInput(findByLabelText);
    await userEvent.clear(titleInput);
    await userEvent.type(titleInput, "Updated title");

    await userEvent.click(getByRole("button", { name: "Cancel" }));
    const dialog = getByRole("dialog", { name: "Unsaved changes" });
    dialog.focus();
    await userEvent.keyboard("{Enter}");

    await waitFor(() => expect(contentMocks.updateContent).toHaveBeenCalled());
    await waitFor(() => expect(routerMocks.navigate).toHaveBeenCalledWith("/pages"));
    expect(queryByRole("dialog", { name: "Unsaved changes" })).not.toBeInTheDocument();
  });

  it("clears the theme when default is selected", async () => {
    contentMocks.readContent.mockResolvedValue({
      id: "test-id",
      alias: "",
      title: "Original title",
      navTitle: "",
      navParentId: "",
      navOrder: null,
      theme: "ocean",
      mime: "application/pdf",
      originalFilename: "file.pdf",
      content: "",
      tags: [],
    });

    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText);

    await userEvent.click(getByRole("button", { name: "Expand details" }));
    const themeSelect = await findByLabelText("Theme");
    await userEvent.selectOptions(themeSelect, "");

    await userEvent.click(getByRole("button", { name: "Save" }));

    await waitFor(() => expect(contentMocks.updateContent).toHaveBeenCalled());
    const updatePayload = contentMocks.updateContent.mock.calls[0]?.[0];
    expect(updatePayload?.theme).toBe("");
  });

  it("saves and collapses details on Enter in a details field", async () => {
    const { findByLabelText, getByRole, queryByLabelText } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText);

    await userEvent.click(getByRole("button", { name: "Expand details" }));
    const aliasInput = await findByLabelText("Alias");
    aliasInput.focus();

    await fireEvent.keyDown(aliasInput, { key: "Enter" });

    await waitFor(() => expect(contentMocks.updateContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(queryByLabelText("Alias")).not.toBeInTheDocument();
    });
  });

  it("copies the ID URL from the editor toolbar", async () => {
    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText);

    await userEvent.click(getByRole("button", { name: "Copy ID URL" }));

    expect(browserMocks.writeClipboardText).toHaveBeenCalledWith(
      "https://example.test/id/test-id",
    );
    expect(notificationMocks.pushNotification).toHaveBeenCalledWith(
      "ID URL copied",
      "success",
    );
  });

  it("opens the ID URL in a new tab on modifier click", async () => {
    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText);

    await fireEvent.click(getByRole("button", { name: "Copy ID URL" }), {
      ctrlKey: true,
    });

    expect(browserMocks.openNewTab).toHaveBeenCalledWith(
      "https://example.test/id/test-id",
    );
    expect(browserMocks.writeClipboardText).not.toHaveBeenCalled();
    expect(notificationMocks.pushNotification).not.toHaveBeenCalled();
  });

  it("copies the alias URL from the editor toolbar", async () => {
    contentMocks.readContent.mockResolvedValue({
      id: "test-id",
      alias: "docs/intro",
      title: "Original title",
      navTitle: "",
      navParentId: "",
      navOrder: null,
      theme: "",
      mime: "text/markdown",
      originalFilename: "file.md",
      content: "",
      tags: [],
    });

    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText);

    await userEvent.click(getByRole("button", { name: "Copy alias URL" }));

    expect(browserMocks.writeClipboardText).toHaveBeenCalledWith(
      "https://example.test/docs/intro",
    );
    expect(notificationMocks.pushNotification).toHaveBeenCalledWith(
      "Alias URL copied",
      "success",
    );
  });

  it("opens the alias URL in a new tab on modifier click", async () => {
    contentMocks.readContent.mockResolvedValue({
      id: "test-id",
      alias: "docs/intro",
      title: "Original title",
      navTitle: "",
      navParentId: "",
      navOrder: null,
      theme: "",
      mime: "text/markdown",
      originalFilename: "file.md",
      content: "",
      tags: [],
    });

    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText);

    await fireEvent.click(getByRole("button", { name: "Copy alias URL" }), {
      metaKey: true,
    });

    expect(browserMocks.openNewTab).toHaveBeenCalledWith(
      "https://example.test/docs/intro",
    );
    expect(browserMocks.writeClipboardText).not.toHaveBeenCalled();
    expect(notificationMocks.pushNotification).not.toHaveBeenCalled();
  });

  it("copies the root URL for index aliases", async () => {
    contentMocks.readContent.mockResolvedValue({
      id: "test-id",
      alias: "index",
      title: "Home",
      navTitle: "",
      navParentId: "",
      navOrder: null,
      theme: "",
      mime: "text/markdown",
      originalFilename: "index.md",
      content: "",
      tags: [],
    });

    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText, "Home");

    await userEvent.click(getByRole("button", { name: "Copy alias URL" }));

    expect(browserMocks.writeClipboardText).toHaveBeenCalledWith(
      "https://example.test/",
    );
  });

  it("reports clipboard failures in the editor toolbar", async () => {
    browserMocks.writeClipboardText.mockResolvedValueOnce(false);
    const { findByLabelText, getByRole } = render(ContentEditorView);
    await waitFor(() => expect(contentMocks.readContent).toHaveBeenCalled());
    await getLoadedTitleInput(findByLabelText);

    await userEvent.click(getByRole("button", { name: "Copy ID URL" }));

    expect(notificationMocks.pushNotification).toHaveBeenCalledWith(
      "Failed to copy ID URL",
      "error",
    );
  });

  it("validates alias on change and clears the error when valid", async () => {
    routerMocks.route.set({
      path: "/pages/new",
      query: new URLSearchParams(),
      fullPath: "/admin/pages/new",
    });

    const { getByRole, getByLabelText, findByText, queryByText } = render(ContentEditorView);

    await userEvent.click(getByRole("button", { name: "Expand details" }));
    const aliasInput = getByLabelText("Alias");

    await userEvent.type(aliasInput, "id/forbidden");
    expect(await findByText(/reserved prefix/i)).toBeInTheDocument();

    await userEvent.clear(aliasInput);
    await userEvent.type(aliasInput, "blog/today");

    await waitFor(() => {
      expect(queryByText(/reserved prefix/i)).not.toBeInTheDocument();
    });
  });

  it("seeds new page tags and applies them to uploads", async () => {
    setContentListState({
      query: "",
      page: 1,
      pageSize: 25,
      markdownOnly: false,
      tags: ["docs", "ui"],
      sortField: "title",
      sortDirection: "asc",
    });
    tagMocks.listTags.mockResolvedValue([
      { id: "docs", name: "Docs" },
      { id: "ui", name: "UI" },
    ]);
    routerMocks.route.set({
      path: "/pages/new",
      query: new URLSearchParams(),
      fullPath: "/admin/pages/new",
    });

    const { getByRole, findByRole } = render(ContentEditorView);
    await waitFor(() => expect(tagMocks.listTags).toHaveBeenCalled());

    const editorRegion = getByRole("region", { name: "Markdown editor" });
    const file = new File(["data"], "photo.jpg", { type: "image/jpeg" });
    await fireEvent.drop(editorRegion, {
      dataTransfer: { files: [file], types: ["Files"] },
    });

    const dialog = await findByRole("dialog", { name: "Upload Asset" });
    await waitFor(() => {
      expect(within(dialog).getByLabelText("Tags")).toBeInTheDocument();
    });
    expect(within(dialog).getByLabelText("Tags")).toHaveTextContent("docs, ui");
  });

  it("uses the page alias for upload defaults and falls back when invalid", async () => {
    routerMocks.route.set({
      path: "/pages/new",
      query: new URLSearchParams(),
      fullPath: "/admin/pages/new",
    });

    const { getByRole, getByLabelText } = render(ContentEditorView);
    await waitFor(() => expect(tagMocks.listTags).toHaveBeenCalled());

    await userEvent.click(getByRole("button", { name: "Expand details" }));
    const aliasInput = getByLabelText("Alias");
    await userEvent.type(aliasInput, "blog/today");

    const editorRegion = getByRole("region", { name: "Markdown editor" });
    const firstFile = new File(["data"], "landscape.jpg", { type: "image/jpeg" });
    await fireEvent.drop(editorRegion, {
      dataTransfer: { files: [firstFile], types: ["Files"] },
    });

    await waitFor(() => expect(contentMocks.defaultAliasForFile).toHaveBeenCalled());
    expect(contentMocks.defaultAliasForFile.mock.calls[0][1]).toBe("blog/today");

    await userEvent.clear(aliasInput);
    await userEvent.type(aliasInput, "id/forbidden");

    const secondFile = new File(["data"], "second.jpg", { type: "image/jpeg" });
    await fireEvent.drop(editorRegion, {
      dataTransfer: { files: [secondFile], types: ["Files"] },
    });

    await waitFor(() => expect(contentMocks.defaultAliasForFile).toHaveBeenCalledTimes(2));
    expect(contentMocks.defaultAliasForFile.mock.calls[1][1]).toBeNull();
  });
});
