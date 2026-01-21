// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, render, waitFor, within } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ContentEditorView from "./ContentEditorView.svelte";

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

vi.mock("../stores/router", () => ({
  route: routerMocks.route,
  navigate: routerMocks.navigate,
}));

vi.mock("../services/content", () => ({
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
}));

vi.mock("../services/tags", () => ({
  listTags: vi.fn().mockResolvedValue([]),
}));

vi.mock("../services/themes", () => ({
  listThemes: vi.fn().mockResolvedValue([]),
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

async function getLoadedTitleInput(
  findByLabelText: (text: string) => Promise<HTMLElement>,
): Promise<HTMLElement> {
  const titleInput = await findByLabelText("Title");
  await waitFor(() => {
    expect((titleInput as HTMLInputElement).value).toBe("Original title");
  });
  return titleInput;
}

describe("ContentEditorView", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    contentMocks.parseContentTags.mockReturnValue({ tags: [], error: null });
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
});
