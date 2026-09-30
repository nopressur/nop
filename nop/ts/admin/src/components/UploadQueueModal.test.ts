// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import UploadQueueModal from "./UploadQueueModal.svelte";

const contentMocks = vi.hoisted(() => ({
  getContentAliasStatus: vi.fn().mockResolvedValue({
    canonicalAlias: "images/photo.png",
    exists: false,
    id: null,
    version: null,
    mime: null,
    isMarkdown: null,
    title: null,
  }),
  uploadBinaryFile: vi.fn().mockResolvedValue({
    id: "upload-id",
    alias: "images/photo.png",
    mime: "image/png",
    isMarkdown: false,
  }),
}));

vi.mock("../services/content", () => ({
  getContentAliasStatus: contentMocks.getContentAliasStatus,
  uploadBinaryFile: contentMocks.uploadBinaryFile,
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

describe("UploadQueueModal", () => {
  beforeEach(() => {
    contentMocks.getContentAliasStatus.mockClear();
    contentMocks.getContentAliasStatus.mockResolvedValue({
      canonicalAlias: "images/photo.png",
      exists: false,
      id: null,
      version: null,
      mime: null,
      isMarkdown: null,
      title: null,
    });
    contentMocks.uploadBinaryFile.mockClear();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("uploads the file on Enter with selected tags", async () => {
    const file = new File(["data"], "photo.png", { type: "image/png" });
    const item = {
      id: "item-1",
      file,
      alias: "images/photo.png",
      title: "photo",
      tags: [],
      status: "ready" as const,
      error: null,
      progress: null,
    };

    const { findByLabelText, getByRole } = render(UploadQueueModal, {
      open: true,
      items: [item],
      availableTags: ["media", "docs"],
    });

    const tagsButton = await findByLabelText("Tags");
    await userEvent.click(tagsButton);
    await userEvent.click(getByRole("button", { name: "media" }));

    const aliasInput = await findByLabelText("Alias");
    aliasInput.focus();
    await userEvent.keyboard("{Enter}");

    await waitFor(() => expect(contentMocks.uploadBinaryFile).toHaveBeenCalled());
    const [params] = contentMocks.uploadBinaryFile.mock.calls[0];
    expect(params.tags).toEqual(["media"]);
  });

  it("marks an existing binary alias as a new version before upload", async () => {
    contentMocks.getContentAliasStatus.mockResolvedValue({
      canonicalAlias: "images/photo.png",
      exists: true,
      id: "0000000000000007",
      version: 3,
      mime: "image/png",
      isMarkdown: false,
      title: "Photo",
    });
    const file = new File(["data"], "photo.png", { type: "image/png" });
    const item = {
      id: "item-1",
      file,
      alias: "images/photo.png",
      title: "photo",
      tags: [],
      status: "ready" as const,
      error: null,
      progress: null,
    };

    const { findByText } = render(UploadQueueModal, {
      open: true,
      items: [item],
      availableTags: [],
    });

    expect(await findByText("New version of 0000000000000007 v4")).toBeTruthy();
    expect(contentMocks.getContentAliasStatus).toHaveBeenCalledWith("images/photo.png");
  });

  it("debounces alias status checks after alias edits without showing a checking message", async () => {
    vi.useFakeTimers();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const file = new File(["data"], "photo.png", { type: "image/png" });
    const item = {
      id: "item-1",
      file,
      alias: "",
      title: "photo",
      tags: [],
      status: "ready" as const,
      error: null,
      progress: null,
    };

    const { findByLabelText, queryByText } = render(UploadQueueModal, {
      open: true,
      items: [item],
      availableTags: [],
    });

    const aliasInput = await findByLabelText("Alias");
    await user.type(aliasInput, "images/new.png");

    expect(queryByText("Checking alias")).toBeNull();
    expect(contentMocks.getContentAliasStatus).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(399);
    expect(contentMocks.getContentAliasStatus).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    await waitFor(() =>
      expect(contentMocks.getContentAliasStatus).toHaveBeenCalledWith("images/new.png"),
    );
  });

  it("shows a durable alias verification failure message", async () => {
    contentMocks.getContentAliasStatus.mockRejectedValueOnce(new Error("network"));
    const file = new File(["data"], "photo.png", { type: "image/png" });
    const item = {
      id: "item-1",
      file,
      alias: "images/photo.png",
      title: "photo",
      tags: [],
      status: "ready" as const,
      error: null,
      progress: null,
    };

    const { findByText, queryByText } = render(UploadQueueModal, {
      open: true,
      items: [item],
      availableTags: [],
    });

    expect(queryByText("Checking alias")).toBeNull();
    expect(await findByText("Alias could not be verified.")).toBeTruthy();
  });

  it("blocks upload when the alias belongs to Markdown content", async () => {
    contentMocks.getContentAliasStatus.mockResolvedValue({
      canonicalAlias: "docs/page",
      exists: true,
      id: "0000000000000008",
      version: 1,
      mime: "text/markdown",
      isMarkdown: true,
      title: "Page",
    });
    const file = new File(["data"], "page.bin", { type: "application/octet-stream" });
    const item = {
      id: "item-1",
      file,
      alias: "docs/page",
      title: "page",
      tags: [],
      status: "ready" as const,
      error: null,
      progress: null,
    };

    const { findByText, getByRole } = render(UploadQueueModal, {
      open: true,
      items: [item],
      availableTags: [],
    });

    expect(await findByText("Alias belongs to Markdown content.")).toBeTruthy();
    expect(getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("ignores stale alias-status responses after alias edits", async () => {
    vi.useFakeTimers();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    let resolveFirst: (value: unknown) => void = () => undefined;
    const firstStatus = new Promise((resolve) => {
      resolveFirst = resolve;
    });
    contentMocks.getContentAliasStatus
      .mockReturnValueOnce(firstStatus)
      .mockResolvedValueOnce({
        canonicalAlias: "images/new.png",
        exists: false,
        id: null,
        version: null,
        mime: null,
        isMarkdown: null,
        title: null,
      });
    const file = new File(["data"], "photo.png", { type: "image/png" });
    const item = {
      id: "item-1",
      file,
      alias: "images/photo.png",
      title: "photo",
      tags: [],
      status: "ready" as const,
      error: null,
      progress: null,
    };

    const { findByLabelText, queryByText } = render(UploadQueueModal, {
      open: true,
      items: [item],
      availableTags: [],
    });

    const aliasInput = await findByLabelText("Alias");
    await user.clear(aliasInput);
    await user.type(aliasInput, "images/new.png");
    await vi.advanceTimersByTimeAsync(400);
    resolveFirst({
      canonicalAlias: "images/photo.png",
      exists: true,
      id: "0000000000000009",
      version: 2,
      mime: "image/png",
      isMarkdown: false,
      title: "Photo",
    });

    await waitFor(() => {
      expect(contentMocks.getContentAliasStatus).toHaveBeenCalledWith("images/new.png");
      expect(queryByText("New version of 0000000000000009 v3")).toBeNull();
    });
  });
});
