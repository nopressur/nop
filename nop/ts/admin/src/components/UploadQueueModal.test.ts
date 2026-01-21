// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import UploadQueueModal from "./UploadQueueModal.svelte";

const contentMocks = vi.hoisted(() => ({
  uploadBinaryFile: vi.fn().mockResolvedValue({
    id: "upload-id",
    alias: "images/photo.png",
    mime: "image/png",
    isMarkdown: false,
  }),
}));

vi.mock("../services/content", () => ({
  uploadBinaryFile: contentMocks.uploadBinaryFile,
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

describe("UploadQueueModal", () => {
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
});
