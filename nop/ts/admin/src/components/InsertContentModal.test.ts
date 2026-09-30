// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, render, waitFor } from "@testing-library/svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import InsertContentModal from "./InsertContentModal.svelte";

const contentMocks = vi.hoisted(() => ({
  listContent: vi.fn().mockResolvedValue({
    items: [],
    total: 0,
    page: 1,
    pageSize: 25,
  }),
}));

const searchMocks = vi.hoisted(() => ({
  findSearch: vi.fn().mockResolvedValue({ hits: [] }),
}));

vi.mock("../services/content", () => ({
  listContent: contentMocks.listContent,
}));

vi.mock("../services/search", () => ({
  findSearch: searchMocks.findSearch,
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

describe("InsertContentModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("uses a textless gradient while initial results load", async () => {
    contentMocks.listContent.mockReturnValueOnce(new Promise(() => undefined));

    const { getByTestId, queryByText } = render(InsertContentModal, {
      open: true,
      tags: [],
      defaultTag: "",
    });

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    expect(queryByText("Loading content...")).toBeNull();
    expect(getByTestId("loading-gradient")).toBeTruthy();
  });
});
