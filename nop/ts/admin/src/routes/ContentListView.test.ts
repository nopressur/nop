// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { routerMocks } from "./listViewTestMocks";
import ContentListView from "./ContentListView.svelte";

const contentMocks = vi.hoisted(() => ({
  defaultAliasForFile: vi.fn(),
  deleteContent: vi.fn(),
  listContent: vi.fn().mockResolvedValue({
    items: [
      {
        id: "first-id",
        title: "First Item",
        alias: "first-item",
        tags: [],
        mime: "text/markdown",
        navTitle: "",
      },
    ],
    total: 1,
    page: 1,
    pageSize: 25,
  }),
  prevalidateBinaryUpload: vi.fn(),
}));

vi.mock("../services/content", () => ({
  defaultAliasForFile: contentMocks.defaultAliasForFile,
  deleteContent: contentMocks.deleteContent,
  listContent: contentMocks.listContent,
  prevalidateBinaryUpload: contentMocks.prevalidateBinaryUpload,
}));

vi.mock("../services/tags", () => ({
  listTags: vi.fn().mockResolvedValue([]),
}));

describe("ContentListView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("navigates when a row is clicked", async () => {
    const { container } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });
    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    await userEvent.click(row as HTMLElement);

    expect(routerMocks.navigate).toHaveBeenCalledWith("/pages/edit/first-id");
  });

  it("opens the selected row on Enter", async () => {
    const { container } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });
    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    (row as HTMLTableRowElement).focus();
    await userEvent.keyboard("{Enter}");

    expect(routerMocks.navigate).toHaveBeenCalledWith("/pages/edit/first-id");
  });

  it("defaults to title ascending sort", async () => {
    render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());

    const [payload] = contentMocks.listContent.mock.calls[0];
    expect(payload).toEqual(
      expect.objectContaining({
        sortField: "title",
        sortDirection: "asc",
      }),
    );
  });

  it("toggles title sort direction on header click", async () => {
    const { getAllByRole } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());

    const [titleButton] = getAllByRole("button", { name: /Title/ });
    await userEvent.click(titleButton);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalledTimes(2));

    const [payload] = contentMocks.listContent.mock.calls[1];
    expect(payload).toEqual(
      expect.objectContaining({
        sortField: "title",
        sortDirection: "desc",
      }),
    );
  });
});
