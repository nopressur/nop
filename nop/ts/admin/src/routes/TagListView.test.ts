// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { routerMocks } from "./listViewTestMocks";
import TagListView from "./TagListView.svelte";

const tagMocks = vi.hoisted(() => ({
  deleteTag: vi.fn(),
  listTags: vi.fn().mockResolvedValue([{ id: "docs", name: "Docs" }]),
}));

vi.mock("../services/tags", () => ({
  deleteTag: tagMocks.deleteTag,
  listTags: tagMocks.listTags,
}));

describe("TagListView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("navigates when a row is clicked", async () => {
    const { container } = render(TagListView);

    await waitFor(() => expect(tagMocks.listTags).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });

    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    await userEvent.click(row as HTMLElement);

    expect(routerMocks.navigate).toHaveBeenCalledWith("/tags/edit?id=docs");
  });

  it("opens the selected row on Enter", async () => {
    const { container } = render(TagListView);

    await waitFor(() => expect(tagMocks.listTags).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });

    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    (row as HTMLTableRowElement).focus();
    await userEvent.keyboard("{Enter}");

    expect(routerMocks.navigate).toHaveBeenCalledWith("/tags/edit?id=docs");
  });
});
