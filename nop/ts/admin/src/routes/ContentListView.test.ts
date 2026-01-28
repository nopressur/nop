// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import { within } from "@testing-library/dom";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { notificationMocks, routerMocks } from "./listViewTestMocks";
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

const browserMocks = vi.hoisted(() => ({
  getLocationOrigin: vi.fn().mockReturnValue("https://example.test"),
  writeClipboardText: vi.fn().mockResolvedValue(true),
}));

vi.mock("../services/browser", async () => {
  const actual = await vi.importActual<typeof import("../services/browser")>(
    "../services/browser",
  );
  return {
    ...actual,
    getLocationOrigin: browserMocks.getLocationOrigin,
    writeClipboardText: browserMocks.writeClipboardText,
  };
});

vi.mock("../services/content", async () => {
  const actual = await vi.importActual<typeof import("../services/content")>(
    "../services/content",
  );
  return {
    ...actual,
    defaultAliasForFile: contentMocks.defaultAliasForFile,
    deleteContent: contentMocks.deleteContent,
    listContent: contentMocks.listContent,
    prevalidateBinaryUpload: contentMocks.prevalidateBinaryUpload,
  };
});

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

  it("copies the ID URL from the actions", async () => {
    const { container } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });
    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    const idButton = within(row as HTMLElement).getByRole("button", {
      name: "Copy ID URL",
    });
    await userEvent.click(idButton);

    expect(browserMocks.writeClipboardText).toHaveBeenCalledWith(
      "https://example.test/id/first-id",
    );
    expect(notificationMocks.pushNotification).toHaveBeenCalledWith(
      "ID URL copied",
      "success",
    );
  });

  it("copies the alias URL when present", async () => {
    const { container } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });
    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    const aliasButton = within(row as HTMLElement).getByRole("button", {
      name: "Copy alias URL",
    });
    await userEvent.click(aliasButton);

    expect(browserMocks.writeClipboardText).toHaveBeenCalledWith(
      "https://example.test/first-item",
    );
    expect(notificationMocks.pushNotification).toHaveBeenCalledWith(
      "Alias URL copied",
      "success",
    );
  });

  it("copies the root URL for index aliases", async () => {
    contentMocks.listContent.mockResolvedValueOnce({
      items: [
        {
          id: "index-id",
          title: "Home",
          alias: "index",
          tags: [],
          mime: "text/markdown",
          navTitle: "",
        },
      ],
      total: 1,
      page: 1,
      pageSize: 25,
    });

    const { container } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });
    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    const aliasButton = within(row as HTMLElement).getByRole("button", {
      name: "Copy alias URL",
    });
    await userEvent.click(aliasButton);

    expect(browserMocks.writeClipboardText).toHaveBeenCalledWith(
      "https://example.test/",
    );
  });

  it("hides the alias button when no alias exists", async () => {
    contentMocks.listContent.mockResolvedValueOnce({
      items: [
        {
          id: "no-alias-id",
          title: "No Alias",
          alias: "",
          tags: [],
          mime: "text/markdown",
          navTitle: "",
        },
      ],
      total: 1,
      page: 1,
      pageSize: 25,
    });

    const { container } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });
    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    const aliasButton = within(row as HTMLElement).queryByRole("button", {
      name: "Copy alias URL",
    });
    expect(aliasButton).toBeNull();
  });

  it("reports clipboard failures", async () => {
    browserMocks.writeClipboardText.mockResolvedValueOnce(false);
    const { container } = render(ContentListView);

    await waitFor(() => expect(contentMocks.listContent).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });
    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    const idButton = within(row as HTMLElement).getByRole("button", {
      name: "Copy ID URL",
    });
    await userEvent.click(idButton);

    expect(notificationMocks.pushNotification).toHaveBeenCalledWith(
      "Failed to copy ID URL",
      "error",
    );
  });
});
