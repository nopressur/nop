// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { routerMocks } from "./listViewTestMocks";
import UserListView from "./UserListView.svelte";

const userMocks = vi.hoisted(() => ({
  deleteUser: vi.fn(),
  getUser: vi.fn().mockResolvedValue({
    email: "alpha@example.com",
    roles: ["editor"],
  }),
  listUsers: vi.fn().mockResolvedValue([
    { email: "alpha@example.com", name: "Alpha" },
  ]),
}));

vi.mock("../config/runtime", () => ({
  getAdminBootstrap: () => ({
    currentUserEmail: "admin@example.com",
  }),
}));

vi.mock("../services/users", () => ({
  deleteUser: userMocks.deleteUser,
  getUser: userMocks.getUser,
  listUsers: userMocks.listUsers,
}));

describe("UserListView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
  });

  it("navigates when a row is clicked", async () => {
    const { container } = render(UserListView);

    await waitFor(() => expect(userMocks.listUsers).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });

    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    await userEvent.click(row as HTMLElement);

    expect(routerMocks.navigate).toHaveBeenCalledWith(
      "/users/edit/alpha%40example.com",
    );
  });

  it("opens the selected row on Enter", async () => {
    const { container } = render(UserListView);

    await waitFor(() => expect(userMocks.listUsers).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });

    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    (row as HTMLTableRowElement).focus();
    await userEvent.keyboard("{Enter}");

    expect(routerMocks.navigate).toHaveBeenCalledWith(
      "/users/edit/alpha%40example.com",
    );
  });
});
