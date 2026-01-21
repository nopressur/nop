// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { routerMocks } from "./listViewTestMocks";
import RoleListView from "./RoleListView.svelte";

const roleMocks = vi.hoisted(() => ({
  deleteRole: vi.fn(),
  listRoles: vi.fn().mockResolvedValue(["admin", "editor"]),
}));

vi.mock("../services/roles", () => ({
  deleteRole: roleMocks.deleteRole,
  listRoles: roleMocks.listRoles,
}));

describe("RoleListView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("does not navigate for the admin role row", async () => {
    const { container } = render(RoleListView);

    await waitFor(() => expect(roleMocks.listRoles).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="0"]')).not.toBeNull();
    });

    const row = container.querySelector('tr[data-row-index="0"]');
    expect(row).not.toBeNull();

    await userEvent.click(row as HTMLElement);

    expect(routerMocks.navigate).not.toHaveBeenCalled();
  });

  it("navigates when a non-admin row is clicked", async () => {
    const { container } = render(RoleListView);

    await waitFor(() => expect(roleMocks.listRoles).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="1"]')).not.toBeNull();
    });

    const row = container.querySelector('tr[data-row-index="1"]');
    expect(row).not.toBeNull();

    await userEvent.click(row as HTMLElement);

    expect(routerMocks.navigate).toHaveBeenCalledWith("/roles/edit?role=editor");
  });

  it("opens the selected row on Enter", async () => {
    const { container } = render(RoleListView);

    await waitFor(() => expect(roleMocks.listRoles).toHaveBeenCalled());
    await waitFor(() => {
      expect(container.querySelector('tr[data-row-index="1"]')).not.toBeNull();
    });

    const row = container.querySelector('tr[data-row-index="1"]');
    expect(row).not.toBeNull();

    (row as HTMLTableRowElement).focus();
    await userEvent.keyboard("{Enter}");

    expect(routerMocks.navigate).toHaveBeenCalledWith("/roles/edit?role=editor");
  });
});
