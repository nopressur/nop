// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import RoleEditorView from "./RoleEditorView.svelte";

type RouteState = {
  path: string;
  query: URLSearchParams;
  fullPath: string;
};

const routerMocks = vi.hoisted(() => {
  let value: RouteState = {
    path: "/roles/new",
    query: new URLSearchParams(),
    fullPath: "/admin/roles/new",
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

const roleMocks = vi.hoisted(() => ({
  createRole: vi.fn().mockResolvedValue(undefined),
  getRole: vi.fn(),
  renameRole: vi.fn(),
}));

vi.mock("../stores/router", () => ({
  route: routerMocks.route,
  navigate: routerMocks.navigate,
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

vi.mock("../services/roles", () => ({
  createRole: roleMocks.createRole,
  getRole: roleMocks.getRole,
  renameRole: roleMocks.renameRole,
}));

describe("RoleEditorView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    routerMocks.route.set({
      path: "/roles/new",
      query: new URLSearchParams(),
      fullPath: "/admin/roles/new",
    });
  });

  it("saves on Enter", async () => {
    const { findByLabelText } = render(RoleEditorView);

    const roleInput = await findByLabelText("Role");
    await userEvent.type(roleInput, "editor");
    roleInput.focus();
    await userEvent.keyboard("{Enter}");

    await waitFor(() => expect(roleMocks.createRole).toHaveBeenCalledWith("editor"));
    await waitFor(() => expect(routerMocks.navigate).toHaveBeenCalledWith("/roles"));
  });

  it("cancels on Escape", async () => {
    render(RoleEditorView);

    await userEvent.keyboard("{Escape}");

    expect(routerMocks.navigate).toHaveBeenCalledWith("/roles");
  });
});
