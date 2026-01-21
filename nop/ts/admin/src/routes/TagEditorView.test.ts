// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import TagEditorView from "./TagEditorView.svelte";

type RouteState = {
  path: string;
  query: URLSearchParams;
  fullPath: string;
};

const routerMocks = vi.hoisted(() => {
  let value: RouteState = {
    path: "/tags/new",
    query: new URLSearchParams(),
    fullPath: "/admin/tags/new",
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

const tagMocks = vi.hoisted(() => ({
  createTag: vi.fn().mockResolvedValue(undefined),
  getTag: vi.fn(),
  updateTag: vi.fn(),
}));

const roleMocks = vi.hoisted(() => ({
  listRoles: vi.fn().mockResolvedValue([]),
}));

vi.mock("../stores/router", () => ({
  route: routerMocks.route,
  navigate: routerMocks.navigate,
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

vi.mock("../services/tags", () => ({
  createTag: tagMocks.createTag,
  getTag: tagMocks.getTag,
  updateTag: tagMocks.updateTag,
}));

vi.mock("../services/roles", () => ({
  listRoles: roleMocks.listRoles,
}));

describe("TagEditorView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    routerMocks.route.set({
      path: "/tags/new",
      query: new URLSearchParams(),
      fullPath: "/admin/tags/new",
    });
  });

  it("saves on Enter", async () => {
    const { findByLabelText } = render(TagEditorView);

    await waitFor(() => expect(roleMocks.listRoles).toHaveBeenCalled());

    const idInput = await findByLabelText("Tag ID");
    const nameInput = await findByLabelText("Name");

    await userEvent.type(idInput, "docs");
    await userEvent.type(nameInput, "Docs");

    nameInput.focus();
    await userEvent.keyboard("{Enter}");

    await waitFor(() =>
      expect(tagMocks.createTag).toHaveBeenCalledWith({
        id: "docs",
        name: "Docs",
        roles: [],
        accessRule: null,
      }),
    );
    await waitFor(() => expect(routerMocks.navigate).toHaveBeenCalledWith("/tags"));
  });

  it("cancels on Escape", async () => {
    render(TagEditorView);

    await userEvent.keyboard("{Escape}");

    expect(routerMocks.navigate).toHaveBeenCalledWith("/tags");
  });
});
