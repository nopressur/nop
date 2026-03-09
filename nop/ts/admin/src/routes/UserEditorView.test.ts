// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearAdminRuntimeConfig,
  setAdminRuntimeConfig,
} from "../config/runtime";
import UserEditorView from "./UserEditorView.svelte";

type RouteState = {
  path: string;
  query: URLSearchParams;
  fullPath: string;
};

const routerMocks = vi.hoisted(() => {
  let value: RouteState = {
    path: "/users/new",
    query: new URLSearchParams(),
    fullPath: "/admin/users/new",
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
  listRoles: vi.fn().mockResolvedValue([]),
}));

const userMocks = vi.hoisted(() => ({
  createUser: vi.fn().mockResolvedValue("User created"),
  getUser: vi.fn(),
  updateUserName: vi.fn(),
  updateUserPassword: vi.fn(),
  addUserRole: vi.fn(),
  removeUserRole: vi.fn(),
}));

vi.mock("../stores/router", () => ({
  route: routerMocks.route,
  navigate: routerMocks.navigate,
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

vi.mock("../services/roles", () => ({
  listRoles: roleMocks.listRoles,
}));

vi.mock("../services/users", () => ({
  createUser: userMocks.createUser,
  getUser: userMocks.getUser,
  updateUserName: userMocks.updateUserName,
  updateUserPassword: userMocks.updateUserPassword,
  addUserRole: userMocks.addUserRole,
  removeUserRole: userMocks.removeUserRole,
}));

describe("UserEditorView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    routerMocks.route.set({
      path: "/users/new",
      query: new URLSearchParams(),
      fullPath: "/admin/users/new",
    });
    setAdminRuntimeConfig({
      adminPath: "/admin",
      appName: "NoPressure",
      csrfTokenPath: "/admin/csrf-token-api",
      wsPath: "/admin/ws",
      wsTicketPath: "/admin/ws-ticket",
      userManagementEnabled: true,
      passwordFrontEnd: {
        memoryKib: 64,
        iterations: 2,
        parallelism: 1,
        outputLen: 32,
        saltLen: 16,
      },
      passwordComplexityEnabled: true,
    });
  });

  afterEach(() => {
    cleanup();
    clearAdminRuntimeConfig();
  });

  it("saves on Enter", async () => {
    const { findByLabelText } = render(UserEditorView);

    await waitFor(() => expect(roleMocks.listRoles).toHaveBeenCalled());

    const emailInput = await findByLabelText("Email");
    const passwordInput = await findByLabelText("Password");
    const confirmInput = await findByLabelText("Confirm Password");

    await userEvent.type(emailInput, "user@example.com");
    await userEvent.type(passwordInput, "Secret123");
    await userEvent.type(confirmInput, "Secret123");

    confirmInput.focus();
    await userEvent.keyboard("{Enter}");

    await waitFor(() =>
      expect(userMocks.createUser).toHaveBeenCalledWith({
        email: "user@example.com",
        name: "",
        password: "Secret123",
        roles: [],
      }),
    );
    await waitFor(() => expect(routerMocks.navigate).toHaveBeenCalledWith("/users"));
  });

  it("cancels on Escape", async () => {
    render(UserEditorView);

    await userEvent.keyboard("{Escape}");

    expect(routerMocks.navigate).toHaveBeenCalledWith("/users");
  });

  it("does not render the add role field", async () => {
    const { queryByLabelText } = render(UserEditorView);

    await waitFor(() => expect(roleMocks.listRoles).toHaveBeenCalled());

    expect(queryByLabelText("Add Role")).toBeNull();
  });

  it("updates roles when editing an existing user", async () => {
    routerMocks.route.set({
      path: "/users/edit/editor@example.com",
      query: new URLSearchParams(),
      fullPath: "/admin/users/edit/editor@example.com",
    });
    roleMocks.listRoles.mockResolvedValueOnce(["editor", "viewer"]);
    userMocks.getUser.mockResolvedValueOnce({
      email: "editor@example.com",
      name: "Editor User",
      roles: ["editor"],
    });

    const { findByLabelText, getByRole } = render(UserEditorView);

    await waitFor(() => expect(userMocks.getUser).toHaveBeenCalledWith("editor@example.com"));

    const editorRole = await findByLabelText("editor");
    const viewerRole = await findByLabelText("viewer");

    expect(editorRole).toBeChecked();
    expect(viewerRole).not.toBeChecked();

    await userEvent.click(viewerRole);
    await userEvent.click(editorRole);

    await userEvent.click(getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(userMocks.addUserRole).toHaveBeenCalledWith("editor@example.com", "viewer"),
    );
    await waitFor(() =>
      expect(userMocks.removeUserRole).toHaveBeenCalledWith("editor@example.com", "editor"),
    );
    await waitFor(() => expect(routerMocks.navigate).toHaveBeenCalledWith("/users"));
  });
});
