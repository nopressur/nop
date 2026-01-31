// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render } from "@testing-library/svelte";
import { tick } from "svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setAdminRuntimeConfig, clearAdminRuntimeConfig } from "../config/runtime";
import { contentEditorViewPagePath } from "../stores/contentEditorLink";

const routerMocks = vi.hoisted(() => {
  let value = {
    path: "/pages",
    query: new URLSearchParams(),
    fullPath: "/admin/pages",
  };
  const subscribers = new Set<(next: typeof value) => void>();
  const route = {
    subscribe(fn: (next: typeof value) => void) {
      fn(value);
      subscribers.add(fn);
      return () => subscribers.delete(fn);
    },
    set(next: typeof value) {
      value = next;
      subscribers.forEach((fn) => fn(value));
    },
  };
  return {
    route,
    navigate: vi.fn(),
    isActiveRoute: vi.fn(() => false),
  };
});

vi.mock("../stores/router", () => ({
  route: routerMocks.route,
  navigate: routerMocks.navigate,
  isActiveRoute: routerMocks.isActiveRoute,
}));

vi.mock("../routes/routeValidation", () => ({
  enforceAdminRoute: vi.fn(),
}));

vi.mock("../services/browser", () => ({
  addWindowListener: vi.fn(),
  removeWindowListener: vi.fn(),
}));

vi.mock("../components/NotificationToaster.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../components/ConfirmModal.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/ContentEditorView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/ContentListView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/RoleEditorView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/RoleListView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/TagEditorView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/TagListView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/ThemeEditorView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/ThemeListView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/UserEditorView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/UserListView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

vi.mock("../routes/SystemSettingsView.svelte", async () => ({
  default: (await import("../testing/StubView.svelte")).default,
}));

describe("App header view link", () => {
  beforeEach(() => {
    setAdminRuntimeConfig({
      adminPath: "/admin",
      appName: "NoPressure",
      csrfTokenPath: "/admin/csrf-token-api",
      wsPath: "/admin/ws",
      wsTicketPath: "/admin/ws-ticket",
      userManagementEnabled: true,
      passwordFrontEnd: {
        memoryKib: 65536,
        iterations: 3,
        parallelism: 1,
        outputLen: 32,
        saltLen: 16,
      },
    });
    contentEditorViewPagePath.set(null);
  });

  afterEach(() => {
    clearAdminRuntimeConfig();
    contentEditorViewPagePath.set(null);
  });

  it("shows View Site by default and switches to View Page when a path is set", async () => {
    const App = (await import("./App.svelte")).default;
    const { getByText, queryByText } = render(App);

    const viewSite = getByText("View Site");
    expect(viewSite.getAttribute("href")).toBe("/");

    contentEditorViewPagePath.set("/id/test-id");
    await tick();

    expect(queryByText("View Site")).toBeNull();
    const viewPage = getByText("View Page");
    expect(viewPage.getAttribute("href")).toBe("/id/test-id");
  });
});
