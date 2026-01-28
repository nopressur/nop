// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../stores/router", () => ({
  navigate: vi.fn()
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn()
}));

import { navigate } from "../stores/router";
import { pushNotification } from "../stores/notifications";
import { enforceAdminRoute, getAdminRouteOutcome } from "./routeValidation";

const navigateMock = vi.mocked(navigate);
const notifyMock = vi.mocked(pushNotification);

describe("admin route validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("flags invalid admin routes", () => {
    expect(getAdminRouteOutcome("/pages/index.md", true)).toBe("invalid");
    expect(getAdminRouteOutcome("/pages/edit/abc", true)).toBe("valid");
  });

  it("redirects and notifies on invalid routes", () => {
    enforceAdminRoute("/pages/index.md", true);
    expect(notifyMock).toHaveBeenCalledWith(
      "Invalid admin URL.",
      "info"
    );
    expect(navigateMock).toHaveBeenCalledWith("/pages", true);
  });

  it("redirects users when user management is disabled", () => {
    enforceAdminRoute("/users", false);
    expect(notifyMock).not.toHaveBeenCalled();
    expect(navigateMock).toHaveBeenCalledWith("/pages", true);
  });

  it("does nothing for valid routes", () => {
    enforceAdminRoute("/themes/new", true);
    expect(notifyMock).not.toHaveBeenCalled();
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
