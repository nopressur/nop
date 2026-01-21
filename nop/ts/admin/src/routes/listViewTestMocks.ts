// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { vi } from "vitest";

vi.mock("../stores/router", () => ({
  navigate: vi.fn(),
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: vi.fn(),
}));

import { navigate } from "../stores/router";
import { pushNotification } from "../stores/notifications";

export const routerMocks = {
  navigate: vi.mocked(navigate),
};

export const notificationMocks = {
  pushNotification: vi.mocked(pushNotification),
};
