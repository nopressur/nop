// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import SettingsView from "./SettingsView.svelte";

const settingsMocks = vi.hoisted(() => ({
  fetchSettings: vi.fn(),
  updateWebsiteName: vi.fn(),
  updateWebsiteTitle: vi.fn(),
  updateWebsiteDescription: vi.fn(),
}));

const notificationMocks = vi.hoisted(() => ({
  pushNotification: vi.fn(),
}));

vi.mock("../services/settings", () => ({
  fetchSettings: settingsMocks.fetchSettings,
  updateWebsiteName: settingsMocks.updateWebsiteName,
  updateWebsiteTitle: settingsMocks.updateWebsiteTitle,
  updateWebsiteDescription: settingsMocks.updateWebsiteDescription,
}));

vi.mock("../stores/notifications", () => ({
  pushNotification: notificationMocks.pushNotification,
}));

describe("SettingsView", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    settingsMocks.fetchSettings.mockResolvedValue({
      name: "Example",
      title: "Example Site",
      description: "Example description",
    });
    settingsMocks.updateWebsiteName.mockResolvedValue({
      name: "Updated Name",
      title: "Example Site",
      description: "Example description",
    });
    settingsMocks.updateWebsiteTitle.mockResolvedValue({
      name: "Example",
      title: "Updated Site",
      description: "Example description",
    });
    settingsMocks.updateWebsiteDescription.mockResolvedValue({
      name: "Example",
      title: "Example Site",
      description: "Updated description",
    });
  });

  it("loads website settings", async () => {
    const { findByLabelText } = render(SettingsView);

    const name = (await findByLabelText("Website Name")) as HTMLInputElement;
    const input = (await findByLabelText("Website Title")) as HTMLInputElement;
    const description = (await findByLabelText("Website Description")) as HTMLInputElement;
    expect(name.value).toBe("Example");
    expect(input.value).toBe("Example Site");
    expect(description.value).toBe("Example description");
  });

  it("saves a changed Website Title", async () => {
    const { findByLabelText, getByText } = render(SettingsView);
    const input = (await findByLabelText("Website Title")) as HTMLInputElement;

    await userEvent.clear(input);
    await userEvent.type(input, "  Updated Site  ");
    await userEvent.click(getByText("Save"));

    await waitFor(() =>
    expect(settingsMocks.updateWebsiteTitle).toHaveBeenCalledWith("Updated Site"),
    );
    expect(notificationMocks.pushNotification).toHaveBeenCalledWith(
      "Website settings updated",
      "success",
    );
  });

  it("cancels Website Title edits", async () => {
    const { findByLabelText, getByText } = render(SettingsView);
    const input = (await findByLabelText("Website Title")) as HTMLInputElement;

    await userEvent.clear(input);
    await userEvent.type(input, "Draft");
    await userEvent.click(getByText("Cancel"));

    expect(input.value).toBe("Example Site");
    expect(settingsMocks.updateWebsiteTitle).not.toHaveBeenCalled();
  });

  it("validates Website Title length before saving", async () => {
    const { findByLabelText, findByText, getByText } = render(SettingsView);
    const input = (await findByLabelText("Website Title")) as HTMLInputElement;

    await userEvent.clear(input);
    await userEvent.type(input, "x".repeat(121));

    expect(await findByText("Website Title must be at most 120 characters")).toBeInTheDocument();
    expect(getByText("Save")).toBeDisabled();
  });
});
