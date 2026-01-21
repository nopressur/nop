// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, render } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import ConfirmModal from "./ConfirmModal.svelte";
import { confirmDialog } from "../stores/confirmDialog";

describe("ConfirmModal", () => {
  afterEach(() => {
    cleanup();
  });

  it("resolves true on Enter", async () => {
    const { findByRole, queryByRole } = render(ConfirmModal);
    const result = confirmDialog({ message: "Confirm action" });

    const dialog = await findByRole("dialog", { name: "Confirm" });
    dialog.focus();
    await userEvent.keyboard("{Enter}");

    await expect(result).resolves.toBe(true);
    expect(queryByRole("dialog", { name: "Confirm" })).not.toBeInTheDocument();
  });

  it("resolves false on Escape", async () => {
    const { findByRole, queryByRole } = render(ConfirmModal);
    const result = confirmDialog({ message: "Confirm action" });

    const dialog = await findByRole("dialog", { name: "Confirm" });
    dialog.focus();
    await userEvent.keyboard("{Escape}");

    await expect(result).resolves.toBe(false);
    expect(queryByRole("dialog", { name: "Confirm" })).not.toBeInTheDocument();
  });
});
