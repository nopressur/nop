// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, render } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";
import Input from "./Input.svelte";

describe("Input", () => {
  afterEach(() => {
    cleanup();
  });

  it("renders an error state with helper text", () => {
    const { getByRole, getByText } = render(Input, {
      props: {
        id: "alias",
        value: "",
        error: "Alias is invalid",
      },
    });

    const input = getByRole("textbox");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-describedby", "alias-error");
    expect(input.className).toContain("border-danger");
    expect(getByText("Alias is invalid")).toBeInTheDocument();
  });

  it("does not reserve suffix padding without a suffix control", () => {
    const { getByRole } = render(Input, {
      props: {
        id: "title",
        value: "Page",
      },
    });

    expect(getByRole("textbox").className).not.toContain("pr-9");
  });
});
