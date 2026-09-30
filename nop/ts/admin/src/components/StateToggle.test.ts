// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, fireEvent, render } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import StateToggle from "./StateToggle.svelte";

const options = [
  { value: "auto", label: "Auto Width", tone: "success" as const },
  { value: "wide", label: "Wide", tone: "warning" as const },
  { value: "narrow", label: "Narrow", tone: "danger" as const },
];

describe("StateToggle", () => {
  afterEach(() => {
    cleanup();
  });

  it("renders the selected label and tone", () => {
    const { getByRole } = render(StateToggle, {
      props: {
        value: "wide",
        options,
        ariaLabel: "Content width",
      },
    });

    const button = getByRole("button", { name: "Content width" });
    expect(button).toHaveTextContent("Wide");
    expect(button.className).toContain("border-warning");
    expect(button.className).toContain("text-warning");
    expect(button.className).not.toContain("bg-warning");
    expect(button.className).toContain("bg-transparent");
  });

  it("uses visible text as the accessible name when no aria label is supplied", () => {
    const { getByRole } = render(StateToggle, {
      props: {
        value: "auto",
        options,
      },
    });

    expect(getByRole("button", { name: "Auto Width" })).toBeInTheDocument();
  });

  it("cycles to the next option and emits the selected value", async () => {
    const handleChange = vi.fn();
    const { getByRole } = render(StateToggle, {
      props: {
        value: "auto",
        options,
        ariaLabel: "Content width",
      },
      events: {
        change: handleChange,
      },
    });

    await fireEvent.click(getByRole("button", { name: "Content width" }));

    expect(handleChange).toHaveBeenCalledTimes(1);
    expect(handleChange.mock.calls[0]?.[0].detail).toBe("wide");
  });

  it("does not emit while disabled", async () => {
    const handleChange = vi.fn();
    const { getByRole } = render(StateToggle, {
      props: {
        value: "auto",
        options,
        disabled: true,
        ariaLabel: "Content width",
      },
      events: {
        change: handleChange,
      },
    });

    await fireEvent.click(getByRole("button", { name: "Content width" }));

    expect(handleChange).not.toHaveBeenCalled();
  });
});
