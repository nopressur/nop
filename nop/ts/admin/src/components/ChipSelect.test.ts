// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { cleanup, fireEvent, render, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import ChipSelect from "./ChipSelect.svelte";
import {
  filterChips,
  fitChipCount,
  fitsSingleRow,
  sortAlphabetical,
  topChips,
  unselectedOptions,
} from "./chipSelect";

type Layout = {
  clientWidth?: number;
  scrollWidth?: number;
  offsetWidth?: number;
};

const originalDescriptors = {
  clientWidth: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientWidth"),
  scrollWidth: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollWidth"),
  offsetWidth: Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth"),
};

// jsdom reports zero sizes, so layout-dependent branches are driven by stubbing
// the measurement getters before render.
function mockLayout({ clientWidth = 0, scrollWidth = 0, offsetWidth = 0 }: Layout): void {
  Object.defineProperty(HTMLElement.prototype, "clientWidth", {
    configurable: true,
    get: () => clientWidth,
  });
  Object.defineProperty(HTMLElement.prototype, "scrollWidth", {
    configurable: true,
    get: () => scrollWidth,
  });
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
    configurable: true,
    get: () => offsetWidth,
  });
}

afterEach(() => {
  cleanup();
  for (const [key, descriptor] of Object.entries(originalDescriptors)) {
    if (descriptor) {
      Object.defineProperty(HTMLElement.prototype, key, descriptor);
    }
  }
  vi.restoreAllMocks();
});

function addButtonNames(container: HTMLElement): string[] {
  return Array.from(
    container.querySelectorAll('button[aria-label^="Add "]'),
  ).map((button) => button.getAttribute("aria-label") ?? "");
}

describe("ChipSelect", () => {
  it("collapses to a single row with no filter when everything fits", async () => {
    mockLayout({ clientWidth: 500, scrollWidth: 200, offsetWidth: 40 });
    const { container, queryByRole } = render(ChipSelect, {
      props: {
        options: ["b", "a", "c"],
        selected: [],
        counts: { a: 1, b: 2, c: 3 },
        emptyLabel: "No tags",
      },
    });

    await waitFor(() => {
      expect(container.querySelectorAll('button[aria-label^="Add "]')).toHaveLength(3);
    });
    expect(addButtonNames(container)).toEqual(["Add a", "Add b", "Add c"]);
    expect(queryByRole("textbox")).toBeNull();
  });

  it("expands to filter plus top and alphabetical rows on overflow", async () => {
    mockLayout({ clientWidth: 200, scrollWidth: 600, offsetWidth: 40 });
    const { container, findByPlaceholderText, findAllByRole } = render(ChipSelect, {
      props: {
        options: ["a", "b", "c", "d"],
        selected: [],
        counts: { b: 5, a: 2 },
        placeholder: "Filter tags",
      },
    });

    await findByPlaceholderText("Filter tags");
    // Top-row candidates render twice (top row plus alphabetical row).
    expect(addButtonNames(container).filter((name) => name === "Add b")).toHaveLength(2);
    expect(addButtonNames(container).filter((name) => name === "Add c")).toHaveLength(1);
    expect(await findAllByRole("button", { name: /^Add / })).toHaveLength(6);
    const root = container.querySelector("div.relative");
    const alphaRow = container.querySelector("div.overflow-x-auto");
    expect(root?.className).toContain("min-w-0");
    expect(root?.className).toContain("w-full");
    expect(alphaRow?.className).toContain("min-w-0");
    expect(alphaRow?.className).toContain("w-full");
  });

  it("orders top chips by usage before the alphabetical row", async () => {
    mockLayout({ clientWidth: 200, scrollWidth: 600, offsetWidth: 40 });
    const { container, findByPlaceholderText } = render(ChipSelect, {
      props: {
        options: ["a", "b", "c"],
        selected: [],
        counts: { c: 9, a: 1 },
      },
    });

    await findByPlaceholderText("Filter");
    // Top row first (c, a by usage), then the alphabetical row (a, b, c).
    expect(addButtonNames(container)).toEqual([
      "Add c",
      "Add a",
      "Add a",
      "Add b",
      "Add c",
    ]);
  });

  it("shows no top row when no top chip fits", async () => {
    mockLayout({ clientWidth: 300, scrollWidth: 600, offsetWidth: 200 });
    const { container, findByPlaceholderText } = render(ChipSelect, {
      props: {
        options: ["a", "b"],
        selected: [],
        counts: { a: 4, b: 3 },
      },
    });

    await findByPlaceholderText("Filter");
    await waitFor(() => {
      expect(container.querySelectorAll('button[aria-label^="Add "]')).toHaveLength(2);
    });
    expect(addButtonNames(container)).toEqual(["Add a", "Add b"]);
  });

  it("narrows the list while filtering and keeps the filter on select", async () => {
    const user = userEvent.setup();
    mockLayout({ clientWidth: 200, scrollWidth: 600, offsetWidth: 40 });
    const { findByPlaceholderText, findAllByRole, getByRole, queryByRole } = render(ChipSelect, {
      props: {
        options: ["a", "b", "c", "d"],
        selected: [],
        counts: { b: 5 },
      },
    });

    const filter = (await findByPlaceholderText("Filter")) as HTMLInputElement;
    await user.type(filter, "b");
    // Top row hides while filtering: the single match renders once.
    expect(await findAllByRole("button", { name: /^Add / })).toHaveLength(1);

    await user.click(getByRole("button", { name: "Add b" }));
    expect(getByRole("button", { name: "Remove b" })).toBeInTheDocument();
    expect(filter.value).toBe("b");
    expect(queryByRole("button", { name: "Add b" })).toBeNull();
  });

  it("clears the filter with the clear button", async () => {
    const user = userEvent.setup();
    mockLayout({ clientWidth: 200, scrollWidth: 600, offsetWidth: 40 });
    const { findByPlaceholderText, findAllByRole, getByRole } = render(ChipSelect, {
      props: {
        options: ["a", "b"],
        selected: [],
      },
    });

    const filter = (await findByPlaceholderText("Filter")) as HTMLInputElement;
    await user.type(filter, "a");
    expect(await findAllByRole("button", { name: /^Add / })).toHaveLength(1);

    await user.click(getByRole("button", { name: "Clear search" }));
    expect(filter.value).toBe("");
    expect(await findAllByRole("button", { name: /^Add / })).toHaveLength(2);
  });

  it("preselects the filter text on focus", async () => {
    const selectSpy = vi.spyOn(window.HTMLInputElement.prototype, "select");
    mockLayout({ clientWidth: 200, scrollWidth: 600, offsetWidth: 40 });
    const { findByPlaceholderText } = render(ChipSelect, {
      props: {
        options: ["a", "b"],
        selected: [],
      },
    });

    const filter = await findByPlaceholderText("Filter");
    await fireEvent.focus(filter);
    expect(selectSpy).toHaveBeenCalled();
  });

  it("renders alphabetical only without counts", async () => {
    mockLayout({ clientWidth: 200, scrollWidth: 600, offsetWidth: 40 });
    const { container, findByPlaceholderText, findAllByRole } = render(ChipSelect, {
      props: {
        options: ["b", "a"],
        selected: [],
      },
    });

    await findByPlaceholderText("Filter");
    expect(await findAllByRole("button", { name: /^Add / })).toHaveLength(2);
    expect(addButtonNames(container)).toEqual(["Add a", "Add b"]);
  });

  it("renders active chips green with working remove buttons", async () => {
    mockLayout({ clientWidth: 500, scrollWidth: 200, offsetWidth: 40 });
    const { getByRole, queryByRole } = render(ChipSelect, {
      props: {
        options: ["a", "b"],
        selected: ["a"],
      },
    });

    const remove = getByRole("button", { name: "Remove a" });
    expect(remove.closest("span")).toHaveClass("border-success");
    await fireEvent.click(remove);
    expect(queryByRole("button", { name: "Remove a" })).toBeNull();
  });

  it("renders the empty label with no options", () => {
    const { getByText, queryByRole } = render(ChipSelect, {
      props: {
        options: [],
        selected: [],
        emptyLabel: "No roles",
      },
    });

    expect(getByText("No roles")).toBeInTheDocument();
    expect(queryByRole("textbox")).toBeNull();
    expect(queryByRole("button")).toBeNull();
  });

  describe("chipSelect helpers", () => {
    it("sorts alphabetically without mutating", () => {
      const input = ["updates", "docs", "news"];
      expect(sortAlphabetical(input)).toEqual(["docs", "news", "updates"]);
      expect(input).toEqual(["updates", "docs", "news"]);
    });

    it("excludes selected options", () => {
      expect(unselectedOptions(["a", "b", "c"], ["b"])).toEqual(["a", "c"]);
    });

    it("filters by case-sensitive substring anywhere in the option", () => {
      const options = ["News", "newsletter", "updates", "docs"];
      expect(filterChips(options, [], "News")).toEqual(["News"]);
      expect(filterChips(options, [], "news")).toEqual(["newsletter"]);
      expect(filterChips(options, [], "e")).toEqual(["News", "newsletter", "updates"]);
    });

    it("returns the alphabetical unselected list for an empty filter", () => {
      expect(filterChips(["b", "a", "c"], ["c"], "")).toEqual(["a", "b"]);
    });

    it("ranks top chips by count then alphabetically and skips unused", () => {
      const options = ["b", "a", "c", "d"];
      const counts = { a: 2, b: 5, c: 0 };
      expect(topChips(options, [], counts)).toEqual(["b", "a"]);
    });

    it("breaks count ties alphabetically and excludes selected", () => {
      const options = ["b", "a", "c"];
      const counts = { a: 3, b: 3, c: 3 };
      expect(topChips(options, ["a"], counts)).toEqual(["b", "c"]);
    });

    it("returns no top chips without counts", () => {
      expect(topChips(["a", "b"], [], undefined)).toEqual([]);
    });

    it("counts whole chips that fit including gaps", () => {
      // Each chip costs width + 8 gap: 68, 136, 204 > 150 stops at two.
      expect(fitChipCount(150, [60, 60, 60], 8)).toBe(2);
      expect(fitChipCount(136, [60, 60, 60], 8)).toBe(2);
      expect(fitChipCount(67, [60, 60], 8)).toBe(0);
      expect(fitChipCount(500, [60, 60], 8)).toBe(2);
    });

    it("shows all chips when widths are unmeasurable", () => {
      expect(fitChipCount(0, [60, 60], 8)).toBe(2);
      expect(fitChipCount(-10, [60, 60], 8)).toBe(2);
      expect(fitChipCount(150, [0, 0], 8)).toBe(2);
      expect(fitChipCount(150, [], 8)).toBe(0);
    });

    it("detects single-row fit from container and content widths", () => {
      expect(fitsSingleRow(500, 200)).toBe(true);
      expect(fitsSingleRow(200, 200)).toBe(true);
      expect(fitsSingleRow(200, 500)).toBe(false);
    });

    it("reports a fit when widths are unmeasurable", () => {
      expect(fitsSingleRow(0, 0)).toBe(true);
      expect(fitsSingleRow(200, 0)).toBe(true);
    });
  });

  it("disables the filter and chips when disabled", async () => {
    mockLayout({ clientWidth: 200, scrollWidth: 600, offsetWidth: 40 });
    const { findByPlaceholderText, findAllByRole } = render(ChipSelect, {
      props: {
        options: ["a", "b"],
        selected: ["a"],
        disabled: true,
      },
    });

    expect(await findByPlaceholderText("Filter")).toBeDisabled();
    for (const chip of await findAllByRole("button")) {
      expect(chip).toBeDisabled();
    }
  });
});
