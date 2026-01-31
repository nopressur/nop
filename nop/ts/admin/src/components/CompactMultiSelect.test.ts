// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { render } from "@testing-library/svelte";
import { tick } from "svelte";
import { describe, expect, it } from "vitest";
import CompactMultiSelect from "./CompactMultiSelect.svelte";

describe("CompactMultiSelect", () => {
  it("defers pruning until options are ready", async () => {
    const { rerender, getByText, queryByRole } = render(CompactMultiSelect, {
      props: {
        options: [],
        selected: ["tag-one"],
        optionsReady: false,
      },
    });

    expect(getByText("tag-one")).toBeInTheDocument();
    expect(queryByRole("button", { name: "Clear tags" })).toBeInTheDocument();

    await rerender({
      optionsReady: true,
      options: ["tag-two"],
    });
    await tick();

    expect(getByText("All tags")).toBeInTheDocument();
    expect(queryByRole("button", { name: "Clear tags" })).toBeNull();
  });
});
