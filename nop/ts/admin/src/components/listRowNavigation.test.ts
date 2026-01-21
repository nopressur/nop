// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { get } from "svelte/store";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createListRowNavigation } from "./listRowNavigation";

type ListFixture = {
  list: HTMLTableSectionElement;
  rows: HTMLTableRowElement[];
  actionButton: HTMLButtonElement;
};

function buildList(count: number): ListFixture {
  const list = document.createElement("tbody");
  const rows: HTMLTableRowElement[] = [];
  let actionButton = document.createElement("button");

  for (let index = 0; index < count; index += 1) {
    const row = document.createElement("tr");
    row.dataset.rowIndex = String(index);
    row.tabIndex = -1;
    const cell = document.createElement("td");
    cell.textContent = `Row ${index}`;
    row.appendChild(cell);
    const actionCell = document.createElement("td");
    actionCell.dataset.rowActions = "true";
    actionButton = document.createElement("button");
    actionButton.type = "button";
    actionButton.textContent = "Action";
    actionCell.appendChild(actionButton);
    row.appendChild(actionCell);
    list.appendChild(row);
    rows.push(row);
  }

  document.body.appendChild(list);

  return { list, rows, actionButton };
}

function createKeydown(key: string): KeyboardEvent {
  return new KeyboardEvent("keydown", { key, bubbles: true });
}

it("clamps selection when items are empty", () => {
  const nav = createListRowNavigation({ onOpen: vi.fn() });
  nav.setItemCount(0);
  expect(get(nav.selectedIndex)).toBe(-1);
});

describe("createListRowNavigation", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("moves selection with arrows and opens on Enter", () => {
    const onOpen = vi.fn();
    const nav = createListRowNavigation({ onOpen });
    const { list, rows } = buildList(3);
    nav.setListRef(list);
    nav.setItemCount(3);
    list.addEventListener("keydown", nav.handleKeydown);

    rows[0].dispatchEvent(createKeydown("ArrowDown"));
    expect(get(nav.selectedIndex)).toBe(1);
    expect(document.activeElement).toBe(rows[1]);

    rows[1].dispatchEvent(createKeydown("Enter"));
    expect(onOpen).toHaveBeenCalledWith(1);
  });

  it("ignores keydown events originating from the action cell", () => {
    const onOpen = vi.fn();
    const nav = createListRowNavigation({ onOpen });
    const { list, rows, actionButton } = buildList(2);
    nav.setListRef(list);
    nav.setItemCount(2);
    list.addEventListener("keydown", nav.handleKeydown);

    actionButton.dispatchEvent(createKeydown("ArrowDown"));
    expect(get(nav.selectedIndex)).toBe(0);
    expect(document.activeElement).not.toBe(rows[1]);
    expect(onOpen).not.toHaveBeenCalled();
  });
});
