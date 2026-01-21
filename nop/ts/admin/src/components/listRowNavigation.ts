// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { get, writable } from "svelte/store";

type ListRowNavigationOptions = {
  onOpen: (index: number) => void;
  initialIndex?: number;
  rowSelector?: string;
  actionSelector?: string;
};

type ListRowNavigation = {
  selectedIndex: ReturnType<typeof writable<number>>;
  setItemCount: (count: number) => void;
  setListRef: (node: HTMLElement | null) => void;
  handleKeydown: (event: KeyboardEvent) => void;
  handleRowClick: (index: number) => void;
  handleRowFocus: (index: number) => void;
};

const DEFAULT_ROW_SELECTOR = "[data-row-index]";
const DEFAULT_ACTION_SELECTOR = "[data-row-actions]";

export function createListRowNavigation(
  options: ListRowNavigationOptions,
): ListRowNavigation {
  const selectedIndex = writable(options.initialIndex ?? 0);
  const rowSelector = options.rowSelector ?? DEFAULT_ROW_SELECTOR;
  const actionSelector = options.actionSelector ?? DEFAULT_ACTION_SELECTOR;

  let itemCount = 0;
  let listRef: HTMLElement | null = null;

  function clampIndex(index: number): number {
    if (itemCount <= 0) {
      return -1;
    }
    return Math.max(0, Math.min(itemCount - 1, index));
  }

  function findRow(index: number): HTMLElement | null {
    if (!listRef || index < 0) {
      return null;
    }
    return listRef.querySelector(
      `${rowSelector}[data-row-index="${index}"]`,
    ) as HTMLElement | null;
  }

  function focusRow(index: number): void {
    const row = findRow(index);
    if (!row) {
      return;
    }
    row.focus();
    if (typeof row.scrollIntoView === "function") {
      row.scrollIntoView({ block: "nearest" });
    }
  }

  function setSelectedIndex(index: number, focus = false): void {
    const next = clampIndex(index);
    selectedIndex.set(next);
    if (focus && next >= 0) {
      focusRow(next);
    }
  }

  function setItemCount(count: number): void {
    itemCount = count;
    const current = get(selectedIndex);
    if (itemCount <= 0) {
      if (current !== -1) {
        selectedIndex.set(-1);
      }
      return;
    }
    const next = clampIndex(current < 0 ? 0 : current);
    if (next !== current) {
      selectedIndex.set(next);
    }
  }

  function setListRef(node: HTMLElement | null): void {
    listRef = node;
  }

  function isActionTarget(target: EventTarget | null): boolean {
    if (!(target instanceof HTMLElement)) {
      return false;
    }
    if (target.closest(actionSelector)) {
      return true;
    }
    return Boolean(
      target.closest(
        "button,a,input,select,textarea,[contenteditable='true']",
      ),
    );
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (itemCount <= 0 || isActionTarget(event.target)) {
      return;
    }
    const current = get(selectedIndex);
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setSelectedIndex(current + 1, true);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setSelectedIndex(current - 1, true);
    } else if (event.key === "Home") {
      event.preventDefault();
      setSelectedIndex(0, true);
    } else if (event.key === "End") {
      event.preventDefault();
      setSelectedIndex(itemCount - 1, true);
    } else if (event.key === "Enter") {
      if (current >= 0) {
        event.preventDefault();
        options.onOpen(current);
      }
    }
  }

  function handleRowClick(index: number): void {
    setSelectedIndex(index);
    options.onOpen(index);
  }

  function handleRowFocus(index: number): void {
    setSelectedIndex(index);
  }

  return {
    selectedIndex,
    setItemCount,
    setListRef,
    handleKeydown,
    handleRowClick,
    handleRowFocus,
  };
}
