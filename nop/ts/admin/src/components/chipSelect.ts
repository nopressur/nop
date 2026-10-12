// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

// Gap between chips in the ChipSelect rows. Must match the rendered `gap-2`.
export const CHIP_ROW_GAP_PX = 8;

export function sortAlphabetical(values: string[]): string[] {
  return [...values].sort((a, b) => a.localeCompare(b));
}

export function unselectedOptions(options: string[], selected: string[]): string[] {
  const chosen = new Set(selected);
  return options.filter((option) => !chosen.has(option));
}

export function filterChips(options: string[], selected: string[], filter: string): string[] {
  const unselected = unselectedOptions(options, selected);
  if (!filter) {
    return sortAlphabetical(unselected);
  }
  return sortAlphabetical(unselected.filter((option) => option.includes(filter)));
}

export function topChips(
  options: string[],
  selected: string[],
  counts: Record<string, number> | undefined,
): string[] {
  if (!counts) {
    return [];
  }
  return unselectedOptions(options, selected)
    .filter((option) => (counts[option] ?? 0) > 0)
    .sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0) || a.localeCompare(b));
}

// How many leading chips fit whole into the available width. Each chip costs
// its width plus one gap (the gap separating it from the previous item).
// Unmeasurable input (zero or non-finite widths, as in jsdom) shows all
// candidates: the fallback must never hide an option.
export function fitChipCount(
  availableWidth: number,
  chipWidths: number[],
  gap: number = CHIP_ROW_GAP_PX,
): number {
  if (chipWidths.length === 0) {
    return 0;
  }
  if (!Number.isFinite(availableWidth) || availableWidth <= 0) {
    return chipWidths.length;
  }
  let used = 0;
  let count = 0;
  for (const width of chipWidths) {
    if (!Number.isFinite(width) || width <= 0) {
      return chipWidths.length;
    }
    used += width + gap;
    if (used > availableWidth) {
      break;
    }
    count += 1;
  }
  return count;
}

// Whether scrolled content fits its container in one row. Unmeasurable input
// reports a fit so layout degrades to the simple single-row form.
export function fitsSingleRow(containerWidth: number, contentWidth: number): boolean {
  if (!Number.isFinite(containerWidth) || containerWidth <= 0) {
    return true;
  }
  if (!Number.isFinite(contentWidth) || contentWidth <= 0) {
    return true;
  }
  return contentWidth <= containerWidth;
}
