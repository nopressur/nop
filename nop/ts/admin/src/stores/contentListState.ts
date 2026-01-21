// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { writable } from "svelte/store";
import type {
  ContentSortDirection,
  ContentSortField,
} from "../protocol/content";

export type ContentListState = {
  query: string;
  page: number;
  pageSize: number;
  markdownOnly: boolean;
  tags: string[];
  sortField: ContentSortField;
  sortDirection: ContentSortDirection;
};

const defaultState: ContentListState = {
  query: "",
  page: 1,
  pageSize: 25,
  markdownOnly: false,
  tags: [],
  sortField: "title",
  sortDirection: "asc",
};

export const contentListState = writable<ContentListState>({ ...defaultState });

export function setContentListState(next: ContentListState): void {
  contentListState.set({ ...next });
}

export function resetContentListState(): void {
  contentListState.set({ ...defaultState });
}
