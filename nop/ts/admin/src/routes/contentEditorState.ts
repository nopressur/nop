// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type ContentEditorSnapshot = {
  alias: string;
  title: string;
  tags: string[];
  navTitle: string;
  navParentId: string;
  navOrder: string;
  theme: string;
  content: string;
};

type ContentEditorInput = {
  alias: string;
  title: string;
  selectedTags: string[];
  navTitle: string;
  navParentId: string;
  navOrder: string | number | null | undefined;
  theme: string;
  contentValue: string;
  isMarkdown: boolean;
};

export function normalizeTagList(tags: string[]): string[] {
  return [...tags]
    .map((tag) => tag.trim())
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));
}

export function normalizeNavOrderValue(value: string | number | null | undefined): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return "";
    }
    return value.toString();
  }
  return value;
}

export function buildEditorSnapshot(input: ContentEditorInput): ContentEditorSnapshot {
  return {
    alias: input.alias,
    title: input.title,
    tags: normalizeTagList(input.selectedTags),
    navTitle: input.navTitle.trim(),
    navParentId: input.navParentId.trim(),
    navOrder: normalizeNavOrderValue(input.navOrder).trim(),
    theme: input.theme,
    content: input.isMarkdown ? input.contentValue : "",
  };
}

export function isEditorDirty(
  initial: ContentEditorSnapshot,
  current: ContentEditorSnapshot,
): boolean {
  if (initial.alias !== current.alias) {
    return true;
  }
  if (initial.title !== current.title) {
    return true;
  }
  if (initial.navTitle !== current.navTitle) {
    return true;
  }
  if (initial.navParentId !== current.navParentId) {
    return true;
  }
  if (initial.navOrder !== current.navOrder) {
    return true;
  }
  if (initial.theme !== current.theme) {
    return true;
  }
  if (initial.tags.length !== current.tags.length) {
    return true;
  }
  for (let i = 0; i < current.tags.length; i += 1) {
    if (initial.tags[i] !== current.tags[i]) {
      return true;
    }
  }
  if (initial.content !== current.content) {
    return true;
  }
  return false;
}
