// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type InsertTitleHeadingResult = {
  content: string;
  cursorOffset: number;
  replaced: boolean;
};

export function insertTitleAsPageHeading(
  content: string,
  title: string,
): InsertTitleHeadingResult {
  const trimmedTitle = title.trim();
  if (!trimmedTitle) {
    return { content, cursorOffset: 0, replaced: false };
  }

  const lines = content.split("\n");
  const firstContentIndex = firstContentfulIndex(lines);

  if (firstContentIndex !== -1 && isAtxH1(lines[firstContentIndex])) {
    const current = lines[firstContentIndex];
    const leading = current.slice(0, current.length - current.trimStart().length);
    lines[firstContentIndex] = `${leading}# ${trimmedTitle}`;
    const next = lines.join("\n");
    return {
      content: next,
      cursorOffset: cursorAtFirstBodyLine(next, firstContentIndex),
      replaced: true,
    };
  }

  const restStart =
    firstContentIndex === -1 ? content.length : lineStartOffset(lines, firstContentIndex);
  const rest = content.slice(restStart);
  const next = rest ? `# ${trimmedTitle}\n\n${rest}` : `# ${trimmedTitle}\n\n`;
  return {
    content: next,
    cursorOffset: cursorAtFirstBodyLine(next, 0),
    replaced: false,
  };
}

function isBlank(line: string): boolean {
  return line.trim() === "";
}

function firstContentfulIndex(lines: string[]): number {
  return lines.findIndex((line) => !isBlank(line));
}

function isAtxH1(line: string): boolean {
  const trimmed = line.trimStart();
  if (!trimmed.startsWith("#") || trimmed.startsWith("##")) {
    return false;
  }
  return trimmed.length === 1 || /[ \t]/.test(trimmed[1] ?? "");
}

function lineStartOffset(lines: string[], index: number): number {
  let offset = 0;
  for (let i = 0; i < index; i += 1) {
    offset += lines[i].length + 1;
  }
  return offset;
}

function cursorAtFirstBodyLine(content: string, headingIndex: number): number {
  const lines = content.split("\n");
  for (let i = headingIndex + 1; i < lines.length; i += 1) {
    if (!isBlank(lines[i])) {
      return lineStartOffset(lines, i);
    }
  }

  const headingStart = lineStartOffset(lines, headingIndex);
  const headingEnd = headingStart + (lines[headingIndex]?.length ?? 0);
  return Math.min(headingEnd + 2, content.length);
}
