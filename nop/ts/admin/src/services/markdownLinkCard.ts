// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type MarkdownLinkCardConversion = {
  startOffset: number;
  endOffset: number;
  shortcode: string;
  cursorOffset: number;
  title: string;
  link: string;
};

type ParsedMarkdownLink = {
  startOffset: number;
  endOffset: number;
  label: string;
  destination: string;
};

export function convertMarkdownLinkToLinkCard(
  content: string,
  selectionStartOffset: number,
  selectionEndOffset: number,
): MarkdownLinkCardConversion | null {
  const normalizedStart = clampOffset(
    Math.min(selectionStartOffset, selectionEndOffset),
    content,
  );
  const normalizedEnd = clampOffset(
    Math.max(selectionStartOffset, selectionEndOffset),
    content,
  );
  const link = normalizedStart === normalizedEnd
    ? findLinkAtOffset(content, normalizedStart)
    : findSelectedLink(content, normalizedStart, normalizedEnd);
  if (!link) {
    return null;
  }

  const title = link.label.trim() || link.destination;
  const shortcode = `((link-card title=${JSON.stringify(title)} link=${JSON.stringify(
    link.destination,
  )} noblank))`;
  return {
    startOffset: link.startOffset,
    endOffset: link.endOffset,
    shortcode,
    cursorOffset: link.startOffset + shortcode.length,
    title,
    link: link.destination,
  };
}

function clampOffset(offset: number, content: string): number {
  if (!Number.isFinite(offset)) {
    return 0;
  }
  return Math.min(Math.max(Math.trunc(offset), 0), content.length);
}

function findSelectedLink(
  content: string,
  selectionStartOffset: number,
  selectionEndOffset: number,
): ParsedMarkdownLink | null {
  const selected = content.slice(selectionStartOffset, selectionEndOffset);
  const leading = selected.match(/^\s*/)?.[0].length ?? 0;
  const trailing = selected.match(/\s*$/)?.[0].length ?? 0;
  const startOffset = selectionStartOffset + leading;
  const endOffset = selectionEndOffset - trailing;
  if (startOffset >= endOffset) {
    return null;
  }

  const link = parseMarkdownLinkAt(content, startOffset);
  return link && link.endOffset === endOffset ? link : null;
}

function findLinkAtOffset(content: string, offset: number): ParsedMarkdownLink | null {
  let searchOffset = 0;
  while (searchOffset < content.length) {
    const startOffset = content.indexOf("[", searchOffset);
    if (startOffset === -1) {
      return null;
    }
    const link = parseMarkdownLinkAt(content, startOffset);
    if (link && link.startOffset <= offset && offset <= link.endOffset) {
      return link;
    }
    searchOffset = startOffset + 1;
  }
  return null;
}

function parseMarkdownLinkAt(
  content: string,
  startOffset: number,
): ParsedMarkdownLink | null {
  if (
    !content.startsWith("[", startOffset) ||
    isEscaped(content, startOffset) ||
    isImageMarker(content, startOffset)
  ) {
    return null;
  }

  const labelEndOffset = findClosingLabelOffset(content, startOffset + 1);
  if (labelEndOffset === -1 || content[labelEndOffset + 1] !== "(") {
    return null;
  }

  const destinationStartOffset = labelEndOffset + 2;
  const destinationEndOffset = findClosingDestinationOffset(content, destinationStartOffset);
  if (destinationEndOffset === -1) {
    return null;
  }

  const label = unescapeMarkdown(content.slice(startOffset + 1, labelEndOffset));
  const destination = extractInlineDestination(
    content.slice(destinationStartOffset, destinationEndOffset),
  );
  if (!destination) {
    return null;
  }

  return {
    startOffset,
    endOffset: destinationEndOffset + 1,
    label,
    destination,
  };
}

function findClosingLabelOffset(content: string, startOffset: number): number {
  let depth = 0;
  for (let index = startOffset; index < content.length; index += 1) {
    const char = content[index];
    if (char === "\\") {
      index += 1;
      continue;
    }
    if (char === "[") {
      depth += 1;
      continue;
    }
    if (char === "]") {
      if (depth === 0) {
        return index;
      }
      depth -= 1;
    }
  }
  return -1;
}

function findClosingDestinationOffset(content: string, startOffset: number): number {
  let depth = 0;
  let quote: string | null = null;
  let inAngle = false;
  for (let index = startOffset; index < content.length; index += 1) {
    const char = content[index];
    if (char === "\\") {
      index += 1;
      continue;
    }
    if (inAngle) {
      if (char === ">") {
        inAngle = false;
      }
      continue;
    }
    if (quote) {
      if (char === quote) {
        quote = null;
      }
      continue;
    }
    if (char === "<") {
      inAngle = true;
      continue;
    }
    if (char === "\"" || char === "'") {
      quote = char;
      continue;
    }
    if (char === "(") {
      depth += 1;
      continue;
    }
    if (char === ")") {
      if (depth === 0) {
        return index;
      }
      depth -= 1;
    }
  }
  return -1;
}

function extractInlineDestination(rawPayload: string): string | null {
  const payload = rawPayload.trim();
  if (!payload) {
    return null;
  }
  if (payload.startsWith("<")) {
    const closingOffset = findClosingAngleOffset(payload);
    if (closingOffset <= 1) {
      return null;
    }
    return unescapeMarkdown(payload.slice(1, closingOffset));
  }

  let depth = 0;
  let destinationEnd = payload.length;
  for (let index = 0; index < payload.length; index += 1) {
    const char = payload[index];
    if (char === "\\") {
      index += 1;
      continue;
    }
    if (char === "(") {
      depth += 1;
      continue;
    }
    if (char === ")") {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (/\s/.test(char) && depth === 0) {
      destinationEnd = index;
      break;
    }
  }

  const destination = payload.slice(0, destinationEnd);
  return destination.trim() ? unescapeMarkdown(destination.trim()) : null;
}

function findClosingAngleOffset(payload: string): number {
  for (let index = 1; index < payload.length; index += 1) {
    const char = payload[index];
    if (char === "\\") {
      index += 1;
      continue;
    }
    if (char === ">") {
      return index;
    }
  }
  return -1;
}

function isImageMarker(content: string, offset: number): boolean {
  return offset > 0 && content[offset - 1] === "!" && !isEscaped(content, offset - 1);
}

function isEscaped(content: string, offset: number): boolean {
  let slashCount = 0;
  for (let index = offset - 1; index >= 0 && content[index] === "\\"; index -= 1) {
    slashCount += 1;
  }
  return slashCount % 2 === 1;
}

function unescapeMarkdown(value: string): string {
  return value.replace(/\\([!"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])/g, "$1");
}
