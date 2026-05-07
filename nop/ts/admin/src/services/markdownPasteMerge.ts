// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

export type PasteMergeResult = {
  content: string;
  cursorOffset: number;
  existingReferenceCount: number;
  pastedReferenceCount: number;
};

type ParsedDocument = {
  body: string;
  trailingDefinitions: string;
  referenceNumbers: Set<number>;
};

type FenceState = {
  marker: "`" | "~";
  length: number;
} | null;

const REFERENCE_DEFINITION_PATTERN = /^([ \t]{0,3}\[)(\d+)(\]:[ \t]*.*)$/;
const REFERENCE_LABEL_PATTERN = /(\]\[)(\d+)(\])/g;
const FENCE_PATTERN = /^[ \t]{0,3}(`{3,}|~{3,})/;

export function pasteMergeMarkdown(existing: string, pasted: string): PasteMergeResult {
  const existingDocument = parseDocument(existing);
  const pastedDocument = parseDocument(pasted);
  const nextReferenceNumber = getNextReferenceNumber(existingDocument.referenceNumbers);
  const labelMap = buildPastedReferenceMap(pastedDocument, nextReferenceNumber);
  const mergedPastedBody = rewriteReferences(pastedDocument.body, labelMap);
  const mergedPastedDefinitions = rewriteReferences(pastedDocument.trailingDefinitions, labelMap);
  const content = composeMergedMarkdown(
    existingDocument.body,
    mergedPastedBody,
    existingDocument.trailingDefinitions,
    mergedPastedDefinitions,
  );
  const cursorOffset = getCursorOffset(content, existingDocument.body, mergedPastedBody);

  return {
    content,
    cursorOffset,
    existingReferenceCount: existingDocument.referenceNumbers.size,
    pastedReferenceCount: labelMap.size,
  };
}

function normalizeMarkdown(value: string): string {
  return value.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
}

function parseDocument(value: string): ParsedDocument {
  const normalized = normalizeMarkdown(value);
  const referenceNumbers = collectReferenceNumbers(normalized);
  const split = splitTrailingDefinitions(normalized);
  return {
    body: split.body,
    trailingDefinitions: split.trailingDefinitions,
    referenceNumbers,
  };
}

function collectReferenceNumbers(value: string): Set<number> {
  const referenceNumbers = new Set<number>();
  forEachMarkdownLine(value, (line) => {
    const definitionMatch = REFERENCE_DEFINITION_PATTERN.exec(line);
    if (definitionMatch) {
      referenceNumbers.add(Number(definitionMatch[2]));
    }
    for (const match of line.matchAll(REFERENCE_LABEL_PATTERN)) {
      referenceNumbers.add(Number(match[2]));
    }
  });
  return referenceNumbers;
}

function splitTrailingDefinitions(value: string): { body: string; trailingDefinitions: string } {
  const trimmed = trimTrailingBlankLines(value);
  if (!trimmed) {
    return { body: "", trailingDefinitions: "" };
  }

  const lines = trimmed.split("\n");
  const codeLines = buildFencedCodeLineMap(lines);
  let index = lines.length - 1;

  while (index >= 0 && lines[index].trim() === "") {
    index -= 1;
  }

  const definitionEnd = index;
  let definitionStart = definitionEnd + 1;
  let seenDefinition = false;
  while (
    index >= 0 && !codeLines[index]
  ) {
    if (REFERENCE_DEFINITION_PATTERN.test(lines[index])) {
      seenDefinition = true;
      definitionStart = index;
      index -= 1;
      continue;
    }
    if (seenDefinition && lines[index].trim() === "" && hasReferenceDefinitionBefore(lines, codeLines, index)) {
      definitionStart = index;
      index -= 1;
      continue;
    }
    break;
  }

  if (!seenDefinition) {
    return { body: trimmed, trailingDefinitions: "" };
  }

  while (definitionStart <= definitionEnd && lines[definitionStart].trim() === "") {
    definitionStart += 1;
  }

  if (definitionStart > definitionEnd) {
    return { body: trimmed, trailingDefinitions: "" };
  }

  return {
    body: trimTrailingBlankLines(lines.slice(0, definitionStart).join("\n")),
    trailingDefinitions: lines.slice(definitionStart, definitionEnd + 1).join("\n"),
  };
}

function hasReferenceDefinitionBefore(lines: string[], codeLines: boolean[], startIndex: number): boolean {
  let index = startIndex - 1;
  while (index >= 0 && lines[index].trim() === "") {
    index -= 1;
  }
  return index >= 0 && !codeLines[index] && REFERENCE_DEFINITION_PATTERN.test(lines[index]);
}

function buildPastedReferenceMap(
  pastedDocument: ParsedDocument,
  nextReferenceNumber: number,
): Map<number, number> {
  const pastedReferences = new Set<number>();
  collectReferenceNumbers(pastedDocument.body).forEach((value) => pastedReferences.add(value));
  collectReferenceNumbers(pastedDocument.trailingDefinitions).forEach((value) =>
    pastedReferences.add(value),
  );

  const mapping = new Map<number, number>();
  [...pastedReferences]
    .sort((left, right) => left - right)
    .forEach((value, index) => {
      mapping.set(value, nextReferenceNumber + index);
    });
  return mapping;
}

function getNextReferenceNumber(referenceNumbers: Set<number>): number {
  if (referenceNumbers.size === 0) {
    return 1;
  }
  return Math.max(...referenceNumbers) + 1;
}

function rewriteReferences(value: string, mapping: Map<number, number>): string {
  if (!value || mapping.size === 0) {
    return value;
  }

  const lines = value.split("\n");
  let fence: FenceState = null;
  return lines
    .map((line) => {
      const insideFence = fence !== null;
      const nextFence = getNextFenceState(line, fence);
      fence = nextFence;
      if (insideFence || isFenceLine(line)) {
        return line;
      }
      return rewriteReferenceLine(line, mapping);
    })
    .join("\n");
}

function rewriteReferenceLine(line: string, mapping: Map<number, number>): string {
  const definitionMatch = REFERENCE_DEFINITION_PATTERN.exec(line);
  let rewritten = line;
  if (definitionMatch) {
    const next = mapping.get(Number(definitionMatch[2]));
    if (next !== undefined) {
      rewritten = `${definitionMatch[1]}${next}${definitionMatch[3]}`;
    }
  }
  return rewritten.replace(REFERENCE_LABEL_PATTERN, (match, prefix, label, suffix) => {
    const next = mapping.get(Number(label));
    return next === undefined ? match : `${prefix}${next}${suffix}`;
  });
}

function composeMergedMarkdown(
  existingBody: string,
  pastedBody: string,
  existingDefinitions: string,
  pastedDefinitions: string,
): string {
  const bodyParts = [existingBody, pastedBody]
    .map((part) => trimTrailingBlankLines(part))
    .filter((part) => part.length > 0);
  const definitionParts = [existingDefinitions, pastedDefinitions]
    .map((part) => trimTrailingBlankLines(part))
    .filter((part) => part.length > 0);
  const body = bodyParts.join("\n\n");
  const definitions = definitionParts.join("\n");
  const parts = [body, definitions].filter((part) => part.length > 0);
  const merged = parts.join("\n\n");
  return merged ? `${merged}\n` : "";
}

function getCursorOffset(content: string, existingBody: string, pastedBody: string): number {
  const trimmedExistingBody = trimTrailingBlankLines(existingBody);
  const trimmedPastedBody = trimTrailingBlankLines(pastedBody);
  if (!trimmedPastedBody) {
    return trimTrailingBlankLines(content).length;
  }
  return trimmedExistingBody
    ? trimmedExistingBody.length + 2 + trimmedPastedBody.length
    : trimmedPastedBody.length;
}

function trimTrailingBlankLines(value: string): string {
  return value.replace(/[ \t\n]+$/g, "");
}

function forEachMarkdownLine(value: string, handler: (line: string) => void): void {
  const lines = value.split("\n");
  let fence: FenceState = null;
  lines.forEach((line) => {
    const insideFence = fence !== null;
    const nextFence = getNextFenceState(line, fence);
    if (!insideFence && !isFenceLine(line)) {
      handler(line);
    }
    fence = nextFence;
  });
}

function buildFencedCodeLineMap(lines: string[]): boolean[] {
  const codeLines: boolean[] = [];
  let fence: FenceState = null;
  lines.forEach((line, index) => {
    const insideFence = fence !== null;
    const nextFence = getNextFenceState(line, fence);
    codeLines[index] = insideFence || isFenceLine(line);
    fence = nextFence;
  });
  return codeLines;
}

function getNextFenceState(line: string, fence: FenceState): FenceState {
  const match = FENCE_PATTERN.exec(line);
  if (!match) {
    return fence;
  }
  const markerText = match[1];
  const marker = markerText[0] as "`" | "~";
  if (!fence) {
    return { marker, length: markerText.length };
  }
  if (fence.marker === marker && markerText.length >= fence.length) {
    return null;
  }
  return fence;
}

function isFenceLine(line: string): boolean {
  return FENCE_PATTERN.test(line);
}
