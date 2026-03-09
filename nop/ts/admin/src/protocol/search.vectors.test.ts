// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import {
  assertRecord,
  bytesToHex,
  hexToBytes,
  loadVectorEntries,
  parseBool,
  parseOptionalStringArray,
  parseString,
} from "./fixtures";
import {
  SEARCH_ACTION_FIND,
  SEARCH_ACTION_FIND_ERR,
  SEARCH_ACTION_FIND_OK,
  SEARCH_ACTION_INVALIDATE,
  SEARCH_ACTION_INVALIDATE_ERR,
  SEARCH_ACTION_INVALIDATE_OK,
  SEARCH_ACTION_RESET,
  SEARCH_ACTION_RESET_ERR,
  SEARCH_ACTION_RESET_OK,
  SEARCH_DOMAIN_ID,
  decodeMessageResponse,
  decodeSearchFindResponse,
  encodeSearchFindRequest,
  encodeSearchInvalidateRequest,
  encodeSearchResetRequest,
} from "./search";

describe("search wire vectors", () => {
  const entries = loadVectorEntries().filter(
    (entry) => entry.domain_id === SEARCH_DOMAIN_ID,
  );

  it("encodes request payloads", () => {
    for (const entry of entries.filter((item) => item.direction === "request")) {
      const payload = assertRecord(entry.payload, entry.name);
      const encoded = encodeRequest(entry.action_id, payload, entry.name);
      expect(bytesToHex(encoded)).toBe(entry.hex);
    }
  });

  it("decodes response payloads", () => {
    for (const entry of entries.filter((item) => item.direction === "response")) {
      const decoded = decodeResponse(entry.action_id, hexToBytes(entry.hex));
      expect(decoded).toEqual(entry.payload);
    }
  });

  it("rejects malformed response payloads", () => {
    expect(() => decodeSearchFindResponse(new Uint8Array([0xff]))).toThrow();
  });
});

function encodeRequest(
  actionId: number,
  payload: Record<string, unknown>,
  name: string,
): Uint8Array {
  switch (actionId) {
    case SEARCH_ACTION_FIND:
      return encodeSearchFindRequest({
        query: parseString(payload.query, `${name}.query`),
        tags: parseOptionalStringArray(payload.tags, `${name}.tags`),
        markdownOnly: parseBool(payload.markdown_only, `${name}.markdown_only`),
      });
    case SEARCH_ACTION_INVALIDATE:
      return encodeSearchInvalidateRequest({
        id: parseString(payload.id, `${name}.id`),
      });
    case SEARCH_ACTION_RESET:
      return encodeSearchResetRequest({});
    default:
      throw new Error(`Unhandled search request action ${actionId}`);
  }
}

function decodeResponse(actionId: number, bytes: Uint8Array): unknown {
  switch (actionId) {
    case SEARCH_ACTION_FIND_OK:
      return normalizeSearchFindResponse(decodeSearchFindResponse(bytes));
    case SEARCH_ACTION_FIND_ERR:
    case SEARCH_ACTION_INVALIDATE_OK:
    case SEARCH_ACTION_INVALIDATE_ERR:
    case SEARCH_ACTION_RESET_OK:
    case SEARCH_ACTION_RESET_ERR:
      return decodeMessageResponse(bytes);
    default:
      throw new Error(`Unhandled search response action ${actionId}`);
  }
}

function normalizeSearchFindResponse(response: {
  hits: {
    id: string;
    alias: string;
    title: string | null;
    mime: string;
    tags: string[];
    navTitle: string | null;
    navParentId: string | null;
    navOrder: number | null;
    originalFilename: string | null;
    isMarkdown: boolean;
  }[];
}): unknown {
  return {
    hits: response.hits.map((item) => ({
      id: item.id,
      alias: item.alias,
      title: item.title,
      mime: item.mime,
      tags: item.tags,
      nav_title: item.navTitle,
      nav_parent_id: item.navParentId,
      nav_order: item.navOrder,
      original_filename: item.originalFilename,
      is_markdown: item.isMarkdown,
    })),
  };
}
