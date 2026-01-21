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
  parseOptionalString,
  parseOptionalStringArray,
  parseString,
  parseStringArray,
} from "./fixtures";
import {
  TAG_ACTION_ADD,
  TAG_ACTION_ADD_ERR,
  TAG_ACTION_ADD_OK,
  TAG_ACTION_CHANGE,
  TAG_ACTION_CHANGE_ERR,
  TAG_ACTION_CHANGE_OK,
  TAG_ACTION_DELETE,
  TAG_ACTION_DELETE_ERR,
  TAG_ACTION_DELETE_OK,
  TAG_ACTION_LIST,
  TAG_ACTION_LIST_ERR,
  TAG_ACTION_LIST_OK,
  TAG_ACTION_SHOW,
  TAG_ACTION_SHOW_ERR,
  TAG_ACTION_SHOW_OK,
  TAGS_DOMAIN_ID,
  decodeMessageResponse,
  decodeTagListResponse,
  decodeTagShowResponse,
  encodeTagAddRequest,
  encodeTagChangeRequest,
  encodeTagDeleteRequest,
  encodeTagListRequest,
  encodeTagShowRequest,
  type AccessRule,
} from "./tags";

describe("tags wire vectors", () => {
  const entries = loadVectorEntries().filter(
    (entry) => entry.domain_id === TAGS_DOMAIN_ID,
  );

  it("encodes request payloads", () => {
    for (const entry of entries.filter((item) => item.direction === "request")) {
      const payload = assertRecord(entry.payload, entry.name);
      const encoded = encodeRequest(entry.action_id, payload);
      expect(bytesToHex(encoded)).toBe(entry.hex);
    }
  });

  it("decodes response payloads", () => {
    for (const entry of entries.filter((item) => item.direction === "response")) {
      const decoded = decodeResponse(entry.action_id, hexToBytes(entry.hex));
      expect(decoded).toEqual(entry.payload);
    }
  });
});

function encodeRequest(actionId: number, payload: Record<string, unknown>): Uint8Array {
  switch (actionId) {
    case TAG_ACTION_ADD:
      return encodeTagAddRequest({
        id: parseString(payload.id, "tags.add.id"),
        name: parseString(payload.name, "tags.add.name"),
        roles: parseStringArray(payload.roles, "tags.add.roles"),
        accessRule: parseOptionalAccessRule(payload.access_rule, "tags.add.access_rule"),
      });
    case TAG_ACTION_CHANGE:
      return encodeTagChangeRequest({
        id: parseString(payload.id, "tags.change.id"),
        newId: parseOptionalString(payload.new_id, "tags.change.new_id"),
        name: parseOptionalString(payload.name, "tags.change.name"),
        roles: parseOptionalStringArray(payload.roles, "tags.change.roles"),
        accessRule: parseOptionalAccessRule(payload.access_rule, "tags.change.access_rule"),
        clearAccess: parseBool(payload.clear_access, "tags.change.clear_access"),
      });
    case TAG_ACTION_DELETE:
      return encodeTagDeleteRequest({
        id: parseString(payload.id, "tags.delete.id"),
      });
    case TAG_ACTION_LIST:
      return encodeTagListRequest({});
    case TAG_ACTION_SHOW:
      return encodeTagShowRequest({
        id: parseString(payload.id, "tags.show.id"),
      });
    default:
      throw new Error(`Unhandled tags request action ${actionId}`);
  }
}

function parseOptionalAccessRule(value: unknown, label: string): AccessRule | null {
  const rule = parseOptionalString(value, label);
  if (rule === null) {
    return null;
  }
  if (rule !== "union" && rule !== "intersect") {
    throw new Error(`${label} must be 'union' or 'intersect'`);
  }
  return rule;
}

function decodeResponse(actionId: number, bytes: Uint8Array): unknown {
  switch (actionId) {
    case TAG_ACTION_ADD_OK:
    case TAG_ACTION_ADD_ERR:
    case TAG_ACTION_CHANGE_OK:
    case TAG_ACTION_CHANGE_ERR:
    case TAG_ACTION_DELETE_OK:
    case TAG_ACTION_DELETE_ERR:
    case TAG_ACTION_LIST_ERR:
    case TAG_ACTION_SHOW_ERR:
      return decodeMessageResponse(bytes);
    case TAG_ACTION_LIST_OK:
      return decodeTagListResponse(bytes);
    case TAG_ACTION_SHOW_OK: {
      const decoded = decodeTagShowResponse(bytes);
      return {
        id: decoded.id,
        name: decoded.name,
        roles: decoded.roles,
        access_rule: decoded.accessRule,
      };
    }
    default:
      throw new Error(`Unhandled tags response action ${actionId}`);
  }
}
