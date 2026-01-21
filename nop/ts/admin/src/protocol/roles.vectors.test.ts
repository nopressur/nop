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
  parseString,
  parseStringArray,
} from "./fixtures";
import {
  ROLE_ACTION_ADD,
  ROLE_ACTION_ADD_ERR,
  ROLE_ACTION_ADD_OK,
  ROLE_ACTION_CHANGE,
  ROLE_ACTION_CHANGE_ERR,
  ROLE_ACTION_CHANGE_OK,
  ROLE_ACTION_DELETE,
  ROLE_ACTION_DELETE_ERR,
  ROLE_ACTION_DELETE_OK,
  ROLE_ACTION_LIST,
  ROLE_ACTION_LIST_ERR,
  ROLE_ACTION_LIST_OK,
  ROLE_ACTION_SHOW,
  ROLE_ACTION_SHOW_ERR,
  ROLE_ACTION_SHOW_OK,
  ROLES_DOMAIN_ID,
  decodeMessageResponse,
  decodeRoleListResponse,
  decodeRoleShowResponse,
  encodeRoleAddRequest,
  encodeRoleChangeRequest,
  encodeRoleDeleteRequest,
  encodeRoleListRequest,
  encodeRoleShowRequest,
} from "./roles";

describe("roles wire vectors", () => {
  const entries = loadVectorEntries().filter(
    (entry) => entry.domain_id === ROLES_DOMAIN_ID,
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
    case ROLE_ACTION_ADD:
      return encodeRoleAddRequest({
        role: parseString(payload.role, "roles.add.role"),
      });
    case ROLE_ACTION_CHANGE:
      return encodeRoleChangeRequest({
        role: parseString(payload.role, "roles.change.role"),
        newRole: parseString(payload.new_role, "roles.change.new_role"),
      });
    case ROLE_ACTION_DELETE:
      return encodeRoleDeleteRequest({
        role: parseString(payload.role, "roles.delete.role"),
      });
    case ROLE_ACTION_LIST:
      return encodeRoleListRequest({});
    case ROLE_ACTION_SHOW:
      return encodeRoleShowRequest({
        role: parseString(payload.role, "roles.show.role"),
      });
    default:
      throw new Error(`Unhandled roles request action ${actionId}`);
  }
}

function decodeResponse(actionId: number, bytes: Uint8Array): unknown {
  switch (actionId) {
    case ROLE_ACTION_ADD_OK:
    case ROLE_ACTION_ADD_ERR:
    case ROLE_ACTION_CHANGE_OK:
    case ROLE_ACTION_CHANGE_ERR:
    case ROLE_ACTION_DELETE_OK:
    case ROLE_ACTION_DELETE_ERR:
    case ROLE_ACTION_LIST_ERR:
    case ROLE_ACTION_SHOW_ERR:
      return decodeMessageResponse(bytes);
    case ROLE_ACTION_LIST_OK: {
      const decoded = decodeRoleListResponse(bytes);
      return {
        roles: parseStringArray(decoded.roles, "roles.list.roles"),
      };
    }
    case ROLE_ACTION_SHOW_OK:
      return decodeRoleShowResponse(bytes);
    default:
      throw new Error(`Unhandled roles response action ${actionId}`);
  }
}
