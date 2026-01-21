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
  parseOptionalString,
  parseOptionalStringArray,
  parseString,
  parseStringArray,
} from "./fixtures";
import type { PasswordPayload } from "./users";
import {
  USER_ACTION_ADD,
  USER_ACTION_ADD_ERR,
  USER_ACTION_ADD_OK,
  USER_ACTION_CHANGE,
  USER_ACTION_CHANGE_ERR,
  USER_ACTION_CHANGE_OK,
  USER_ACTION_DELETE,
  USER_ACTION_DELETE_ERR,
  USER_ACTION_DELETE_OK,
  USER_ACTION_LIST,
  USER_ACTION_LIST_ERR,
  USER_ACTION_LIST_OK,
  USER_ACTION_PASSWORD_SALT,
  USER_ACTION_PASSWORD_SALT_ERR,
  USER_ACTION_PASSWORD_SALT_OK,
  USER_ACTION_PASSWORD_SET,
  USER_ACTION_PASSWORD_SET_ERR,
  USER_ACTION_PASSWORD_SET_OK,
  USER_ACTION_PASSWORD_UPDATE,
  USER_ACTION_PASSWORD_UPDATE_ERR,
  USER_ACTION_PASSWORD_UPDATE_OK,
  USER_ACTION_PASSWORD_VALIDATE,
  USER_ACTION_PASSWORD_VALIDATE_ERR,
  USER_ACTION_PASSWORD_VALIDATE_OK,
  USER_ACTION_ROLE_ADD,
  USER_ACTION_ROLE_ADD_ERR,
  USER_ACTION_ROLE_ADD_OK,
  USER_ACTION_ROLE_REMOVE,
  USER_ACTION_ROLE_REMOVE_ERR,
  USER_ACTION_ROLE_REMOVE_OK,
  USER_ACTION_ROLES_LIST,
  USER_ACTION_ROLES_LIST_ERR,
  USER_ACTION_ROLES_LIST_OK,
  USER_ACTION_SHOW,
  USER_ACTION_SHOW_ERR,
  USER_ACTION_SHOW_OK,
  USERS_DOMAIN_ID,
  decodeMessageResponse,
  decodePasswordSaltResponse,
  decodePasswordValidateResponse,
  decodeUserListResponse,
  decodeUserRolesListResponse,
  decodeUserShowResponse,
  encodeUserAddRequest,
  encodeUserChangeRequest,
  encodeUserDeleteRequest,
  encodeUserListRequest,
  encodeUserPasswordSaltRequest,
  encodeUserPasswordSetRequest,
  encodeUserPasswordUpdateRequest,
  encodeUserPasswordValidateRequest,
  encodeUserRoleAddRequest,
  encodeUserRoleRemoveRequest,
  encodeUserRolesListRequest,
  encodeUserShowRequest,
} from "./users";

describe("users wire vectors", () => {
  const entries = loadVectorEntries().filter(
    (entry) => entry.domain_id === USERS_DOMAIN_ID,
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
    case USER_ACTION_ADD:
      return encodeUserAddRequest({
        email: parseString(payload.email, "users.add.email"),
        name: parseString(payload.name, "users.add.name"),
        password: parsePasswordPayload(payload.password, "users.add.password"),
        roles: parseStringArray(payload.roles, "users.add.roles"),
        change_token: parseOptionalString(payload.change_token, "users.add.change_token"),
      });
    case USER_ACTION_CHANGE:
      return encodeUserChangeRequest({
        email: parseString(payload.email, "users.change.email"),
        name: parseOptionalString(payload.name, "users.change.name"),
        roles: parseOptionalStringArray(payload.roles, "users.change.roles"),
      });
    case USER_ACTION_DELETE:
      return encodeUserDeleteRequest({
        email: parseString(payload.email, "users.delete.email"),
      });
    case USER_ACTION_PASSWORD_SET:
      return encodeUserPasswordSetRequest({
        email: parseString(payload.email, "users.password_set.email"),
        password: parsePasswordPayload(
          payload.password,
          "users.password_set.password",
        ),
        change_token: parseOptionalString(
          payload.change_token,
          "users.password_set.change_token",
        ),
      });
    case USER_ACTION_PASSWORD_SALT:
      return encodeUserPasswordSaltRequest({
        email: parseString(payload.email, "users.password_salt.email"),
      });
    case USER_ACTION_PASSWORD_VALIDATE:
      return encodeUserPasswordValidateRequest({
        email: parseString(payload.email, "users.password_validate.email"),
        front_end_hash: parseString(
          payload.front_end_hash,
          "users.password_validate.front_end_hash",
        ),
      });
    case USER_ACTION_PASSWORD_UPDATE:
      return encodeUserPasswordUpdateRequest({
        email: parseString(payload.email, "users.password_update.email"),
        current_front_end_hash: parseString(
          payload.current_front_end_hash,
          "users.password_update.current_front_end_hash",
        ),
        new_front_end_hash: parseString(
          payload.new_front_end_hash,
          "users.password_update.new_front_end_hash",
        ),
        new_front_end_salt: parseString(
          payload.new_front_end_salt,
          "users.password_update.new_front_end_salt",
        ),
        change_token: parseString(
          payload.change_token,
          "users.password_update.change_token",
        ),
      });
    case USER_ACTION_LIST:
      return encodeUserListRequest({});
    case USER_ACTION_SHOW:
      return encodeUserShowRequest({
        email: parseString(payload.email, "users.show.email"),
      });
    case USER_ACTION_ROLE_ADD:
      return encodeUserRoleAddRequest({
        email: parseString(payload.email, "users.role_add.email"),
        role: parseString(payload.role, "users.role_add.role"),
      });
    case USER_ACTION_ROLE_REMOVE:
      return encodeUserRoleRemoveRequest({
        email: parseString(payload.email, "users.role_remove.email"),
        role: parseString(payload.role, "users.role_remove.role"),
      });
    case USER_ACTION_ROLES_LIST:
      return encodeUserRolesListRequest({});
    default:
      throw new Error(`Unhandled users request action ${actionId}`);
  }
}

function decodeResponse(actionId: number, bytes: Uint8Array): unknown {
  switch (actionId) {
    case USER_ACTION_ADD_OK:
    case USER_ACTION_ADD_ERR:
    case USER_ACTION_CHANGE_OK:
    case USER_ACTION_CHANGE_ERR:
    case USER_ACTION_DELETE_OK:
    case USER_ACTION_DELETE_ERR:
    case USER_ACTION_PASSWORD_SET_OK:
    case USER_ACTION_PASSWORD_SET_ERR:
    case USER_ACTION_LIST_ERR:
    case USER_ACTION_SHOW_ERR:
    case USER_ACTION_ROLE_ADD_OK:
    case USER_ACTION_ROLE_ADD_ERR:
    case USER_ACTION_ROLE_REMOVE_OK:
    case USER_ACTION_ROLE_REMOVE_ERR:
    case USER_ACTION_ROLES_LIST_ERR:
    case USER_ACTION_PASSWORD_SALT_ERR:
    case USER_ACTION_PASSWORD_VALIDATE_ERR:
    case USER_ACTION_PASSWORD_UPDATE_OK:
    case USER_ACTION_PASSWORD_UPDATE_ERR:
      return decodeMessageResponse(bytes);
    case USER_ACTION_PASSWORD_SALT_OK:
      return decodePasswordSaltResponse(bytes);
    case USER_ACTION_PASSWORD_VALIDATE_OK:
      return decodePasswordValidateResponse(bytes);
    case USER_ACTION_LIST_OK:
      return decodeUserListResponse(bytes);
    case USER_ACTION_SHOW_OK:
      return decodeUserShowResponse(bytes);
    case USER_ACTION_ROLES_LIST_OK:
      return decodeUserRolesListResponse(bytes);
    default:
      throw new Error(`Unhandled users response action ${actionId}`);
  }
}

function parsePasswordPayload(
  value: unknown,
  label: string,
): PasswordPayload {
  const record = assertRecord(value, label);
  const kind = parseString(record.kind, `${label}.kind`);
  if (kind === "plaintext") {
    return {
      kind,
      plaintext: parseString(record.plaintext, `${label}.plaintext`),
    };
  }
  if (kind === "front_end_hash") {
    return {
      kind,
      front_end_hash: parseString(
        record.front_end_hash,
        `${label}.front_end_hash`,
      ),
      front_end_salt: parseString(
        record.front_end_salt,
        `${label}.front_end_salt`,
      ),
    };
  }
  throw new Error(`Unsupported password payload kind ${kind} at ${label}`);
}
