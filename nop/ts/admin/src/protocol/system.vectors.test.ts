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
  parseNumber,
} from "./fixtures";
import {
  SYSTEM_ACTION_LOGGING_CLEAR,
  SYSTEM_ACTION_LOGGING_CLEAR_ERR,
  SYSTEM_ACTION_LOGGING_CLEAR_OK,
  SYSTEM_ACTION_LOGGING_GET,
  SYSTEM_ACTION_LOGGING_GET_ERR,
  SYSTEM_ACTION_LOGGING_GET_OK,
  SYSTEM_ACTION_LOGGING_SET,
  SYSTEM_ACTION_LOGGING_SET_ERR,
  SYSTEM_ACTION_LOGGING_SET_OK,
  SYSTEM_ACTION_PING,
  SYSTEM_ACTION_PONG,
  SYSTEM_ACTION_PONG_ERROR,
  SYSTEM_DOMAIN_ID,
  decodeClearLogsResponse,
  decodeLoggingConfigResponse,
  decodeMessageResponse,
  encodeLoggingClearRequest,
  encodeLoggingGetRequest,
  encodeLoggingSetRequest,
  encodePingRequest,
} from "./system";

describe("system wire vectors", () => {
  const entries = loadVectorEntries().filter(
    (entry) => entry.domain_id === SYSTEM_DOMAIN_ID,
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
      const decoded = decodeResponse(entry.action_id, hexToBytes(entry.hex), entry.name);
      expect(decoded).toEqual(entry.payload);
    }
  });
});

function encodeRequest(
  actionId: number,
  payload: Record<string, unknown>,
  name: string,
): Uint8Array {
  switch (actionId) {
    case SYSTEM_ACTION_PING:
      return encodePingRequest({
        versionMajor: parseNumber(payload.version_major, `${name}.version_major`),
        versionMinor: parseNumber(payload.version_minor, `${name}.version_minor`),
        versionPatch: parseNumber(payload.version_patch, `${name}.version_patch`),
      });
    case SYSTEM_ACTION_LOGGING_GET:
      return encodeLoggingGetRequest({});
    case SYSTEM_ACTION_LOGGING_SET:
      return encodeLoggingSetRequest({
        rotationMaxSizeMb: parseNumber(
          payload.rotation_max_size_mb,
          `${name}.rotation_max_size_mb`,
        ),
        rotationMaxFiles: parseNumber(
          payload.rotation_max_files,
          `${name}.rotation_max_files`,
        ),
      });
    case SYSTEM_ACTION_LOGGING_CLEAR:
      return encodeLoggingClearRequest({});
    default:
      throw new Error(`Unhandled system request action ${actionId}`);
  }
}

function decodeResponse(actionId: number, bytes: Uint8Array, name: string): unknown {
  switch (actionId) {
    case SYSTEM_ACTION_PONG:
    case SYSTEM_ACTION_PONG_ERROR:
    case SYSTEM_ACTION_LOGGING_GET_ERR:
    case SYSTEM_ACTION_LOGGING_SET_ERR:
    case SYSTEM_ACTION_LOGGING_CLEAR_ERR:
      return decodeMessageResponse(bytes);
    case SYSTEM_ACTION_LOGGING_GET_OK:
    case SYSTEM_ACTION_LOGGING_SET_OK:
      return decodeLoggingConfigResponse(bytes);
    case SYSTEM_ACTION_LOGGING_CLEAR_OK:
      return decodeClearLogsResponse(bytes);
    default:
      throw new Error(`Unhandled system response action ${actionId} for ${name}`);
  }
}
