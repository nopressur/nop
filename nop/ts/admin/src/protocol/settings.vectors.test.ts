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
} from "./fixtures";
import {
  SETTINGS_ACTION_GET,
  SETTINGS_ACTION_GET_ERR,
  SETTINGS_ACTION_GET_OK,
  SETTINGS_ACTION_SET_DESCRIPTION,
  SETTINGS_ACTION_SET_DESCRIPTION_ERR,
  SETTINGS_ACTION_SET_DESCRIPTION_OK,
  SETTINGS_ACTION_SET_NAME,
  SETTINGS_ACTION_SET_NAME_ERR,
  SETTINGS_ACTION_SET_NAME_OK,
  SETTINGS_ACTION_SET_TITLE,
  SETTINGS_ACTION_SET_TITLE_ERR,
  SETTINGS_ACTION_SET_TITLE_OK,
  SETTINGS_DOMAIN_ID,
  decodeMessageResponse,
  decodeSettingsResponse,
  encodeSettingsGetRequest,
  encodeSettingsSetDescriptionRequest,
  encodeSettingsSetNameRequest,
  encodeSettingsSetTitleRequest,
} from "./settings";

describe("settings wire vectors", () => {
  const entries = loadVectorEntries().filter(
    (entry) => entry.domain_id === SETTINGS_DOMAIN_ID,
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

  it("rejects malformed response payloads", () => {
    expect(() => decodeSettingsResponse(new Uint8Array([0xff]))).toThrow();
  });
});

function encodeRequest(
  actionId: number,
  payload: Record<string, unknown>,
  name: string,
): Uint8Array {
  switch (actionId) {
    case SETTINGS_ACTION_GET:
      return encodeSettingsGetRequest({});
    case SETTINGS_ACTION_SET_NAME:
      return encodeSettingsSetNameRequest({
        name: parseRequiredString(payload.name, `${name}.name`),
      });
    case SETTINGS_ACTION_SET_TITLE:
      return encodeSettingsSetTitleRequest({
        title: parseOptionalString(payload.title, `${name}.title`),
      });
    case SETTINGS_ACTION_SET_DESCRIPTION:
      return encodeSettingsSetDescriptionRequest({
        description: parseOptionalString(
          payload.description,
          `${name}.description`,
        ),
      });
    default:
      throw new Error(`Unhandled settings request action ${actionId}`);
  }
}

function decodeResponse(actionId: number, bytes: Uint8Array, name: string): unknown {
  switch (actionId) {
    case SETTINGS_ACTION_GET_OK:
    case SETTINGS_ACTION_SET_NAME_OK:
    case SETTINGS_ACTION_SET_TITLE_OK:
    case SETTINGS_ACTION_SET_DESCRIPTION_OK:
      return decodeSettingsResponse(bytes);
    case SETTINGS_ACTION_GET_ERR:
    case SETTINGS_ACTION_SET_NAME_ERR:
    case SETTINGS_ACTION_SET_TITLE_ERR:
    case SETTINGS_ACTION_SET_DESCRIPTION_ERR:
      return decodeMessageResponse(bytes);
    default:
      throw new Error(`Unhandled settings response action ${actionId} for ${name}`);
  }
}

function parseRequiredString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  return value;
}
