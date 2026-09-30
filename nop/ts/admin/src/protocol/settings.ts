// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { OptionMap, WireReader, WireWriter } from "./wire";

export const SETTINGS_DOMAIN_ID = 22;

export const SETTINGS_ACTION_GET = 1;
export const SETTINGS_ACTION_SET_NAME = 2;
export const SETTINGS_ACTION_SET_TITLE = 3;
export const SETTINGS_ACTION_SET_DESCRIPTION = 4;

export const SETTINGS_ACTION_GET_OK = 101;
export const SETTINGS_ACTION_GET_ERR = 102;
export const SETTINGS_ACTION_SET_NAME_OK = 201;
export const SETTINGS_ACTION_SET_NAME_ERR = 202;
export const SETTINGS_ACTION_SET_TITLE_OK = 301;
export const SETTINGS_ACTION_SET_TITLE_ERR = 302;
export const SETTINGS_ACTION_SET_DESCRIPTION_OK = 401;
export const SETTINGS_ACTION_SET_DESCRIPTION_ERR = 402;
export const WEBSITE_NAME_MAX_CHARS = 120;
export const WEBSITE_TITLE_MAX_CHARS = 120;
export const WEBSITE_DESCRIPTION_MAX_CHARS = 240;

export interface SettingsGetRequest {}

export interface SettingsSetNameRequest {
  name: string;
}

export interface SettingsSetTitleRequest {
  title?: string | null;
}

export interface SettingsSetDescriptionRequest {
  description?: string | null;
}

export interface SettingsResponse {
  name: string;
  title: string | null;
  description: string | null;
}

export interface MessageResponse {
  message: string;
}

export function encodeSettingsGetRequest(_payload: SettingsGetRequest): Uint8Array {
  return new Uint8Array(0);
}

export function encodeSettingsSetNameRequest(payload: SettingsSetNameRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.name);
  return writer.toUint8Array();
}

export function encodeSettingsSetTitleRequest(
  payload: SettingsSetTitleRequest,
): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [payload.title !== null && payload.title !== undefined];
  OptionMap.write(writer, optionFlags);
  if (optionFlags[0]) {
    writer.writeString(payload.title as string);
  }
  return writer.toUint8Array();
}

export function encodeSettingsSetDescriptionRequest(
  payload: SettingsSetDescriptionRequest,
): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.description !== null && payload.description !== undefined,
  ];
  OptionMap.write(writer, optionFlags);
  if (optionFlags[0]) {
    writer.writeString(payload.description as string);
  }
  return writer.toUint8Array();
}

export function decodeSettingsResponse(bytes: Uint8Array): SettingsResponse {
  const reader = new WireReader(bytes);
  const name = reader.readString();
  const flags = OptionMap.read(reader, 2);
  const title = flags[0] ? reader.readString() : null;
  const description = flags[1] ? reader.readString() : null;
  reader.ensureFullyConsumed();
  return { name, title, description };
}

export function decodeMessageResponse(bytes: Uint8Array): MessageResponse {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { message };
}
