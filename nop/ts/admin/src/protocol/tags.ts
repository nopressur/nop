// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { OptionMap, WireReader, WireWriter } from "./wire";

export const TAGS_DOMAIN_ID = 11;
export const TAG_ACTION_ADD = 1;
export const TAG_ACTION_CHANGE = 2;
export const TAG_ACTION_DELETE = 3;
export const TAG_ACTION_LIST = 4;
export const TAG_ACTION_SHOW = 5;

export const TAG_ACTION_ADD_OK = 101;
export const TAG_ACTION_ADD_ERR = 102;
export const TAG_ACTION_CHANGE_OK = 201;
export const TAG_ACTION_CHANGE_ERR = 202;
export const TAG_ACTION_DELETE_OK = 301;
export const TAG_ACTION_DELETE_ERR = 302;
export const TAG_ACTION_LIST_OK = 401;
export const TAG_ACTION_LIST_ERR = 402;
export const TAG_ACTION_SHOW_OK = 501;
export const TAG_ACTION_SHOW_ERR = 502;

export type AccessRule = "union" | "intersect";

export interface TagAddRequest {
  id: string;
  name: string;
  roles: string[];
  accessRule?: AccessRule | null;
}

export interface TagChangeRequest {
  id: string;
  newId?: string | null;
  name?: string | null;
  roles?: string[] | null;
  accessRule?: AccessRule | null;
  clearAccess: boolean;
}

export interface TagDeleteRequest {
  id: string;
}

export interface TagListRequest {}

export interface TagShowRequest {
  id: string;
}

export interface TagSummary {
  id: string;
  name: string;
}

export interface TagListResponse {
  tags: TagSummary[];
}

export interface TagShowResponse {
  id: string;
  name: string;
  roles: string[];
  accessRule: AccessRule | null;
}

export interface MessageResponse {
  message: string;
}

const ACCESS_RULE_UNION = 0;
const ACCESS_RULE_INTERSECT = 1;

function writeStringVec(writer: WireWriter, values: string[]): void {
  writer.writeVec(values, (itemWriter, value) => itemWriter.writeString(value));
}

function readStringVec(reader: WireReader): string[] {
  return reader.readVec((itemReader) => itemReader.readString());
}

function writeAccessRule(writer: WireWriter, value: AccessRule): void {
  writer.writeU32(value === "union" ? ACCESS_RULE_UNION : ACCESS_RULE_INTERSECT);
}

function readAccessRule(reader: WireReader): AccessRule {
  const value = reader.readU32();
  if (value === ACCESS_RULE_UNION) {
    return "union";
  }
  if (value === ACCESS_RULE_INTERSECT) {
    return "intersect";
  }
  throw new Error(`Unknown access rule ${value}`);
}

export function encodeTagAddRequest(payload: TagAddRequest): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [payload.accessRule !== null && payload.accessRule !== undefined];
  OptionMap.write(writer, optionFlags);

  writer.writeString(payload.id);
  writer.writeString(payload.name);
  writeStringVec(writer, payload.roles);
  if (optionFlags[0]) {
    writeAccessRule(writer, payload.accessRule as AccessRule);
  }
  return writer.toUint8Array();
}

export function encodeTagChangeRequest(payload: TagChangeRequest): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.newId !== null && payload.newId !== undefined,
    payload.name !== null && payload.name !== undefined,
    payload.roles !== null && payload.roles !== undefined,
    payload.accessRule !== null && payload.accessRule !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  writer.writeString(payload.id);
  if (optionFlags[0]) {
    writer.writeString(payload.newId as string);
  }
  if (optionFlags[1]) {
    writer.writeString(payload.name as string);
  }
  if (optionFlags[2]) {
    writeStringVec(writer, payload.roles as string[]);
  }
  if (optionFlags[3]) {
    writeAccessRule(writer, payload.accessRule as AccessRule);
  }
  writer.writeBool(payload.clearAccess);
  return writer.toUint8Array();
}

export function encodeTagDeleteRequest(payload: TagDeleteRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.id);
  return writer.toUint8Array();
}

export function encodeTagListRequest(_payload: TagListRequest): Uint8Array {
  return new Uint8Array(0);
}

export function encodeTagShowRequest(payload: TagShowRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.id);
  return writer.toUint8Array();
}

export function decodeMessageResponse(bytes: Uint8Array): MessageResponse {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { message };
}

export function decodeTagListResponse(bytes: Uint8Array): TagListResponse {
  const reader = new WireReader(bytes);
  const tags = reader.readVec((itemReader) => ({
    id: itemReader.readString(),
    name: itemReader.readString(),
  }));
  reader.ensureFullyConsumed();
  return { tags };
}

export function decodeTagShowResponse(bytes: Uint8Array): TagShowResponse {
  const reader = new WireReader(bytes);
  const flags = OptionMap.read(reader, 1);
  const id = reader.readString();
  const name = reader.readString();
  const roles = readStringVec(reader);
  const accessRule = flags[0] ? readAccessRule(reader) : null;
  reader.ensureFullyConsumed();
  return {
    id,
    name,
    roles,
    accessRule,
  };
}
