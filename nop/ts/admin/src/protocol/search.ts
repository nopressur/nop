// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { OptionMap, WireReader, WireWriter } from "./wire";

export const SEARCH_DOMAIN_ID = 21;
export const SEARCH_ACTION_FIND = 1;
export const SEARCH_ACTION_INVALIDATE = 2;
export const SEARCH_ACTION_RESET = 3;

export const SEARCH_ACTION_FIND_OK = 101;
export const SEARCH_ACTION_FIND_ERR = 102;
export const SEARCH_ACTION_INVALIDATE_OK = 201;
export const SEARCH_ACTION_INVALIDATE_ERR = 202;
export const SEARCH_ACTION_RESET_OK = 301;
export const SEARCH_ACTION_RESET_ERR = 302;

export interface SearchFindRequest {
  query: string;
  tags?: string[] | null;
  markdownOnly: boolean;
}

export interface SearchListItem {
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
}

export interface SearchFindResponse {
  hits: SearchListItem[];
}

export interface SearchInvalidateRequest {
  id: string;
}

export interface SearchResetRequest {}

export interface MessageResponse {
  message: string;
}

function writeStringVec(writer: WireWriter, values: string[]): void {
  writer.writeVec(values, (itemWriter, value) => itemWriter.writeString(value));
}

function readStringVec(reader: WireReader): string[] {
  return reader.readVec((itemReader) => itemReader.readString());
}

function readSearchListItem(reader: WireReader): SearchListItem {
  const flags = OptionMap.read(reader, 5);
  const id = reader.readString();
  const alias = reader.readString();
  const title = flags[0] ? reader.readString() : null;
  const mime = reader.readString();
  const tags = readStringVec(reader);
  const navTitle = flags[1] ? reader.readString() : null;
  const navParentId = flags[2] ? reader.readString() : null;
  const navOrder = flags[3] ? reader.readI32() : null;
  const originalFilename = flags[4] ? reader.readString() : null;
  const isMarkdown = reader.readBool();
  return {
    id,
    alias,
    title,
    mime,
    tags,
    navTitle,
    navParentId,
    navOrder,
    originalFilename,
    isMarkdown,
  };
}

export function encodeSearchFindRequest(payload: SearchFindRequest): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [payload.tags !== null && payload.tags !== undefined];
  OptionMap.write(writer, optionFlags);
  writer.writeString(payload.query);
  writer.writeBool(payload.markdownOnly);
  if (optionFlags[0]) {
    writeStringVec(writer, payload.tags as string[]);
  }
  return writer.toUint8Array();
}

export function decodeSearchFindResponse(bytes: Uint8Array): SearchFindResponse {
  const reader = new WireReader(bytes);
  const hits = reader.readVec((itemReader) => readSearchListItem(itemReader));
  reader.ensureFullyConsumed();
  return { hits };
}

export function encodeSearchInvalidateRequest(
  payload: SearchInvalidateRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.id);
  return writer.toUint8Array();
}

export function encodeSearchResetRequest(_payload: SearchResetRequest): Uint8Array {
  const writer = new WireWriter();
  return writer.toUint8Array();
}

export function decodeMessageResponse(bytes: Uint8Array): MessageResponse {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { message };
}
