// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { OptionMap, WireReader, WireWriter } from "./wire";

export const CONTENT_DOMAIN_ID = 12;
export const CONTENT_ACTION_LIST = 1;
export const CONTENT_ACTION_READ = 2;
export const CONTENT_ACTION_UPDATE = 3;
export const CONTENT_ACTION_DELETE = 4;
export const CONTENT_ACTION_UPLOAD = 5;
export const CONTENT_ACTION_NAV_INDEX = 6;
export const CONTENT_ACTION_BINARY_PREVALIDATE = 7;
export const CONTENT_ACTION_BINARY_UPLOAD_INIT = 8;
export const CONTENT_ACTION_BINARY_UPLOAD_COMMIT = 9;
export const CONTENT_ACTION_UPLOAD_STREAM_INIT = 10;
export const CONTENT_ACTION_UPLOAD_STREAM_COMMIT = 11;
export const CONTENT_ACTION_UPDATE_STREAM_INIT = 12;
export const CONTENT_ACTION_UPDATE_STREAM_COMMIT = 13;

export const CONTENT_ACTION_LIST_OK = 101;
export const CONTENT_ACTION_LIST_ERR = 102;
export const CONTENT_ACTION_READ_OK = 201;
export const CONTENT_ACTION_READ_ERR = 202;
export const CONTENT_ACTION_UPDATE_OK = 301;
export const CONTENT_ACTION_UPDATE_ERR = 302;
export const CONTENT_ACTION_DELETE_OK = 401;
export const CONTENT_ACTION_DELETE_ERR = 402;
export const CONTENT_ACTION_UPLOAD_OK = 501;
export const CONTENT_ACTION_UPLOAD_ERR = 502;
export const CONTENT_ACTION_NAV_INDEX_OK = 601;
export const CONTENT_ACTION_NAV_INDEX_ERR = 602;
export const CONTENT_ACTION_BINARY_PREVALIDATE_OK = 701;
export const CONTENT_ACTION_BINARY_PREVALIDATE_ERR = 702;
export const CONTENT_ACTION_BINARY_UPLOAD_INIT_OK = 801;
export const CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR = 802;
export const CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK = 901;
export const CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR = 902;
export const CONTENT_ACTION_UPLOAD_STREAM_INIT_OK = 1001;
export const CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR = 1002;
export const CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK = 1101;
export const CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR = 1102;
export const CONTENT_ACTION_UPDATE_STREAM_INIT_OK = 1201;
export const CONTENT_ACTION_UPDATE_STREAM_INIT_ERR = 1202;
export const CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK = 1301;
export const CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR = 1302;

export type ContentSortField = "title" | "alias" | "tags" | "mime" | "nav_title";
export type ContentSortDirection = "asc" | "desc";

const SORT_FIELD_TITLE = 0;
const SORT_FIELD_ALIAS = 1;
const SORT_FIELD_TAGS = 2;
const SORT_FIELD_MIME = 3;
const SORT_FIELD_NAV_TITLE = 4;

const SORT_DIRECTION_ASC = 0;
const SORT_DIRECTION_DESC = 1;

function writeStringVec(writer: WireWriter, values: string[]): void {
  writer.writeVec(values, (itemWriter, value) => itemWriter.writeString(value));
}

function readStringVec(reader: WireReader): string[] {
  return reader.readVec((itemReader) => itemReader.readString());
}

function writeContentSortField(writer: WireWriter, value: ContentSortField): void {
  switch (value) {
    case "title":
      writer.writeU32(SORT_FIELD_TITLE);
      return;
    case "alias":
      writer.writeU32(SORT_FIELD_ALIAS);
      return;
    case "tags":
      writer.writeU32(SORT_FIELD_TAGS);
      return;
    case "mime":
      writer.writeU32(SORT_FIELD_MIME);
      return;
    case "nav_title":
      writer.writeU32(SORT_FIELD_NAV_TITLE);
      return;
  }
}

function writeContentSortDirection(
  writer: WireWriter,
  value: ContentSortDirection,
): void {
  writer.writeU32(value === "asc" ? SORT_DIRECTION_ASC : SORT_DIRECTION_DESC);
}

export function encodeContentListRequest(payload: {
  page: number;
  pageSize: number;
  sortField: ContentSortField;
  sortDirection: ContentSortDirection;
  query?: string | null;
  tags?: string[] | null;
  markdownOnly: boolean;
}): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.query !== null && payload.query !== undefined,
    payload.tags !== null && payload.tags !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  writer.writeU32(payload.page);
  writer.writeU32(payload.pageSize);
  writeContentSortField(writer, payload.sortField);
  writeContentSortDirection(writer, payload.sortDirection);
  if (optionFlags[0]) {
    writer.writeString(payload.query as string);
  }
  if (optionFlags[1]) {
    writeStringVec(writer, payload.tags as string[]);
  }
  writer.writeBool(payload.markdownOnly);
  return writer.toUint8Array();
}

export function encodeContentReadRequest(payload: { id: string }): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.id);
  return writer.toUint8Array();
}

export function encodeContentUpdateRequest(payload: {
  id: string;
  newAlias?: string | null;
  title?: string | null;
  tags?: string[] | null;
  navTitle?: string | null;
  navParentId?: string | null;
  navOrder?: number | null;
  theme?: string | null;
  content?: string | null;
}): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.newAlias !== null && payload.newAlias !== undefined,
    payload.title !== null && payload.title !== undefined,
    payload.tags !== null && payload.tags !== undefined,
    payload.navTitle !== null && payload.navTitle !== undefined,
    payload.navParentId !== null && payload.navParentId !== undefined,
    payload.navOrder !== null && payload.navOrder !== undefined,
    payload.theme !== null && payload.theme !== undefined,
    payload.content !== null && payload.content !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  writer.writeString(payload.id);
  if (optionFlags[0]) {
    writer.writeString(payload.newAlias as string);
  }
  if (optionFlags[1]) {
    writer.writeString(payload.title as string);
  }
  if (optionFlags[2]) {
    writeStringVec(writer, payload.tags as string[]);
  }
  if (optionFlags[3]) {
    writer.writeString(payload.navTitle as string);
  }
  if (optionFlags[4]) {
    writer.writeString(payload.navParentId as string);
  }
  if (optionFlags[5]) {
    writer.writeI32(payload.navOrder as number);
  }
  if (optionFlags[6]) {
    writer.writeString(payload.theme as string);
  }
  if (optionFlags[7]) {
    writer.writeString(payload.content as string);
  }
  return writer.toUint8Array();
}

export function encodeContentDeleteRequest(payload: { id: string }): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.id);
  return writer.toUint8Array();
}

export function encodeContentNavIndexRequest(): Uint8Array {
  return new Uint8Array();
}

export function encodeContentUploadRequest(payload: {
  alias?: string | null;
  title?: string | null;
  mime: string;
  tags: string[];
  navTitle?: string | null;
  navParentId?: string | null;
  navOrder?: number | null;
  originalFilename?: string | null;
  theme?: string | null;
  content: Uint8Array;
}): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.alias !== null && payload.alias !== undefined,
    payload.title !== null && payload.title !== undefined,
    payload.navTitle !== null && payload.navTitle !== undefined,
    payload.navParentId !== null && payload.navParentId !== undefined,
    payload.navOrder !== null && payload.navOrder !== undefined,
    payload.originalFilename !== null && payload.originalFilename !== undefined,
    payload.theme !== null && payload.theme !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  if (optionFlags[0]) {
    writer.writeString(payload.alias as string);
  }
  if (optionFlags[1]) {
    writer.writeString(payload.title as string);
  }
  writer.writeString(payload.mime);
  writeStringVec(writer, payload.tags);
  if (optionFlags[2]) {
    writer.writeString(payload.navTitle as string);
  }
  if (optionFlags[3]) {
    writer.writeString(payload.navParentId as string);
  }
  if (optionFlags[4]) {
    writer.writeI32(payload.navOrder as number);
  }
  if (optionFlags[5]) {
    writer.writeString(payload.originalFilename as string);
  }
  if (optionFlags[6]) {
    writer.writeString(payload.theme as string);
  }
  writer.writeBytes(payload.content);
  return writer.toUint8Array();
}

export function encodeBinaryPrevalidateRequest(payload: {
  filename: string;
  mime: string;
  sizeBytes: number;
}): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.filename);
  writer.writeString(payload.mime);
  writer.writeU64(payload.sizeBytes);
  return writer.toUint8Array();
}

export function encodeBinaryUploadInitRequest(payload: {
  alias?: string | null;
  title?: string | null;
  tags: string[];
  filename: string;
  mime: string;
  sizeBytes: number;
}): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.alias !== null && payload.alias !== undefined,
    payload.title !== null && payload.title !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  if (optionFlags[0]) {
    writer.writeString(payload.alias as string);
  }
  if (optionFlags[1]) {
    writer.writeString(payload.title as string);
  }
  writeStringVec(writer, payload.tags);
  writer.writeString(payload.filename);
  writer.writeString(payload.mime);
  writer.writeU64(payload.sizeBytes);
  return writer.toUint8Array();
}

export function encodeBinaryUploadCommitRequest(payload: {
  uploadId: number;
}): Uint8Array {
  const writer = new WireWriter();
  writer.writeU32(payload.uploadId);
  return writer.toUint8Array();
}

export function encodeContentUploadStreamInitRequest(payload: {
  alias?: string | null;
  title?: string | null;
  tags: string[];
  navTitle?: string | null;
  navParentId?: string | null;
  navOrder?: number | null;
  theme?: string | null;
  sizeBytes: number;
}): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.alias !== null && payload.alias !== undefined,
    payload.title !== null && payload.title !== undefined,
    payload.navTitle !== null && payload.navTitle !== undefined,
    payload.navParentId !== null && payload.navParentId !== undefined,
    payload.navOrder !== null && payload.navOrder !== undefined,
    payload.theme !== null && payload.theme !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  if (optionFlags[0]) {
    writer.writeString(payload.alias as string);
  }
  if (optionFlags[1]) {
    writer.writeString(payload.title as string);
  }
  writeStringVec(writer, payload.tags);
  if (optionFlags[2]) {
    writer.writeString(payload.navTitle as string);
  }
  if (optionFlags[3]) {
    writer.writeString(payload.navParentId as string);
  }
  if (optionFlags[4]) {
    writer.writeI32(payload.navOrder as number);
  }
  if (optionFlags[5]) {
    writer.writeString(payload.theme as string);
  }
  writer.writeU64(payload.sizeBytes);
  return writer.toUint8Array();
}

export function encodeContentUploadStreamCommitRequest(payload: {
  uploadId: number;
}): Uint8Array {
  const writer = new WireWriter();
  writer.writeU32(payload.uploadId);
  return writer.toUint8Array();
}

export function encodeContentUpdateStreamInitRequest(payload: {
  id: string;
  newAlias?: string | null;
  title?: string | null;
  tags?: string[] | null;
  navTitle?: string | null;
  navParentId?: string | null;
  navOrder?: number | null;
  theme?: string | null;
  sizeBytes: number;
}): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.newAlias !== null && payload.newAlias !== undefined,
    payload.title !== null && payload.title !== undefined,
    payload.tags !== null && payload.tags !== undefined,
    payload.navTitle !== null && payload.navTitle !== undefined,
    payload.navParentId !== null && payload.navParentId !== undefined,
    payload.navOrder !== null && payload.navOrder !== undefined,
    payload.theme !== null && payload.theme !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  writer.writeString(payload.id);
  if (optionFlags[0]) {
    writer.writeString(payload.newAlias as string);
  }
  if (optionFlags[1]) {
    writer.writeString(payload.title as string);
  }
  if (optionFlags[2]) {
    writeStringVec(writer, payload.tags as string[]);
  }
  if (optionFlags[3]) {
    writer.writeString(payload.navTitle as string);
  }
  if (optionFlags[4]) {
    writer.writeString(payload.navParentId as string);
  }
  if (optionFlags[5]) {
    writer.writeI32(payload.navOrder as number);
  }
  if (optionFlags[6]) {
    writer.writeString(payload.theme as string);
  }
  writer.writeU64(payload.sizeBytes);
  return writer.toUint8Array();
}

export function encodeContentUpdateStreamCommitRequest(payload: {
  uploadId: number;
}): Uint8Array {
  const writer = new WireWriter();
  writer.writeU32(payload.uploadId);
  return writer.toUint8Array();
}

export function decodeMessageResponse(bytes: Uint8Array): { message: string } {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { message };
}

export function decodeBinaryPrevalidateResponse(bytes: Uint8Array): {
  accepted: boolean;
  message: string;
} {
  const reader = new WireReader(bytes);
  const accepted = reader.readBool();
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { accepted, message };
}

export function decodeUploadStreamInitResponse(bytes: Uint8Array): {
  uploadId: number;
  streamId: number;
  maxBytes: number;
  chunkBytes: number;
} {
  const reader = new WireReader(bytes);
  const uploadId = reader.readU32();
  const streamId = reader.readU32();
  const maxBytes = reader.readU64Number();
  const chunkBytes = reader.readU32();
  reader.ensureFullyConsumed();
  return { uploadId, streamId, maxBytes, chunkBytes };
}

export function decodeContentListResponse(bytes: Uint8Array): {
  total: number;
  page: number;
  pageSize: number;
  items: {
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
} {
  const reader = new WireReader(bytes);
  const total = reader.readU32();
  const page = reader.readU32();
  const pageSize = reader.readU32();
  const items = reader.readVec((itemReader) => {
    const flags = OptionMap.read(itemReader, 5);
    const id = itemReader.readString();
    const alias = itemReader.readString();
    const title = flags[0] ? itemReader.readString() : null;
    const mime = itemReader.readString();
    const tags = readStringVec(itemReader);
    const navTitle = flags[1] ? itemReader.readString() : null;
    const navParentId = flags[2] ? itemReader.readString() : null;
    const navOrder = flags[3] ? itemReader.readI32() : null;
    const originalFilename = flags[4] ? itemReader.readString() : null;
    const isMarkdown = itemReader.readBool();
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
  });
  reader.ensureFullyConsumed();
  return { total, page, pageSize, items };
}

export function decodeContentReadResponse(bytes: Uint8Array): {
  id: string;
  alias: string;
  title: string | null;
  mime: string;
  tags: string[];
  navTitle: string | null;
  navParentId: string | null;
  navOrder: number | null;
  originalFilename: string | null;
  theme: string | null;
  content: string | null;
} {
  const reader = new WireReader(bytes);
  const flags = OptionMap.read(reader, 7);
  const id = reader.readString();
  const alias = reader.readString();
  const title = flags[0] ? reader.readString() : null;
  const mime = reader.readString();
  const tags = readStringVec(reader);
  const navTitle = flags[1] ? reader.readString() : null;
  const navParentId = flags[2] ? reader.readString() : null;
  const navOrder = flags[3] ? reader.readI32() : null;
  const originalFilename = flags[4] ? reader.readString() : null;
  const theme = flags[5] ? reader.readString() : null;
  const content = flags[6] ? reader.readString() : null;
  reader.ensureFullyConsumed();
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
    theme,
    content,
  };
}

export function decodeContentUploadResponse(bytes: Uint8Array): {
  id: string;
  alias: string;
  mime: string;
  isMarkdown: boolean;
} {
  const reader = new WireReader(bytes);
  const id = reader.readString();
  const alias = reader.readString();
  const mime = reader.readString();
  const isMarkdown = reader.readBool();
  reader.ensureFullyConsumed();
  return { id, alias, mime, isMarkdown };
}

export function decodeContentNavIndexResponse(bytes: Uint8Array): {
  items: {
    id: string;
    alias: string;
    title: string | null;
    navTitle: string | null;
    navParentId: string | null;
    navOrder: number | null;
  }[];
} {
  const reader = new WireReader(bytes);
  const items = reader.readVec((itemReader) => {
    const flags = OptionMap.read(itemReader, 4);
    const id = itemReader.readString();
    const alias = itemReader.readString();
    const title = flags[0] ? itemReader.readString() : null;
    const navTitle = flags[1] ? itemReader.readString() : null;
    const navParentId = flags[2] ? itemReader.readString() : null;
    const navOrder = flags[3] ? itemReader.readI32() : null;
    return {
      id,
      alias,
      title,
      navTitle,
      navParentId,
      navOrder,
    };
  });
  reader.ensureFullyConsumed();
  return { items };
}
