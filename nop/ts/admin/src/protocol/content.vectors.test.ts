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
  parseBytes,
  parseNumber,
  parseOptionalNumber,
  parseOptionalString,
  parseOptionalStringArray,
  parseString,
  parseStringArray,
  parseU64,
} from "./fixtures";
import {
  CONTENT_ACTION_BINARY_PREVALIDATE,
  CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
  CONTENT_ACTION_BINARY_PREVALIDATE_OK,
  CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
  CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
  CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
  CONTENT_ACTION_BINARY_UPLOAD_INIT,
  CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
  CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
  CONTENT_ACTION_DELETE,
  CONTENT_ACTION_DELETE_ERR,
  CONTENT_ACTION_DELETE_OK,
  CONTENT_ACTION_LIST,
  CONTENT_ACTION_LIST_ERR,
  CONTENT_ACTION_LIST_OK,
  CONTENT_ACTION_NAV_INDEX,
  CONTENT_ACTION_NAV_INDEX_ERR,
  CONTENT_ACTION_NAV_INDEX_OK,
  CONTENT_ACTION_READ,
  CONTENT_ACTION_READ_ERR,
  CONTENT_ACTION_READ_OK,
  CONTENT_ACTION_UPDATE,
  CONTENT_ACTION_UPDATE_ERR,
  CONTENT_ACTION_UPDATE_OK,
  CONTENT_ACTION_UPDATE_STREAM_COMMIT,
  CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
  CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
  CONTENT_ACTION_UPDATE_STREAM_INIT,
  CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
  CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
  CONTENT_ACTION_UPLOAD,
  CONTENT_ACTION_UPLOAD_ERR,
  CONTENT_ACTION_UPLOAD_OK,
  CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
  CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
  CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
  CONTENT_ACTION_UPLOAD_STREAM_INIT,
  CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
  CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
  CONTENT_DOMAIN_ID,
  type ContentSortDirection,
  type ContentSortField,
  decodeBinaryPrevalidateResponse,
  decodeContentListResponse,
  decodeContentNavIndexResponse,
  decodeContentReadResponse,
  decodeContentUploadResponse,
  decodeMessageResponse,
  decodeUploadStreamInitResponse,
  encodeBinaryPrevalidateRequest,
  encodeBinaryUploadCommitRequest,
  encodeBinaryUploadInitRequest,
  encodeContentDeleteRequest,
  encodeContentListRequest,
  encodeContentNavIndexRequest,
  encodeContentReadRequest,
  encodeContentUpdateRequest,
  encodeContentUploadRequest,
  encodeContentUploadStreamCommitRequest,
  encodeContentUploadStreamInitRequest,
  encodeContentUpdateStreamCommitRequest,
  encodeContentUpdateStreamInitRequest,
} from "./content";

describe("content wire vectors", () => {
  const entries = loadVectorEntries().filter(
    (entry) => entry.domain_id === CONTENT_DOMAIN_ID,
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
});

function encodeRequest(
  actionId: number,
  payload: Record<string, unknown>,
  name: string,
): Uint8Array {
  switch (actionId) {
    case CONTENT_ACTION_LIST:
      return encodeContentListRequest({
        page: parseNumber(payload.page, `${name}.page`),
        pageSize: parseNumber(payload.page_size, `${name}.page_size`),
        sortField: parseString(
          payload.sort_field,
          `${name}.sort_field`,
        ) as ContentSortField,
        sortDirection: parseString(
          payload.sort_direction,
          `${name}.sort_direction`,
        ) as ContentSortDirection,
        query: parseOptionalString(payload.query, `${name}.query`),
        tags: parseOptionalStringArray(payload.tags, `${name}.tags`),
        markdownOnly: parseBool(payload.markdown_only, `${name}.markdown_only`),
      });
    case CONTENT_ACTION_READ:
      return encodeContentReadRequest({
        id: parseString(payload.id, `${name}.id`),
      });
    case CONTENT_ACTION_UPDATE:
      return encodeContentUpdateRequest({
        id: parseString(payload.id, `${name}.id`),
        newAlias: parseOptionalString(payload.new_alias, `${name}.new_alias`),
        title: parseOptionalString(payload.title, `${name}.title`),
        tags: parseOptionalStringArray(payload.tags, `${name}.tags`),
        navTitle: parseOptionalString(payload.nav_title, `${name}.nav_title`),
        navParentId: parseOptionalString(payload.nav_parent_id, `${name}.nav_parent_id`),
        navOrder: parseOptionalNumber(payload.nav_order, `${name}.nav_order`),
        theme: parseOptionalString(payload.theme, `${name}.theme`),
        content: parseOptionalString(payload.content, `${name}.content`),
      });
    case CONTENT_ACTION_DELETE:
      return encodeContentDeleteRequest({
        id: parseString(payload.id, `${name}.id`),
      });
    case CONTENT_ACTION_UPLOAD:
      return encodeContentUploadRequest({
        alias: parseOptionalString(payload.alias, `${name}.alias`),
        title: parseOptionalString(payload.title, `${name}.title`),
        mime: parseString(payload.mime, `${name}.mime`),
        tags: parseStringArray(payload.tags, `${name}.tags`),
        navTitle: parseOptionalString(payload.nav_title, `${name}.nav_title`),
        navParentId: parseOptionalString(payload.nav_parent_id, `${name}.nav_parent_id`),
        navOrder: parseOptionalNumber(payload.nav_order, `${name}.nav_order`),
        originalFilename: parseOptionalString(
          payload.original_filename,
          `${name}.original_filename`,
        ),
        theme: parseOptionalString(payload.theme, `${name}.theme`),
        content: parseBytes(payload.content, `${name}.content`),
      });
    case CONTENT_ACTION_NAV_INDEX:
      return encodeContentNavIndexRequest();
    case CONTENT_ACTION_BINARY_PREVALIDATE:
      return encodeBinaryPrevalidateRequest({
        filename: parseString(payload.filename, `${name}.filename`),
        mime: parseString(payload.mime, `${name}.mime`),
        sizeBytes: parseU64(payload.size_bytes, `${name}.size_bytes`),
      });
    case CONTENT_ACTION_BINARY_UPLOAD_INIT:
      return encodeBinaryUploadInitRequest({
        alias: parseOptionalString(payload.alias, `${name}.alias`),
        title: parseOptionalString(payload.title, `${name}.title`),
        tags: parseStringArray(payload.tags, `${name}.tags`),
        filename: parseString(payload.filename, `${name}.filename`),
        mime: parseString(payload.mime, `${name}.mime`),
        sizeBytes: parseU64(payload.size_bytes, `${name}.size_bytes`),
      });
    case CONTENT_ACTION_BINARY_UPLOAD_COMMIT:
      return encodeBinaryUploadCommitRequest({
        uploadId: parseNumber(payload.upload_id, `${name}.upload_id`),
      });
    case CONTENT_ACTION_UPLOAD_STREAM_INIT:
      return encodeContentUploadStreamInitRequest({
        alias: parseOptionalString(payload.alias, `${name}.alias`),
        title: parseOptionalString(payload.title, `${name}.title`),
        tags: parseStringArray(payload.tags, `${name}.tags`),
        navTitle: parseOptionalString(payload.nav_title, `${name}.nav_title`),
        navParentId: parseOptionalString(payload.nav_parent_id, `${name}.nav_parent_id`),
        navOrder: parseOptionalNumber(payload.nav_order, `${name}.nav_order`),
        theme: parseOptionalString(payload.theme, `${name}.theme`),
        sizeBytes: parseU64(payload.size_bytes, `${name}.size_bytes`),
      });
    case CONTENT_ACTION_UPLOAD_STREAM_COMMIT:
      return encodeContentUploadStreamCommitRequest({
        uploadId: parseNumber(payload.upload_id, `${name}.upload_id`),
      });
    case CONTENT_ACTION_UPDATE_STREAM_INIT:
      return encodeContentUpdateStreamInitRequest({
        id: parseString(payload.id, `${name}.id`),
        newAlias: parseOptionalString(payload.new_alias, `${name}.new_alias`),
        title: parseOptionalString(payload.title, `${name}.title`),
        tags: parseOptionalStringArray(payload.tags, `${name}.tags`),
        navTitle: parseOptionalString(payload.nav_title, `${name}.nav_title`),
        navParentId: parseOptionalString(payload.nav_parent_id, `${name}.nav_parent_id`),
        navOrder: parseOptionalNumber(payload.nav_order, `${name}.nav_order`),
        theme: parseOptionalString(payload.theme, `${name}.theme`),
        sizeBytes: parseU64(payload.size_bytes, `${name}.size_bytes`),
      });
    case CONTENT_ACTION_UPDATE_STREAM_COMMIT:
      return encodeContentUpdateStreamCommitRequest({
        uploadId: parseNumber(payload.upload_id, `${name}.upload_id`),
      });
    default:
      throw new Error(`Unhandled content request action ${actionId}`);
  }
}

function decodeResponse(actionId: number, bytes: Uint8Array): unknown {
  switch (actionId) {
    case CONTENT_ACTION_LIST_ERR:
    case CONTENT_ACTION_READ_ERR:
    case CONTENT_ACTION_UPDATE_OK:
    case CONTENT_ACTION_UPDATE_ERR:
    case CONTENT_ACTION_DELETE_OK:
    case CONTENT_ACTION_DELETE_ERR:
    case CONTENT_ACTION_UPLOAD_ERR:
    case CONTENT_ACTION_NAV_INDEX_ERR:
    case CONTENT_ACTION_BINARY_PREVALIDATE_ERR:
    case CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR:
    case CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR:
    case CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR:
    case CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR:
    case CONTENT_ACTION_UPDATE_STREAM_INIT_ERR:
    case CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK:
    case CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR:
      return decodeMessageResponse(bytes);
    case CONTENT_ACTION_LIST_OK:
      return normalizeContentListResponse(decodeContentListResponse(bytes));
    case CONTENT_ACTION_READ_OK:
      return normalizeContentReadResponse(decodeContentReadResponse(bytes));
    case CONTENT_ACTION_UPLOAD_OK:
    case CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK:
    case CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK:
      return normalizeContentUploadResponse(decodeContentUploadResponse(bytes));
    case CONTENT_ACTION_NAV_INDEX_OK:
      return normalizeContentNavIndexResponse(decodeContentNavIndexResponse(bytes));
    case CONTENT_ACTION_BINARY_PREVALIDATE_OK:
      return decodeBinaryPrevalidateResponse(bytes);
    case CONTENT_ACTION_BINARY_UPLOAD_INIT_OK:
    case CONTENT_ACTION_UPLOAD_STREAM_INIT_OK:
    case CONTENT_ACTION_UPDATE_STREAM_INIT_OK:
      return normalizeUploadStreamInitResponse(decodeUploadStreamInitResponse(bytes));
    default:
      throw new Error(`Unhandled content response action ${actionId}`);
  }
}

function normalizeContentListResponse(response: {
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
}): unknown {
  return {
    total: response.total,
    page: response.page,
    page_size: response.pageSize,
    items: response.items.map((item) => ({
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

function normalizeContentReadResponse(response: {
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
}): unknown {
  return {
    id: response.id,
    alias: response.alias,
    title: response.title,
    mime: response.mime,
    tags: response.tags,
    nav_title: response.navTitle,
    nav_parent_id: response.navParentId,
    nav_order: response.navOrder,
    original_filename: response.originalFilename,
    theme: response.theme,
    content: response.content,
  };
}

function normalizeContentUploadResponse(response: {
  id: string;
  alias: string;
  mime: string;
  isMarkdown: boolean;
}): unknown {
  return {
    id: response.id,
    alias: response.alias,
    mime: response.mime,
    is_markdown: response.isMarkdown,
  };
}

function normalizeContentNavIndexResponse(response: {
  items: {
    id: string;
    alias: string;
    title: string | null;
    navTitle: string | null;
    navParentId: string | null;
    navOrder: number | null;
  }[];
}): unknown {
  return {
    items: response.items.map((item) => ({
      id: item.id,
      alias: item.alias,
      title: item.title,
      nav_title: item.navTitle,
      nav_parent_id: item.navParentId,
      nav_order: item.navOrder,
    })),
  };
}

function normalizeUploadStreamInitResponse(response: {
  uploadId: number;
  streamId: number;
  maxBytes: number;
  chunkBytes: number;
}): unknown {
  return {
    upload_id: response.uploadId,
    stream_id: response.streamId,
    max_bytes: response.maxBytes,
    chunk_bytes: response.chunkBytes,
  };
}
