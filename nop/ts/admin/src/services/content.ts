// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  CONTENT_ACTION_DELETE,
  CONTENT_ACTION_DELETE_ERR,
  CONTENT_ACTION_DELETE_OK,
  CONTENT_ACTION_LIST,
  CONTENT_ACTION_LIST_ERR,
  CONTENT_ACTION_LIST_OK,
  CONTENT_ACTION_BINARY_PREVALIDATE,
  CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
  CONTENT_ACTION_BINARY_PREVALIDATE_OK,
  CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
  CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
  CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
  CONTENT_ACTION_BINARY_UPLOAD_INIT,
  CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
  CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
  CONTENT_ACTION_READ,
  CONTENT_ACTION_READ_ERR,
  CONTENT_ACTION_READ_OK,
  CONTENT_ACTION_UPDATE_STREAM_COMMIT,
  CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
  CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
  CONTENT_ACTION_UPDATE_STREAM_INIT,
  CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
  CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
  CONTENT_ACTION_UPDATE,
  CONTENT_ACTION_UPDATE_ERR,
  CONTENT_ACTION_UPDATE_OK,
  CONTENT_ACTION_UPLOAD,
  CONTENT_ACTION_UPLOAD_ERR,
  CONTENT_ACTION_UPLOAD_OK,
  CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
  CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
  CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
  CONTENT_ACTION_UPLOAD_STREAM_INIT,
  CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
  CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
  CONTENT_ACTION_NAV_INDEX,
  CONTENT_ACTION_NAV_INDEX_ERR,
  CONTENT_ACTION_NAV_INDEX_OK,
  CONTENT_DOMAIN_ID,
  type ContentSortDirection,
  type ContentSortField,
  decodeBinaryPrevalidateResponse,
  decodeContentNavIndexResponse,
  decodeContentListResponse,
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
  encodeContentUpdateStreamCommitRequest,
  encodeContentUpdateStreamInitRequest,
  encodeContentUpdateRequest,
  encodeContentUploadStreamCommitRequest,
  encodeContentUploadStreamInitRequest,
  encodeContentUploadRequest,
} from "../protocol/content";
import { getAdminWsClient } from "../transport/wsClient";
import { MAX_TAG_ID_CHARS, TAG_ID_PATTERN } from "../validation/tags";
import { handleResponse } from "./response";

export type ContentListItem = {
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
};

export type ContentListResponse = {
  total: number;
  page: number;
  pageSize: number;
  items: ContentListItem[];
};

export type UploadStreamInitResponse = {
  uploadId: number;
  streamId: number;
  maxBytes: number;
  chunkBytes: number;
};

export async function listContent(params: {
  page: number;
  pageSize: number;
  sortField: ContentSortField;
  sortDirection: ContentSortDirection;
  query?: string | null;
  tags?: string[] | null;
  markdownOnly: boolean;
}): Promise<ContentListResponse> {
  const client = getAdminWsClient();
  const payload = encodeContentListRequest(params);
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_LIST,
    payload,
  );

  return handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_LIST_OK,
    errActionId: CONTENT_ACTION_LIST_ERR,
    okDecoder: decodeContentListResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function readContent(id: string): Promise<{
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
}> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_READ,
    encodeContentReadRequest({ id }),
  );

  return handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_READ_OK,
    errActionId: CONTENT_ACTION_READ_ERR,
    okDecoder: decodeContentReadResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function updateContent(params: {
  id: string;
  newAlias?: string | null;
  title?: string | null;
  tags?: string[] | null;
  navTitle?: string | null;
  navParentId?: string | null;
  navOrder?: number | null;
  theme?: string | null;
  content?: string | null;
}): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_UPDATE,
    encodeContentUpdateRequest(params),
  );

  handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_UPDATE_OK,
    errActionId: CONTENT_ACTION_UPDATE_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function deleteContent(id: string): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_DELETE,
    encodeContentDeleteRequest({ id }),
  );

  handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_DELETE_OK,
    errActionId: CONTENT_ACTION_DELETE_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function uploadContent(params: {
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
}): Promise<{ id: string; alias: string; mime: string; isMarkdown: boolean }> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_UPLOAD,
    encodeContentUploadRequest(params),
  );

  return handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_UPLOAD_OK,
    errActionId: CONTENT_ACTION_UPLOAD_ERR,
    okDecoder: decodeContentUploadResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function prevalidateBinaryUpload(params: {
  filename: string;
  mime: string;
  sizeBytes: number;
}): Promise<{ accepted: boolean; message: string }> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_BINARY_PREVALIDATE,
    encodeBinaryPrevalidateRequest(params),
  );

  return handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_BINARY_PREVALIDATE_OK,
    errActionId: CONTENT_ACTION_BINARY_PREVALIDATE_ERR,
    okDecoder: decodeBinaryPrevalidateResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function initBinaryUpload(params: {
  alias?: string | null;
  title?: string | null;
  tags: string[];
  filename: string;
  mime: string;
  sizeBytes: number;
}): Promise<UploadStreamInitResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_BINARY_UPLOAD_INIT,
    encodeBinaryUploadInitRequest(params),
  );

  return handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_BINARY_UPLOAD_INIT_OK,
    errActionId: CONTENT_ACTION_BINARY_UPLOAD_INIT_ERR,
    okDecoder: decodeUploadStreamInitResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function commitBinaryUpload(uploadId: number): Promise<{
  id: string;
  alias: string;
  mime: string;
  isMarkdown: boolean;
}> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_BINARY_UPLOAD_COMMIT,
    encodeBinaryUploadCommitRequest({ uploadId }),
  );

  return handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_OK,
    errActionId: CONTENT_ACTION_BINARY_UPLOAD_COMMIT_ERR,
    okDecoder: decodeContentUploadResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function uploadBinaryFile(params: {
  alias?: string | null;
  title?: string | null;
  tags: string[];
  file: File;
  onProgress?: (loaded: number, total: number) => void;
}): Promise<{ id: string; alias: string; mime: string; isMarkdown: boolean }> {
  const alias = params.alias?.trim() || null;
  const init = await initBinaryUpload({
    alias,
    title: params.title,
    tags: params.tags,
    filename: params.file.name,
    mime: params.file.type || "application/octet-stream",
    sizeBytes: params.file.size,
  });

  await streamFileUpload({
    streamId: init.streamId,
    file: params.file,
    chunkBytes: init.chunkBytes,
    onProgress: params.onProgress,
  });

  return commitBinaryUpload(init.uploadId);
}

export async function createMarkdownStream(params: {
  alias?: string | null;
  title: string;
  tags: string[];
  navTitle?: string | null;
  navParentId?: string | null;
  navOrder?: number | null;
  theme?: string | null;
  content: string;
}): Promise<{ id: string; alias: string; mime: string; isMarkdown: boolean }> {
  const encoder = new TextEncoder();
  const payload = encoder.encode(params.content);

  const client = getAdminWsClient();
  const initResponse = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_UPLOAD_STREAM_INIT,
    encodeContentUploadStreamInitRequest({
      alias: params.alias ?? null,
      title: params.title,
      tags: params.tags,
      navTitle: params.navTitle ?? null,
      navParentId: params.navParentId ?? null,
      navOrder: params.navOrder ?? null,
      theme: params.theme ?? null,
      sizeBytes: payload.length,
    }),
  );

  const init = handleResponse({
    response: initResponse,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_UPLOAD_STREAM_INIT_OK,
    errActionId: CONTENT_ACTION_UPLOAD_STREAM_INIT_ERR,
    okDecoder: decodeUploadStreamInitResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
  await client.streamPayload({
    streamId: init.streamId,
    payload,
    chunkBytes: init.chunkBytes,
  });

  const commitResponse = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_UPLOAD_STREAM_COMMIT,
    encodeContentUploadStreamCommitRequest({ uploadId: init.uploadId }),
  );

  return handleResponse({
    response: commitResponse,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_OK,
    errActionId: CONTENT_ACTION_UPLOAD_STREAM_COMMIT_ERR,
    okDecoder: decodeContentUploadResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export async function updateMarkdownStream(params: {
  id: string;
  newAlias?: string | null;
  title?: string | null;
  tags?: string[] | null;
  navTitle?: string | null;
  navParentId?: string | null;
  navOrder?: number | null;
  theme?: string | null;
  content: string;
}): Promise<void> {
  const encoder = new TextEncoder();
  const payload = encoder.encode(params.content);

  const client = getAdminWsClient();
  const initResponse = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_UPDATE_STREAM_INIT,
    encodeContentUpdateStreamInitRequest({
      id: params.id,
      newAlias: params.newAlias ?? null,
      title: params.title ?? null,
      tags: params.tags ?? null,
      navTitle: params.navTitle ?? null,
      navParentId: params.navParentId ?? null,
      navOrder: params.navOrder ?? null,
      theme: params.theme ?? null,
      sizeBytes: payload.length,
    }),
  );

  const init = handleResponse({
    response: initResponse,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_UPDATE_STREAM_INIT_OK,
    errActionId: CONTENT_ACTION_UPDATE_STREAM_INIT_ERR,
    okDecoder: decodeUploadStreamInitResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
  await client.streamPayload({
    streamId: init.streamId,
    payload,
    chunkBytes: init.chunkBytes,
  });

  const commitResponse = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_UPDATE_STREAM_COMMIT,
    encodeContentUpdateStreamCommitRequest({ uploadId: init.uploadId }),
  );

  handleResponse({
    response: commitResponse,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_UPDATE_STREAM_COMMIT_OK,
    errActionId: CONTENT_ACTION_UPDATE_STREAM_COMMIT_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export type ContentNavIndexItem = {
  id: string;
  alias: string;
  title: string | null;
  navTitle: string | null;
  navParentId: string | null;
  navOrder: number | null;
};

export async function listNavIndex(): Promise<ContentNavIndexItem[]> {
  const client = getAdminWsClient();
  const response = await client.request(
    CONTENT_DOMAIN_ID,
    CONTENT_ACTION_NAV_INDEX,
    encodeContentNavIndexRequest(),
  );

  return handleResponse({
    response,
    domainId: CONTENT_DOMAIN_ID,
    okActionId: CONTENT_ACTION_NAV_INDEX_OK,
    errActionId: CONTENT_ACTION_NAV_INDEX_ERR,
    okDecoder: (payload) => decodeContentNavIndexResponse(payload).items,
    errDecoder: decodeMessageResponse,
    domainLabel: "content",
  });
}

export function parseContentTags(value: string): { tags: string[]; error?: string } {
  if (!value || !value.trim()) {
    return { tags: [] };
  }
  const tags = value
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  for (const tag of tags) {
    if (tag.length > MAX_TAG_ID_CHARS) {
      return { tags: [], error: `Tag '${tag}' is too long` };
    }
    if (!TAG_ID_PATTERN.test(tag)) {
      return { tags: [], error: `Invalid tag '${tag}'` };
    }
  }

  return { tags };
}

function slugifyFilename(name: string): string {
  const lower = name.toLowerCase().trim();
  const replaced = lower.replace(/\s+/g, "-");
  return replaced.replace(/[^a-z0-9._-]/g, "-");
}

export function defaultAliasForFile(file: File): string {
  const type = (file.type || "").toLowerCase();
  let prefix = "files";
  if (type.startsWith("image/")) {
    prefix = "images";
  } else if (type.startsWith("video/")) {
    prefix = "videos";
  }
  return `${prefix}/${slugifyFilename(file.name)}`;
}

async function streamFileUpload(params: {
  streamId: number;
  file: File;
  chunkBytes: number;
  onProgress?: (loaded: number, total: number) => void;
}): Promise<void> {
  if (params.chunkBytes <= 0) {
    throw new Error("chunkBytes must be positive");
  }
  const total = params.file.size;
  if (!Number.isFinite(total) || total <= 0) {
    throw new Error("Upload size must be greater than 0");
  }

  const client = getAdminWsClient();
  if (!params.file.stream) {
    const buffer = new Uint8Array(await params.file.arrayBuffer());
    await client.streamPayload({
      streamId: params.streamId,
      payload: buffer,
      chunkBytes: params.chunkBytes,
      onProgress: params.onProgress,
    });
    return;
  }

  const reader = params.file.stream().getReader();
  let loaded = 0;
  let seq = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    if (!value || value.length === 0) {
      continue;
    }
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
    for (let offset = 0; offset < chunk.length; offset += params.chunkBytes) {
      const end = Math.min(offset + params.chunkBytes, chunk.length);
      const slice = chunk.subarray(offset, end);
      loaded += slice.length;
      const isFinal = loaded === total;
      await client.sendStreamChunk(params.streamId, seq, slice, isFinal);
      params.onProgress?.(loaded, total);
      seq += 1;
    }
  }

  if (loaded !== total) {
    throw new Error("Upload size mismatch");
  }
}

export function buildInsertSnippet(params: {
  mime: string;
  alias?: string | null;
  id?: string | null;
  title?: string | null;
  filename?: string | null;
}): string {
  const display = params.title || params.filename || "file";
  const alias = params.alias?.trim();
  const path = alias
    ? alias.startsWith("/")
      ? alias
      : `/${alias}`
    : params.id
      ? `/id/${params.id}`
      : "/";
  if (params.mime.startsWith("image/")) {
    return `![${display}](${path})`;
  }
  if (params.mime.startsWith("video/")) {
    return `((video src="${path}"))`;
  }
  return `[${display}](${path})`;
}
