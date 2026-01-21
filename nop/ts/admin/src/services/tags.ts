// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  TAG_ACTION_ADD,
  TAG_ACTION_ADD_ERR,
  TAG_ACTION_ADD_OK,
  TAG_ACTION_CHANGE,
  TAG_ACTION_CHANGE_ERR,
  TAG_ACTION_CHANGE_OK,
  TAG_ACTION_DELETE,
  TAG_ACTION_DELETE_ERR,
  TAG_ACTION_DELETE_OK,
  TAG_ACTION_LIST,
  TAG_ACTION_LIST_ERR,
  TAG_ACTION_LIST_OK,
  TAG_ACTION_SHOW,
  TAG_ACTION_SHOW_ERR,
  TAG_ACTION_SHOW_OK,
  TAGS_DOMAIN_ID,
  decodeMessageResponse,
  decodeTagListResponse,
  decodeTagShowResponse,
  encodeTagAddRequest,
  encodeTagChangeRequest,
  encodeTagDeleteRequest,
  encodeTagListRequest,
  encodeTagShowRequest,
} from "../protocol/tags";
import type { AccessRule, TagShowResponse, TagSummary } from "../protocol/tags";
import { getAdminWsClient } from "../transport/wsClient";
import { handleResponse } from "./response";

export async function listTags(): Promise<TagSummary[]> {
  const client = getAdminWsClient();
  const response = await client.request(
    TAGS_DOMAIN_ID,
    TAG_ACTION_LIST,
    encodeTagListRequest({}),
  );

  return handleResponse({
    response,
    domainId: TAGS_DOMAIN_ID,
    okActionId: TAG_ACTION_LIST_OK,
    errActionId: TAG_ACTION_LIST_ERR,
    okDecoder: (payload) => decodeTagListResponse(payload).tags,
    errDecoder: decodeMessageResponse,
    domainLabel: "tag",
  });
}

export async function getTag(id: string): Promise<TagShowResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    TAGS_DOMAIN_ID,
    TAG_ACTION_SHOW,
    encodeTagShowRequest({ id }),
  );

  return handleResponse({
    response,
    domainId: TAGS_DOMAIN_ID,
    okActionId: TAG_ACTION_SHOW_OK,
    errActionId: TAG_ACTION_SHOW_ERR,
    okDecoder: decodeTagShowResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "tag",
  });
}

export async function createTag(params: {
  id: string;
  name: string;
  roles: string[];
  accessRule?: AccessRule | null;
}): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    TAGS_DOMAIN_ID,
    TAG_ACTION_ADD,
    encodeTagAddRequest(params),
  );

  handleResponse({
    response,
    domainId: TAGS_DOMAIN_ID,
    okActionId: TAG_ACTION_ADD_OK,
    errActionId: TAG_ACTION_ADD_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "tag",
  });
}

export async function updateTag(params: {
  id: string;
  newId?: string | null;
  name?: string | null;
  roles?: string[] | null;
  accessRule?: AccessRule | null;
  clearAccess: boolean;
}): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    TAGS_DOMAIN_ID,
    TAG_ACTION_CHANGE,
    encodeTagChangeRequest(params),
  );

  handleResponse({
    response,
    domainId: TAGS_DOMAIN_ID,
    okActionId: TAG_ACTION_CHANGE_OK,
    errActionId: TAG_ACTION_CHANGE_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "tag",
  });
}

export async function deleteTag(id: string): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    TAGS_DOMAIN_ID,
    TAG_ACTION_DELETE,
    encodeTagDeleteRequest({ id }),
  );

  handleResponse({
    response,
    domainId: TAGS_DOMAIN_ID,
    okActionId: TAG_ACTION_DELETE_OK,
    errActionId: TAG_ACTION_DELETE_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "tag",
  });
}
