// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  SEARCH_ACTION_FIND,
  SEARCH_ACTION_FIND_ERR,
  SEARCH_ACTION_FIND_OK,
  SEARCH_ACTION_RESET,
  SEARCH_ACTION_RESET_ERR,
  SEARCH_ACTION_RESET_OK,
  SEARCH_DOMAIN_ID,
  decodeMessageResponse,
  decodeSearchFindResponse,
  encodeSearchFindRequest,
  encodeSearchResetRequest,
  type SearchFindRequest,
  type SearchFindResponse,
} from "../protocol/search";
import { getAdminWsClient } from "../transport/wsClient";
import { handleResponse } from "./response";

export async function findSearch(
  params: SearchFindRequest,
): Promise<SearchFindResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SEARCH_DOMAIN_ID,
    SEARCH_ACTION_FIND,
    encodeSearchFindRequest(params),
  );

  return handleResponse({
    response,
    domainId: SEARCH_DOMAIN_ID,
    okActionId: SEARCH_ACTION_FIND_OK,
    errActionId: SEARCH_ACTION_FIND_ERR,
    okDecoder: decodeSearchFindResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "search",
  });
}

export async function resetSearch(): Promise<{ message: string }> {
  const client = getAdminWsClient();
  const response = await client.request(
    SEARCH_DOMAIN_ID,
    SEARCH_ACTION_RESET,
    encodeSearchResetRequest({}),
  );

  return handleResponse({
    response,
    domainId: SEARCH_DOMAIN_ID,
    okActionId: SEARCH_ACTION_RESET_OK,
    errActionId: SEARCH_ACTION_RESET_ERR,
    okDecoder: decodeMessageResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "search",
  });
}
