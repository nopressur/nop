// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

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
  SYSTEM_DOMAIN_ID,
  decodeClearLogsResponse,
  decodeLoggingConfigResponse,
  decodeMessageResponse,
  encodeLoggingClearRequest,
  encodeLoggingGetRequest,
  encodeLoggingSetRequest,
} from "../protocol/system";
import type {
  ClearLogsResponse,
  LoggingConfigResponse,
  LoggingSetRequest,
} from "../protocol/system";
import { getAdminWsClient } from "../transport/wsClient";
import { handleResponse } from "./response";

export async function fetchLoggingConfig(): Promise<LoggingConfigResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SYSTEM_DOMAIN_ID,
    SYSTEM_ACTION_LOGGING_GET,
    encodeLoggingGetRequest({}),
  );

  return handleResponse({
    response,
    domainId: SYSTEM_DOMAIN_ID,
    okActionId: SYSTEM_ACTION_LOGGING_GET_OK,
    errActionId: SYSTEM_ACTION_LOGGING_GET_ERR,
    okDecoder: decodeLoggingConfigResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "system",
    actionLabel: "system logging",
  });
}

export async function updateLoggingConfig(
  payload: LoggingSetRequest,
): Promise<LoggingConfigResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SYSTEM_DOMAIN_ID,
    SYSTEM_ACTION_LOGGING_SET,
    encodeLoggingSetRequest(payload),
  );

  return handleResponse({
    response,
    domainId: SYSTEM_DOMAIN_ID,
    okActionId: SYSTEM_ACTION_LOGGING_SET_OK,
    errActionId: SYSTEM_ACTION_LOGGING_SET_ERR,
    okDecoder: decodeLoggingConfigResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "system",
    actionLabel: "system logging",
  });
}

export async function clearLogs(): Promise<ClearLogsResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SYSTEM_DOMAIN_ID,
    SYSTEM_ACTION_LOGGING_CLEAR,
    encodeLoggingClearRequest({}),
  );

  return handleResponse({
    response,
    domainId: SYSTEM_DOMAIN_ID,
    okActionId: SYSTEM_ACTION_LOGGING_CLEAR_OK,
    errActionId: SYSTEM_ACTION_LOGGING_CLEAR_ERR,
    okDecoder: decodeClearLogsResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "system",
    actionLabel: "system logging",
  });
}
