// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

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
} from "../protocol/settings";
import type { SettingsResponse } from "../protocol/settings";
import { getAdminWsClient } from "../transport/wsClient";
import { handleResponse } from "./response";

export async function fetchSettings(): Promise<SettingsResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SETTINGS_DOMAIN_ID,
    SETTINGS_ACTION_GET,
    encodeSettingsGetRequest({}),
  );

  return handleResponse({
    response,
    domainId: SETTINGS_DOMAIN_ID,
    okActionId: SETTINGS_ACTION_GET_OK,
    errActionId: SETTINGS_ACTION_GET_ERR,
    okDecoder: decodeSettingsResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "settings",
  });
}

export async function updateWebsiteName(name: string): Promise<SettingsResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SETTINGS_DOMAIN_ID,
    SETTINGS_ACTION_SET_NAME,
    encodeSettingsSetNameRequest({ name }),
  );

  return handleResponse({
    response,
    domainId: SETTINGS_DOMAIN_ID,
    okActionId: SETTINGS_ACTION_SET_NAME_OK,
    errActionId: SETTINGS_ACTION_SET_NAME_ERR,
    okDecoder: decodeSettingsResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "settings",
    actionLabel: "settings name",
  });
}

export async function updateWebsiteTitle(title: string | null): Promise<SettingsResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SETTINGS_DOMAIN_ID,
    SETTINGS_ACTION_SET_TITLE,
    encodeSettingsSetTitleRequest({ title }),
  );

  return handleResponse({
    response,
    domainId: SETTINGS_DOMAIN_ID,
    okActionId: SETTINGS_ACTION_SET_TITLE_OK,
    errActionId: SETTINGS_ACTION_SET_TITLE_ERR,
    okDecoder: decodeSettingsResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "settings",
    actionLabel: "settings title",
  });
}

export async function updateWebsiteDescription(
  description: string | null,
): Promise<SettingsResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    SETTINGS_DOMAIN_ID,
    SETTINGS_ACTION_SET_DESCRIPTION,
    encodeSettingsSetDescriptionRequest({ description }),
  );

  return handleResponse({
    response,
    domainId: SETTINGS_DOMAIN_ID,
    okActionId: SETTINGS_ACTION_SET_DESCRIPTION_OK,
    errActionId: SETTINGS_ACTION_SET_DESCRIPTION_ERR,
    okDecoder: decodeSettingsResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "settings",
    actionLabel: "settings description",
  });
}
