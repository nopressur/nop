// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  ROLE_ACTION_ADD,
  ROLE_ACTION_ADD_ERR,
  ROLE_ACTION_ADD_OK,
  ROLE_ACTION_CHANGE,
  ROLE_ACTION_CHANGE_ERR,
  ROLE_ACTION_CHANGE_OK,
  ROLE_ACTION_DELETE,
  ROLE_ACTION_DELETE_ERR,
  ROLE_ACTION_DELETE_OK,
  ROLE_ACTION_LIST,
  ROLE_ACTION_LIST_ERR,
  ROLE_ACTION_LIST_OK,
  ROLE_ACTION_SHOW,
  ROLE_ACTION_SHOW_ERR,
  ROLE_ACTION_SHOW_OK,
  ROLES_DOMAIN_ID,
  decodeMessageResponse,
  decodeRoleListResponse,
  decodeRoleShowResponse,
  encodeRoleAddRequest,
  encodeRoleChangeRequest,
  encodeRoleDeleteRequest,
  encodeRoleListRequest,
  encodeRoleShowRequest,
} from "../protocol/roles";
import type { RoleShowResponse } from "../protocol/roles";
import { getAdminWsClient } from "../transport/wsClient";
import { handleResponse } from "./response";

export async function listRoles(): Promise<string[]> {
  const client = getAdminWsClient();
  const response = await client.request(
    ROLES_DOMAIN_ID,
    ROLE_ACTION_LIST,
    encodeRoleListRequest({}),
  );

  return handleResponse({
    response,
    domainId: ROLES_DOMAIN_ID,
    okActionId: ROLE_ACTION_LIST_OK,
    errActionId: ROLE_ACTION_LIST_ERR,
    okDecoder: (payload) => decodeRoleListResponse(payload).roles,
    errDecoder: decodeMessageResponse,
    domainLabel: "role",
  });
}

export async function getRole(role: string): Promise<RoleShowResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    ROLES_DOMAIN_ID,
    ROLE_ACTION_SHOW,
    encodeRoleShowRequest({ role }),
  );

  return handleResponse({
    response,
    domainId: ROLES_DOMAIN_ID,
    okActionId: ROLE_ACTION_SHOW_OK,
    errActionId: ROLE_ACTION_SHOW_ERR,
    okDecoder: decodeRoleShowResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "role",
  });
}

export async function createRole(role: string): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    ROLES_DOMAIN_ID,
    ROLE_ACTION_ADD,
    encodeRoleAddRequest({ role }),
  );

  handleResponse({
    response,
    domainId: ROLES_DOMAIN_ID,
    okActionId: ROLE_ACTION_ADD_OK,
    errActionId: ROLE_ACTION_ADD_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "role",
  });
}

export async function renameRole(role: string, newRole: string): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    ROLES_DOMAIN_ID,
    ROLE_ACTION_CHANGE,
    encodeRoleChangeRequest({ role, newRole }),
  );

  handleResponse({
    response,
    domainId: ROLES_DOMAIN_ID,
    okActionId: ROLE_ACTION_CHANGE_OK,
    errActionId: ROLE_ACTION_CHANGE_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "role",
  });
}

export async function deleteRole(role: string): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    ROLES_DOMAIN_ID,
    ROLE_ACTION_DELETE,
    encodeRoleDeleteRequest({ role }),
  );

  handleResponse({
    response,
    domainId: ROLES_DOMAIN_ID,
    okActionId: ROLE_ACTION_DELETE_OK,
    errActionId: ROLE_ACTION_DELETE_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "role",
  });
}
