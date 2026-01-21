// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import {
  USER_ACTION_ADD,
  USER_ACTION_ADD_ERR,
  USER_ACTION_ADD_OK,
  USER_ACTION_CHANGE,
  USER_ACTION_CHANGE_ERR,
  USER_ACTION_CHANGE_OK,
  USER_ACTION_DELETE,
  USER_ACTION_DELETE_ERR,
  USER_ACTION_DELETE_OK,
  USER_ACTION_LIST,
  USER_ACTION_LIST_ERR,
  USER_ACTION_LIST_OK,
  USER_ACTION_PASSWORD_SET,
  USER_ACTION_PASSWORD_SET_ERR,
  USER_ACTION_PASSWORD_SET_OK,
  USER_ACTION_PASSWORD_SALT,
  USER_ACTION_PASSWORD_SALT_ERR,
  USER_ACTION_PASSWORD_SALT_OK,
  USER_ACTION_ROLE_ADD,
  USER_ACTION_ROLE_ADD_ERR,
  USER_ACTION_ROLE_ADD_OK,
  USER_ACTION_ROLE_REMOVE,
  USER_ACTION_ROLE_REMOVE_ERR,
  USER_ACTION_ROLE_REMOVE_OK,
  USER_ACTION_SHOW,
  USER_ACTION_SHOW_ERR,
  USER_ACTION_SHOW_OK,
  USERS_DOMAIN_ID,
  decodePasswordSaltResponse,
  decodeMessageResponse,
  decodeUserListResponse,
  decodeUserShowResponse,
  encodeUserAddRequest,
  encodeUserChangeRequest,
  encodeUserDeleteRequest,
  encodeUserPasswordSetRequest,
  encodeUserPasswordSaltRequest,
  encodeUserRoleAddRequest,
  encodeUserRoleRemoveRequest,
  encodeUserShowRequest,
} from "../protocol/users";
import type { PasswordPayload, PasswordSaltResponse, UserShowResponse, UserSummary } from "../protocol/users";
import { deriveFrontEndHash } from "../argon";
import { getAdminRuntimeConfig } from "../config/runtime";
import { getAdminWsClient } from "../transport/wsClient";
import { handleResponse } from "./response";

async function requestPasswordSalt(email: string): Promise<PasswordSaltResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_PASSWORD_SALT,
    encodeUserPasswordSaltRequest({ email }),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_PASSWORD_SALT_OK,
    errActionId: USER_ACTION_PASSWORD_SALT_ERR,
    okDecoder: decodePasswordSaltResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

async function buildPasswordPayload(
  email: string,
  password: string,
): Promise<{ payload: PasswordPayload; changeToken: string }> {
  const salt = await requestPasswordSalt(email);
  const { passwordFrontEnd } = getAdminRuntimeConfig();
  const front_end_hash = await deriveFrontEndHash(
    password,
    salt.next_front_end_salt,
    passwordFrontEnd,
  );
  return {
    payload: {
      kind: "front_end_hash",
      front_end_hash,
      front_end_salt: salt.next_front_end_salt,
    },
    changeToken: salt.change_token,
  };
}

export async function listUsers(): Promise<UserSummary[]> {
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_LIST,
    new Uint8Array(0),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_LIST_OK,
    errActionId: USER_ACTION_LIST_ERR,
    okDecoder: (payload) => decodeUserListResponse(payload).users,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

export async function getUser(email: string): Promise<UserShowResponse> {
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_SHOW,
    encodeUserShowRequest({ email }),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_SHOW_OK,
    errActionId: USER_ACTION_SHOW_ERR,
    okDecoder: decodeUserShowResponse,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

export async function createUser(params: {
  email: string;
  name: string;
  password: string;
  roles: string[];
}): Promise<string> {
  const { payload, changeToken } = await buildPasswordPayload(
    params.email,
    params.password,
  );
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_ADD,
    encodeUserAddRequest({
      ...params,
      password: payload,
      change_token: changeToken,
    }),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_ADD_OK,
    errActionId: USER_ACTION_ADD_ERR,
    okDecoder: (payload) => decodeMessageResponse(payload).message,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

export async function updateUserName(email: string, name: string): Promise<string> {
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_CHANGE,
    encodeUserChangeRequest({ email, name, roles: null }),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_CHANGE_OK,
    errActionId: USER_ACTION_CHANGE_ERR,
    okDecoder: (payload) => decodeMessageResponse(payload).message,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

export async function updateUserPassword(email: string, password: string): Promise<string> {
  const { payload, changeToken } = await buildPasswordPayload(email, password);
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_PASSWORD_SET,
    encodeUserPasswordSetRequest({
      email,
      password: payload,
      change_token: changeToken,
    }),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_PASSWORD_SET_OK,
    errActionId: USER_ACTION_PASSWORD_SET_ERR,
    okDecoder: (payload) => decodeMessageResponse(payload).message,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

export async function addUserRole(email: string, role: string): Promise<string> {
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_ROLE_ADD,
    encodeUserRoleAddRequest({ email, role }),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_ROLE_ADD_OK,
    errActionId: USER_ACTION_ROLE_ADD_ERR,
    okDecoder: (payload) => decodeMessageResponse(payload).message,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

export async function removeUserRole(email: string, role: string): Promise<string> {
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_ROLE_REMOVE,
    encodeUserRoleRemoveRequest({ email, role }),
  );

  return handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_ROLE_REMOVE_OK,
    errActionId: USER_ACTION_ROLE_REMOVE_ERR,
    okDecoder: (payload) => decodeMessageResponse(payload).message,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}

export async function deleteUser(email: string): Promise<void> {
  const client = getAdminWsClient();
  const response = await client.request(
    USERS_DOMAIN_ID,
    USER_ACTION_DELETE,
    encodeUserDeleteRequest({ email }),
  );

  handleResponse({
    response,
    domainId: USERS_DOMAIN_ID,
    okActionId: USER_ACTION_DELETE_OK,
    errActionId: USER_ACTION_DELETE_ERR,
    okDecoder: () => undefined,
    errDecoder: decodeMessageResponse,
    domainLabel: "user",
  });
}
