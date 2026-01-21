// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { WireReader, WireWriter } from "./wire";

export const ROLES_DOMAIN_ID = 13;
export const ROLE_ACTION_ADD = 1;
export const ROLE_ACTION_CHANGE = 2;
export const ROLE_ACTION_DELETE = 3;
export const ROLE_ACTION_LIST = 4;
export const ROLE_ACTION_SHOW = 5;

export const ROLE_ACTION_ADD_OK = 101;
export const ROLE_ACTION_ADD_ERR = 102;
export const ROLE_ACTION_CHANGE_OK = 201;
export const ROLE_ACTION_CHANGE_ERR = 202;
export const ROLE_ACTION_DELETE_OK = 301;
export const ROLE_ACTION_DELETE_ERR = 302;
export const ROLE_ACTION_LIST_OK = 401;
export const ROLE_ACTION_LIST_ERR = 402;
export const ROLE_ACTION_SHOW_OK = 501;
export const ROLE_ACTION_SHOW_ERR = 502;

export interface RoleAddRequest {
  role: string;
}

export interface RoleChangeRequest {
  role: string;
  newRole: string;
}

export interface RoleDeleteRequest {
  role: string;
}

export interface RoleListRequest {}

export interface RoleShowRequest {
  role: string;
}

export interface RoleListResponse {
  roles: string[];
}

export interface RoleShowResponse {
  role: string;
}

export interface MessageResponse {
  message: string;
}

function writeStringVec(writer: WireWriter, values: string[]): void {
  writer.writeVec(values, (itemWriter, value) => itemWriter.writeString(value));
}

function readStringVec(reader: WireReader): string[] {
  return reader.readVec((itemReader) => itemReader.readString());
}

export function encodeRoleAddRequest(payload: RoleAddRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.role);
  return writer.toUint8Array();
}

export function encodeRoleChangeRequest(payload: RoleChangeRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.role);
  writer.writeString(payload.newRole);
  return writer.toUint8Array();
}

export function encodeRoleDeleteRequest(payload: RoleDeleteRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.role);
  return writer.toUint8Array();
}

export function encodeRoleListRequest(_payload: RoleListRequest): Uint8Array {
  return new Uint8Array(0);
}

export function encodeRoleShowRequest(payload: RoleShowRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.role);
  return writer.toUint8Array();
}

export function decodeMessageResponse(bytes: Uint8Array): MessageResponse {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { message };
}

export function decodeRoleListResponse(bytes: Uint8Array): RoleListResponse {
  const reader = new WireReader(bytes);
  const roles = readStringVec(reader);
  reader.ensureFullyConsumed();
  return { roles };
}

export function decodeRoleShowResponse(bytes: Uint8Array): RoleShowResponse {
  const reader = new WireReader(bytes);
  const role = reader.readString();
  reader.ensureFullyConsumed();
  return { role };
}
