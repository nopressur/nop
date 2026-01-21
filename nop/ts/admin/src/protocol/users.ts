// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { OptionMap, WireReader, WireWriter } from "./wire";

export const USERS_DOMAIN_ID = 1;
export const USER_ACTION_ADD = 1;
export const USER_ACTION_CHANGE = 2;
export const USER_ACTION_DELETE = 3;
export const USER_ACTION_PASSWORD_SET = 4;
export const USER_ACTION_LIST = 5;
export const USER_ACTION_SHOW = 6;
export const USER_ACTION_ROLE_ADD = 7;
export const USER_ACTION_ROLE_REMOVE = 8;
export const USER_ACTION_ROLES_LIST = 9;
export const USER_ACTION_PASSWORD_SALT = 10;
export const USER_ACTION_PASSWORD_VALIDATE = 11;
export const USER_ACTION_PASSWORD_UPDATE = 12;

export const USER_ACTION_ADD_OK = 101;
export const USER_ACTION_ADD_ERR = 102;
export const USER_ACTION_CHANGE_OK = 201;
export const USER_ACTION_CHANGE_ERR = 202;
export const USER_ACTION_DELETE_OK = 301;
export const USER_ACTION_DELETE_ERR = 302;
export const USER_ACTION_PASSWORD_SET_OK = 401;
export const USER_ACTION_PASSWORD_SET_ERR = 402;
export const USER_ACTION_LIST_OK = 501;
export const USER_ACTION_LIST_ERR = 502;
export const USER_ACTION_SHOW_OK = 601;
export const USER_ACTION_SHOW_ERR = 602;
export const USER_ACTION_ROLE_ADD_OK = 701;
export const USER_ACTION_ROLE_ADD_ERR = 702;
export const USER_ACTION_ROLE_REMOVE_OK = 801;
export const USER_ACTION_ROLE_REMOVE_ERR = 802;
export const USER_ACTION_ROLES_LIST_OK = 901;
export const USER_ACTION_ROLES_LIST_ERR = 902;
export const USER_ACTION_PASSWORD_SALT_OK = 1001;
export const USER_ACTION_PASSWORD_SALT_ERR = 1002;
export const USER_ACTION_PASSWORD_VALIDATE_OK = 1101;
export const USER_ACTION_PASSWORD_VALIDATE_ERR = 1102;
export const USER_ACTION_PASSWORD_UPDATE_OK = 1201;
export const USER_ACTION_PASSWORD_UPDATE_ERR = 1202;

export type PasswordPayload =
  | { kind: "plaintext"; plaintext: string }
  | { kind: "front_end_hash"; front_end_hash: string; front_end_salt: string };

export interface UserAddRequest {
  email: string;
  name: string;
  password: PasswordPayload;
  roles: string[];
  change_token?: string | null;
}

export interface UserChangeRequest {
  email: string;
  name?: string | null;
  roles?: string[] | null;
}

export interface UserDeleteRequest {
  email: string;
}

export interface UserPasswordSetRequest {
  email: string;
  password: PasswordPayload;
  change_token?: string | null;
}

export interface UserPasswordSaltRequest {
  email: string;
}

export interface UserPasswordValidateRequest {
  email: string;
  front_end_hash: string;
}

export interface UserPasswordUpdateRequest {
  email: string;
  current_front_end_hash: string;
  new_front_end_hash: string;
  new_front_end_salt: string;
  change_token: string;
}

export interface UserListRequest {}

export interface UserShowRequest {
  email: string;
}

export interface UserRoleAddRequest {
  email: string;
  role: string;
}

export interface UserRoleRemoveRequest {
  email: string;
  role: string;
}

export interface UserRolesListRequest {}

export interface UserSummary {
  email: string;
  name: string;
}

export interface UserListResponse {
  users: UserSummary[];
}

export interface UserShowResponse {
  email: string;
  name: string;
  roles: string[];
}

export interface UserRolesListResponse {
  roles: string[];
}

export interface PasswordSaltResponse {
  change_token: string;
  current_front_end_salt: string;
  next_front_end_salt: string;
  expires_in_seconds: number;
}

export interface PasswordValidateResponse {
  valid: boolean;
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

function encodePasswordPayload(writer: WireWriter, payload: PasswordPayload): void {
  switch (payload.kind) {
    case "plaintext":
      writer.writeU8(0);
      writer.writeString(payload.plaintext);
      break;
    case "front_end_hash":
      writer.writeU8(1);
      writer.writeString(payload.front_end_hash);
      writer.writeString(payload.front_end_salt);
      break;
    default: {
      const _exhaustive: never = payload;
      throw new Error(`Unknown password payload: ${_exhaustive}`);
    }
  }
}

export function encodeUserAddRequest(payload: UserAddRequest): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.change_token !== null && payload.change_token !== undefined,
  ];
  OptionMap.write(writer, optionFlags);
  writer.writeString(payload.email);
  writer.writeString(payload.name);
  encodePasswordPayload(writer, payload.password);
  writeStringVec(writer, payload.roles);
  if (optionFlags[0]) {
    writer.writeString(payload.change_token as string);
  }
  return writer.toUint8Array();
}

export function encodeUserChangeRequest(
  payload: UserChangeRequest,
): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.name !== null && payload.name !== undefined,
    payload.roles !== null && payload.roles !== undefined,
  ];
  OptionMap.write(writer, optionFlags);

  writer.writeString(payload.email);
  if (optionFlags[0]) {
    writer.writeString(payload.name as string);
  }
  if (optionFlags[1]) {
    writeStringVec(writer, payload.roles as string[]);
  }
  return writer.toUint8Array();
}

export function encodeUserDeleteRequest(
  payload: UserDeleteRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.email);
  return writer.toUint8Array();
}

export function encodeUserPasswordSetRequest(
  payload: UserPasswordSetRequest,
): Uint8Array {
  const writer = new WireWriter();
  const optionFlags = [
    payload.change_token !== null && payload.change_token !== undefined,
  ];
  OptionMap.write(writer, optionFlags);
  writer.writeString(payload.email);
  encodePasswordPayload(writer, payload.password);
  if (optionFlags[0]) {
    writer.writeString(payload.change_token as string);
  }
  return writer.toUint8Array();
}

export function encodeUserPasswordSaltRequest(
  payload: UserPasswordSaltRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.email);
  return writer.toUint8Array();
}

export function encodeUserPasswordValidateRequest(
  payload: UserPasswordValidateRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.email);
  writer.writeString(payload.front_end_hash);
  return writer.toUint8Array();
}

export function encodeUserPasswordUpdateRequest(
  payload: UserPasswordUpdateRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.email);
  writer.writeString(payload.current_front_end_hash);
  writer.writeString(payload.new_front_end_hash);
  writer.writeString(payload.new_front_end_salt);
  writer.writeString(payload.change_token);
  return writer.toUint8Array();
}

export function encodeUserListRequest(_payload: UserListRequest): Uint8Array {
  return new Uint8Array(0);
}

export function encodeUserShowRequest(
  payload: UserShowRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.email);
  return writer.toUint8Array();
}

export function encodeUserRoleAddRequest(
  payload: UserRoleAddRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.email);
  writer.writeString(payload.role);
  return writer.toUint8Array();
}

export function encodeUserRoleRemoveRequest(
  payload: UserRoleRemoveRequest,
): Uint8Array {
  const writer = new WireWriter();
  writer.writeString(payload.email);
  writer.writeString(payload.role);
  return writer.toUint8Array();
}

export function encodeUserRolesListRequest(
  _payload: UserRolesListRequest,
): Uint8Array {
  return new Uint8Array(0);
}

export function decodeMessageResponse(bytes: Uint8Array): MessageResponse {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { message };
}

export function decodeUserListResponse(bytes: Uint8Array): UserListResponse {
  const reader = new WireReader(bytes);
  const users = reader.readVec((itemReader) => ({
    email: itemReader.readString(),
    name: itemReader.readString(),
  }));
  reader.ensureFullyConsumed();
  return { users };
}

export function decodeUserShowResponse(bytes: Uint8Array): UserShowResponse {
  const reader = new WireReader(bytes);
  const email = reader.readString();
  const name = reader.readString();
  const roles = readStringVec(reader);
  reader.ensureFullyConsumed();
  return { email, name, roles };
}

export function decodeUserRolesListResponse(
  bytes: Uint8Array,
): UserRolesListResponse {
  const reader = new WireReader(bytes);
  const roles = readStringVec(reader);
  reader.ensureFullyConsumed();
  return { roles };
}

export function decodePasswordSaltResponse(
  bytes: Uint8Array,
): PasswordSaltResponse {
  const reader = new WireReader(bytes);
  const change_token = reader.readString();
  const current_front_end_salt = reader.readString();
  const next_front_end_salt = reader.readString();
  const expires_in_seconds = reader.readU64Number();
  reader.ensureFullyConsumed();
  return {
    change_token,
    current_front_end_salt,
    next_front_end_salt,
    expires_in_seconds,
  };
}

export function decodePasswordValidateResponse(
  bytes: Uint8Array,
): PasswordValidateResponse {
  const reader = new WireReader(bytes);
  const valid = reader.readBool();
  reader.ensureFullyConsumed();
  return { valid };
}

export function decodeUserChangeRequest(bytes: Uint8Array): UserChangeRequest {
  const reader = new WireReader(bytes);
  const flags = OptionMap.read(reader, 2);
  const email = reader.readString();
  const name = flags[0] ? reader.readString() : null;
  const roles = flags[1] ? readStringVec(reader) : null;
  reader.ensureFullyConsumed();
  return { email, name, roles };
}
