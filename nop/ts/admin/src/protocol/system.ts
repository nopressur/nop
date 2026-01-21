// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { WireReader, WireWriter } from "./wire";

export const SYSTEM_DOMAIN_ID = 0;
export const SYSTEM_ACTION_PING = 1;
export const SYSTEM_ACTION_PONG = 2;
export const SYSTEM_ACTION_PONG_ERROR = 3;
export const SYSTEM_ACTION_LOGGING_GET = 4;
export const SYSTEM_ACTION_LOGGING_GET_OK = 5;
export const SYSTEM_ACTION_LOGGING_GET_ERR = 6;
export const SYSTEM_ACTION_LOGGING_SET = 7;
export const SYSTEM_ACTION_LOGGING_SET_OK = 8;
export const SYSTEM_ACTION_LOGGING_SET_ERR = 9;
export const SYSTEM_ACTION_LOGGING_CLEAR = 10;
export const SYSTEM_ACTION_LOGGING_CLEAR_OK = 11;
export const SYSTEM_ACTION_LOGGING_CLEAR_ERR = 12;

export interface PingRequest {
  versionMajor: number;
  versionMinor: number;
  versionPatch: number;
}

export interface LoggingConfigRequest {}

export interface ClearLogsRequest {}

export interface LoggingSetRequest {
  rotationMaxSizeMb: number;
  rotationMaxFiles: number;
}

export interface LoggingConfigResponse {
  level: string;
  rotation_max_size_mb: number;
  rotation_max_files: number;
  run_mode: string;
  file_logging_active: boolean;
}

export interface ClearLogsResponse {
  message: string;
  deleted_files: number;
  deleted_bytes: number;
}

export interface MessageResponse {
  message: string;
}

export function encodePingRequest(payload: PingRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeU16(payload.versionMajor);
  writer.writeU16(payload.versionMinor);
  writer.writeU16(payload.versionPatch);
  return writer.toUint8Array();
}

export function encodeLoggingGetRequest(_payload: LoggingConfigRequest): Uint8Array {
  return new Uint8Array(0);
}

export function encodeLoggingSetRequest(payload: LoggingSetRequest): Uint8Array {
  const writer = new WireWriter();
  writer.writeU64(payload.rotationMaxSizeMb);
  writer.writeU32(payload.rotationMaxFiles);
  return writer.toUint8Array();
}

export function encodeLoggingClearRequest(_payload: ClearLogsRequest): Uint8Array {
  return new Uint8Array(0);
}

export function decodeLoggingConfigResponse(bytes: Uint8Array): LoggingConfigResponse {
  const reader = new WireReader(bytes);
  const level = reader.readString();
  const rotationMaxSizeMb = reader.readU64Number();
  const rotationMaxFiles = reader.readU32();
  const runMode = reader.readString();
  const fileLoggingActive = reader.readBool();
  reader.ensureFullyConsumed();
  return {
    level,
    rotation_max_size_mb: rotationMaxSizeMb,
    rotation_max_files: rotationMaxFiles,
    run_mode: runMode,
    file_logging_active: fileLoggingActive,
  };
}

export function decodeClearLogsResponse(bytes: Uint8Array): ClearLogsResponse {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  const deletedFiles = reader.readU64Number();
  const deletedBytes = reader.readU64Number();
  reader.ensureFullyConsumed();
  return {
    message,
    deleted_files: deletedFiles,
    deleted_bytes: deletedBytes,
  };
}

export function decodeMessageResponse(bytes: Uint8Array): MessageResponse {
  const reader = new WireReader(bytes);
  const message = reader.readString();
  reader.ensureFullyConsumed();
  return { message };
}
