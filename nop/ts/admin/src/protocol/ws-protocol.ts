// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { WireReader, WireWriter } from "./wire";

export const WS_MAX_MESSAGE_BYTES = 63 * 1024;
export const WS_STREAM_CHUNK_OVERHEAD_BYTES = 17;
export const WS_MAX_STREAM_CHUNK_BYTES =
  WS_MAX_MESSAGE_BYTES - WS_STREAM_CHUNK_OVERHEAD_BYTES;
export const STREAM_FLAG_FINAL = 0b0000_0001;
export const STREAM_FLAG_COMPRESSED = 0b0000_0010;
export const FRAME_AUTH = 0;
export const FRAME_AUTH_OK = 1;
export const FRAME_AUTH_ERR = 2;
export const FRAME_REQUEST = 3;
export const FRAME_RESPONSE = 4;
export const FRAME_STREAM_CHUNK = 5;
export const FRAME_ACK = 6;
export const FRAME_ERROR = 7;

export type WsFrame =
  | AuthFrame
  | AuthOkFrame
  | AuthErrFrame
  | RequestFrame
  | ResponseFrame
  | StreamChunkFrame
  | AckFrame
  | ErrorFrame;

export interface AuthFrame {
  frameType: typeof FRAME_AUTH;
  ticket: string;
  csrfToken: string;
}

export interface AuthOkFrame {
  frameType: typeof FRAME_AUTH_OK;
  message: string;
}

export interface AuthErrFrame {
  frameType: typeof FRAME_AUTH_ERR;
  message: string;
}

export interface RequestFrame {
  frameType: typeof FRAME_REQUEST;
  domainId: number;
  actionId: number;
  workflowId: number;
  payload: Uint8Array;
}

export interface ResponseFrame {
  frameType: typeof FRAME_RESPONSE;
  domainId: number;
  actionId: number;
  workflowId: number;
  payload: Uint8Array;
}

export interface StreamChunkFrame {
  frameType: typeof FRAME_STREAM_CHUNK;
  streamId: number;
  seq: number;
  flags: number;
  payload: Uint8Array;
}

export interface AckFrame {
  frameType: typeof FRAME_ACK;
  streamId: number;
  seq: number;
}

export interface ErrorFrame {
  frameType: typeof FRAME_ERROR;
  message: string;
}

export function encodeFrame(frame: WsFrame): Uint8Array {
  const writer = new WireWriter();
  writer.writeU32(frame.frameType);

  switch (frame.frameType) {
    case FRAME_AUTH:
      writer.writeString(frame.ticket);
      writer.writeString(frame.csrfToken);
      break;
    case FRAME_AUTH_OK:
      writer.writeString(frame.message);
      break;
    case FRAME_AUTH_ERR:
      writer.writeString(frame.message);
      break;
    case FRAME_REQUEST:
      writer.writeU32(frame.domainId);
      writer.writeU32(frame.actionId);
      writer.writeU32(frame.workflowId);
      writer.writeBytes(frame.payload);
      break;
    case FRAME_RESPONSE:
      writer.writeU32(frame.domainId);
      writer.writeU32(frame.actionId);
      writer.writeU32(frame.workflowId);
      writer.writeBytes(frame.payload);
      break;
    case FRAME_STREAM_CHUNK:
      writer.writeU32(frame.streamId);
      writer.writeU32(frame.seq);
      writer.writeU8(frame.flags);
      writer.writeBytes(frame.payload);
      break;
    case FRAME_ACK:
      writer.writeU32(frame.streamId);
      writer.writeU32(frame.seq);
      break;
    case FRAME_ERROR:
      writer.writeString(frame.message);
      break;
    default:
      throw new Error("Unknown frame type");
  }

  const bytes = writer.toUint8Array();
  if (bytes.length > WS_MAX_MESSAGE_BYTES) {
    throw new Error("Message exceeds maximum size");
  }
  return bytes;
}

export function decodeFrame(bytes: Uint8Array): WsFrame {
  if (bytes.length > WS_MAX_MESSAGE_BYTES) {
    throw new Error("Message exceeds maximum size");
  }

  const reader = new WireReader(bytes);
  const variant = reader.readU32();

  let frame: WsFrame;
  switch (variant) {
    case FRAME_AUTH:
      frame = {
        frameType: FRAME_AUTH,
        ticket: reader.readString(),
        csrfToken: reader.readString(),
      };
      break;
    case FRAME_AUTH_OK:
      frame = {
        frameType: FRAME_AUTH_OK,
        message: reader.readString(),
      };
      break;
    case FRAME_AUTH_ERR:
      frame = {
        frameType: FRAME_AUTH_ERR,
        message: reader.readString(),
      };
      break;
    case FRAME_REQUEST:
      frame = {
        frameType: FRAME_REQUEST,
        domainId: reader.readU32(),
        actionId: reader.readU32(),
        workflowId: reader.readU32(),
        payload: reader.readBytes(),
      };
      break;
    case FRAME_RESPONSE:
      frame = {
        frameType: FRAME_RESPONSE,
        domainId: reader.readU32(),
        actionId: reader.readU32(),
        workflowId: reader.readU32(),
        payload: reader.readBytes(),
      };
      break;
    case FRAME_STREAM_CHUNK:
      frame = {
        frameType: FRAME_STREAM_CHUNK,
        streamId: reader.readU32(),
        seq: reader.readU32(),
        flags: reader.readU8(),
        payload: reader.readBytes(),
      };
      break;
    case FRAME_ACK:
      frame = {
        frameType: FRAME_ACK,
        streamId: reader.readU32(),
        seq: reader.readU32(),
      };
      break;
    case FRAME_ERROR:
      frame = {
        frameType: FRAME_ERROR,
        message: reader.readString(),
      };
      break;
    default:
      throw new Error("Unknown frame type");
  }

  reader.ensureFullyConsumed();
  return frame;
}
